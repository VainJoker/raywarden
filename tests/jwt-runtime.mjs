import { bearerJsonHeaders, equal, expectStatus } from "./runtime-assertions.mjs";
import { fromBase64Url as bytes, openFixtureJwtKeys, toBase64Url as base64, wrapFixtureJwtKeys } from "./runtime-auth.mjs";

/** JWT persistence and API-key wrapping against compiled Rust and real SQLite. */
export async function runJwtCompatibility({ fixture, check, accessToken, USER, CIPHER, FILE, sql }) {
  const encoder = new TextEncoder();
  // Public fixture bytes 0..31; never use this key outside isolated tests.
  const rootSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  const row = () => sql.exec("SELECT access_secret,refresh_secret FROM jwt_keys WHERE id='global'").toArray()[0];
  const empty = () => sql.exec("DELETE FROM users; DELETE FROM jwt_keys;");
  const writeRow = keys => sql.exec("UPDATE jwt_keys SET access_secret=?,refresh_secret=? WHERE id='global'", keys.access_secret, keys.refresh_secret);
  async function openRow(keys = row()) {
    for (const field of ["access_secret", "refresh_secret"]) {
      if (!keys[field].startsWith("v1.")) throw new Error(`${field} was persisted without its v1 envelope`);
    }
    return openFixtureJwtKeys(keys, rootSecret);
  }
  const wrapRow = keys => wrapFixtureJwtKeys(keys, rootSecret);
  async function aesKey(secret, version) {
    let raw;
    if (version === "v2") {
      const hmac = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      raw = await crypto.subtle.sign("HMAC", hmac, encoder.encode("raywarden/api-key-encryption/v2"));
    } else raw = await crypto.subtle.digest("SHA-256", encoder.encode(secret));
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  const apiKey = async (f, rotate = false) => f.fetch(`/api/accounts/${rotate ? "rotate-api-key" : "api-key"}`, {
    method: "POST", headers: bearerJsonHeaders(await accessToken()),
    body: JSON.stringify({ masterPasswordHash: "hash" }),
  });

  await check("stored JWT keys stay authoritative despite broken legacy bindings", async () => {
    const f = fixture(), before = row();
    Object.defineProperty(f.env, "JWT_SECRET", { get() { throw new Error("unreadable obsolete binding"); } });
    f.env.JWT_REFRESH_SECRET = { malformed: true };
    await expectStatus(await f.fetch("/api/alive"), 200);
    equal(JSON.stringify(await openRow()), JSON.stringify(before));
    const wrapped = JSON.stringify(row());
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${await accessToken()}` } }), 200);
    equal(JSON.stringify(row()), wrapped);
  });

  await check("invalid configured JWT lifetimes fail before serving authenticated APIs", async () => {
    for (const duration of ["0", "-1", "not-seconds", "9223372036854775807", "18446744073709551615"]) {
      const f = fixture(), before = JSON.stringify(row()); f.env.JWT_DURATION_SECONDS = duration;
      await expectStatus(await f.fetch("/api/alive"), 500);
      equal(JSON.stringify(row()), before);
    }
    const f = fixture(); f.env.JWT_DURATION_SECONDS = "1800";
    await expectStatus(await f.fetch("/api/alive"), 200);
  });

  await check("concurrent empty-database initialization persists one random winner", async () => {
    const f = fixture(); empty();
    for (const response of await Promise.all([f.fetch("/api/alive"), f.fetch("/api/alive")])) await expectStatus(response, 200);
    const stored = row(), keys = await openRow(stored);
    equal(bytes(keys.access_secret).length, 64); equal(bytes(keys.refresh_secret).length, 64);
    if (keys.access_secret === keys.refresh_secret) throw new Error("independent JWT keys collided");
    equal(sql.exec("SELECT count(*) AS n FROM jwt_keys").one().n, 1);
    await expectStatus(await f.fetch("/api/alive"), 200);
    equal(JSON.stringify(row()), JSON.stringify(stored));
  });

  await check("a populated database cannot replace missing keys without explicit legacy import", async () => {
    const f = fixture(); sql.exec("DELETE FROM jwt_keys;");
    const failure = await (await expectStatus(await f.fetch("/api/alive"), 500)).json();
    equal(failure.code, 13); equal(failure.message, "Internal server error");
    equal(row(), undefined);
    f.env.JWT_SECRET = " original access "; f.env.JWT_REFRESH_SECRET = " original refresh ";
    await expectStatus(await f.fetch("/api/alive"), 200);
    const keys = await openRow();
    equal(keys.access_secret, f.env.JWT_SECRET); equal(keys.refresh_secret, f.env.JWT_REFRESH_SECRET);
  });

  await check("partial, empty and non-string legacy bindings fail without generating keys", async () => {
    for (const bindings of [
      { JWT_SECRET: "one" }, { JWT_REFRESH_SECRET: "one" },
      { JWT_SECRET: "", JWT_REFRESH_SECRET: "two" },
      { JWT_SECRET: "one", JWT_REFRESH_SECRET: " " },
      { JWT_SECRET: {}, JWT_REFRESH_SECRET: {} },
      { JWT_SECRET: null, JWT_REFRESH_SECRET: null },
    ]) {
      const f = fixture(); empty(); Object.assign(f.env, bindings);
      const failure = await (await expectStatus(await f.fetch("/api/alive"), 500)).json();
      equal(failure.code, 0); equal(failure.message, "Internal server error");
      equal(row(), undefined);
    }
  });

  await check("blank JWT keys in stored rows fail without replacement", async () => {
    for (const stored of [
      { access_secret: " ", refresh_secret: "fixture stored secret" },
      { access_secret: "fixture stored secret", refresh_secret: "\t" },
    ]) {
      const f = fixture(); writeRow(stored);
      const failure = await (await expectStatus(await f.fetch("/api/alive"), 500)).json();
      equal(failure.code, 13); equal(failure.message, "Internal server error");
      equal(JSON.stringify(row()), JSON.stringify(stored));
    }
  });

  await check("a JWT-key read failure never initializes or overwrites keys", async () => {
    const f = fixture(), before = JSON.stringify(row()), prepare = f.db.prepare.bind(f.db);
    f.db.prepare = query => {
      if (query.startsWith("SELECT access_secret, refresh_secret FROM jwt_keys")) return {
        ...prepare(query), async first() { throw new Error("fixture D1 read failure"); },
      };
      return prepare(query);
    };
    await expectStatus(await f.fetch("/api/alive"), 500);
    equal(JSON.stringify(row()), before);
    if (f.db.queries.some(query => query.startsWith("INSERT OR IGNORE INTO jwt_keys"))) throw new Error("read error entered the initialization path");
  });

  await check("legacy JWT wrapping preserves exact bytes and uses independent CSPRNG nonces", async () => {
    const f = fixture();
    const original = { access_secret: " access \u0000bytes-é ", refresh_secret: " refresh \r\n " };
    writeRow(original);
    for (const response of await Promise.all([f.fetch("/api/alive"), f.fetch("/api/alive")])) await expectStatus(response, 200);
    const wrapped = row();
    equal(JSON.stringify(await openRow(wrapped)), JSON.stringify(original));
    if (wrapped.access_secret.includes(original.access_secret) || wrapped.refresh_secret.includes(original.refresh_secret)) throw new Error("JWT plaintext remained in D1");
    const access = bytes(wrapped.access_secret.slice(3)), refresh = bytes(wrapped.refresh_secret.slice(3));
    equal(access.length, 12 + encoder.encode(original.access_secret).length + 16);
    equal(refresh.length, 12 + encoder.encode(original.refresh_secret).length + 16);
    if (base64(access.subarray(0, 12)) === base64(refresh.subarray(0, 12))) throw new Error("JWT fields reused the same nonce");
  });

  await check("required external JWT root key rejects absent, malformed and unreadable bindings", async () => {
    for (const wrapped of [false, true]) for (const key of [undefined, null, {}, "", " ", "short", `${rootSecret}=`, ` ${rootSecret}`, base64(new Uint8Array(31)), base64(new Uint8Array(33)), rootSecret.replace(/8$/, "9")]) {
      const f = fixture();
      if (wrapped) await expectStatus(await f.fetch("/api/alive"), 200);
      const before = JSON.stringify(row()); f.env.KEY_ENCRYPTION_KEY = key;
      await expectStatus(await f.fetch("/api/alive"), 500);
      equal(JSON.stringify(row()), before);
    }
    const f = fixture(), before = JSON.stringify(row());
    Object.defineProperty(f.env, "KEY_ENCRYPTION_KEY", { get() { throw new Error("fixture unreadable root key"); } });
    await expectStatus(await f.fetch("/api/alive"), 500);
    equal(JSON.stringify(row()), before);
    const absent = fixture(); empty(); delete absent.env.KEY_ENCRYPTION_KEY;
    await expectStatus(await absent.fetch("/api/alive"), 500); equal(row(), undefined);
  });

  await check("wrapped JWT keys reject wrong root keys without legacy or random fallback", async () => {
    const f = fixture(); await expectStatus(await f.fetch("/api/alive"), 200);
    const before = JSON.stringify(row());
    f.env.KEY_ENCRYPTION_KEY = base64(new Uint8Array(32).fill(9));
    f.env.JWT_SECRET = "replacement access"; f.env.JWT_REFRESH_SECRET = "replacement refresh";
    await expectStatus(await f.fetch("/api/alive"), 500);
    equal(JSON.stringify(row()), before);
    f.env.KEY_ENCRYPTION_KEY = rootSecret;
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${await accessToken()}` } }), 200);
  });

  await check("mixed, unsupported, swapped and tampered JWT envelopes fail without writes", async () => {
    const cases = [
      keys => ({ ...keys, access_secret: "legacy access" }),
      keys => ({ ...keys, refresh_secret: "legacy refresh" }),
      keys => ({ access_secret: keys.refresh_secret, refresh_secret: keys.access_secret }),
      keys => ({ access_secret: keys.access_secret.replace("v1.", "v2."), refresh_secret: keys.refresh_secret.replace("v1.", "v2.") }),
      keys => ({ ...keys, access_secret: "v1.!" }),
      keys => ({ ...keys, refresh_secret: `v1.${base64(new Uint8Array(27))}` }),
    ];
    for (const field of ["access_secret", "refresh_secret"]) for (const position of [0, 12, -1]) cases.push(keys => {
      const packed = bytes(keys[field].slice(3)); packed[position < 0 ? packed.length - 1 : position] ^= 1;
      return { ...keys, [field]: `v1.${base64(packed)}` };
    });
    for (const mutate of cases) {
      const f = fixture(); await expectStatus(await f.fetch("/api/alive"), 200);
      const invalid = mutate(row()); writeRow(invalid); const before = JSON.stringify(row()), queryCount = f.db.queries.length;
      await expectStatus(await f.fetch("/api/alive"), 500);
      equal(JSON.stringify(row()), before);
      if (f.db.queries.slice(queryCount).some(query => /^(UPDATE|INSERT).*jwt_keys/.test(query))) throw new Error("invalid envelope entered the write path");
    }
  });

  await check("JWT initialization and legacy wrapping reject database write failures", async () => {
    for (const initialize of [false, true]) for (const falseResult of [false, true]) {
      const f = fixture(); if (initialize) empty();
      const before = JSON.stringify(row()), prepare = f.db.prepare.bind(f.db);
      f.db.prepare = query => {
        if (!query.startsWith(initialize ? "INSERT OR IGNORE INTO jwt_keys" : "UPDATE jwt_keys")) return prepare(query);
        return { bind() { return { async run() {
          if (falseResult) return { success: false, results: [], meta: { changes: 0 } };
          throw new Error("fixture D1 write failure");
        } }; } };
      };
      await expectStatus(await f.fetch("/api/alive"), 500); equal(JSON.stringify(row()), before);
    }
  });

  await check("a legacy-wrap readback failure does not serve unconfirmed keys", async () => {
    const f = fixture(), original = row(), prepare = f.db.prepare.bind(f.db); let reads = 0;
    f.db.prepare = query => {
      if (query.startsWith("SELECT access_secret, refresh_secret FROM jwt_keys") && ++reads === 2) return {
        ...prepare(query), async first() { throw new Error("fixture D1 readback failure"); },
      };
      return prepare(query);
    };
    await expectStatus(await f.fetch("/api/alive"), 500);
    equal(JSON.stringify(await openRow()), JSON.stringify(original));
    f.db.prepare = prepare;
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${await accessToken()}` } }), 200);
  });

  await check("a losing JWT wrapper serves only the persisted concurrent winner", async () => {
    const f = fixture(), prepare = f.db.prepare.bind(f.db);
    const winner = await wrapRow({ access_secret: "concurrent winner access", refresh_secret: "concurrent winner refresh" });
    f.db.prepare = query => {
      if (!query.startsWith("UPDATE jwt_keys")) return prepare(query);
      return { bind() { return { async run() { writeRow(winner); return { success: true, results: [], meta: { changes: 0 } }; } }; } };
    };
    // This original-key token must fail in the same request that lost its CAS.
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${await accessToken()}` } }), 401);
    equal(JSON.stringify(row()), JSON.stringify(winner));
    equal(f.db.queries.filter(query => query.startsWith("SELECT access_secret, refresh_secret FROM jwt_keys")).length, 2);
  });

  await check("legacy exp-only attachment tokens retain 64-bit dates and cannot become user access tokens", async () => {
    const f = fixture(), secret = row().access_secret;
    const header = base64(encoder.encode('{"alg":"HS256","typ":"JWT"}'));
    const body = base64(encoder.encode(JSON.stringify({ sub: USER, cipher_id: CIPHER, attachment_id: FILE, exp: 4294967595 })));
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signed = `${header}.${body}.${base64(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(`${header}.${body}`))))}`;
    const download = `/api/ciphers/${CIPHER}/attachment/${FILE}/download?token=`;
    const response = await expectStatus(await f.fetch(download + signed), 200);
    equal((await response.arrayBuffer()).byteLength, 6);
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${signed}` } }), 401);
    await expectStatus(await f.fetch(download + await accessToken()), 401);
  });

  await check("legacy API-key ciphertext remains readable without rewriting its row", async () => {
    const f = fixture(), secret = row().access_secret, value = "legacy-api-secret";
    const nonce = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: encoder.encode(USER) }, await aesKey(secret, "legacy"), encoder.encode(value)));
    const packed = new Uint8Array(nonce.length + encrypted.length); packed.set(nonce); packed.set(encrypted, nonce.length);
    const ciphertext = base64(packed), hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))), byte => byte.toString(16).padStart(2, "0")).join("");
    sql.exec("INSERT INTO user_api_keys(user_id,encrypted_key,key_hash,updated_at) VALUES(?,?,?,'legacy-time')", USER, ciphertext, hash);
    const response = await (await expectStatus(await apiKey(f), 200)).json();
    equal(response.apiKey, value); equal(response.revisionDate, "legacy-time");
    equal(sql.exec("SELECT encrypted_key FROM user_api_keys WHERE user_id=?", USER).one().encrypted_key, ciphertext);
  });

  await check("new API-key ciphertext uses v2 domain separation and survives later requests", async () => {
    const f = fixture(), secret = row().access_secret;
    const first = await (await expectStatus(await apiKey(f), 200)).json();
    const ciphertext = sql.exec("SELECT encrypted_key FROM user_api_keys WHERE user_id=?", USER).one().encrypted_key;
    if (!ciphertext.startsWith("v2.")) throw new Error("new API key did not use v2 ciphertext");
    const packed = bytes(ciphertext.slice(3));
    const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.subarray(0, 12), additionalData: encoder.encode(USER) }, await aesKey(secret, "v2"), packed.subarray(12));
    equal(new TextDecoder().decode(opened), first.apiKey);
    const second = await (await expectStatus(await apiKey(f), 200)).json();
    equal(second.apiKey, first.apiKey);
    equal(sql.exec("SELECT encrypted_key FROM user_api_keys WHERE user_id=?", USER).one().encrypted_key, ciphertext);
    const rotated = await (await expectStatus(await apiKey(f, true), 200)).json();
    if (rotated.apiKey === first.apiKey) throw new Error("explicit API-key rotation preserved the old credential");
  });
}
