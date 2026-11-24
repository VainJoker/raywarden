import {
  bearerJsonHeaders,
  emailCodeHash,
  equal,
  expectJson,
  expectStatus,
  fixtureAccessSecret,
  fromBase64Url,
  oauthToken,
  openFixtureJwtKeys,
  toBase64Url,
  totp,
  wrapFixtureJwtKeys,
} from "./runtime-tools.mjs";

export async function runAuthTests(context) {
  await runPreloginChecks(context);
  await runJwtChecks(context);
  await runAuthSessionChecks(context);
}

/** Stable unknown-email KDF responses through compiled Rust and real SQLite. */
async function runPreloginChecks({ fixture, check, sql }) {
  const aliases = [
    "/api/accounts/prelogin", "/api/accounts/prelogin/password",
    "/identity/accounts/prelogin", "/identity/accounts/prelogin/password",
  ];
  const request = (f, email, path = aliases[0]) => f.fetch(path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const prelogin = async (f, email, path) => expectJson(await request(f, email, path), 200);
  const users = () => JSON.stringify(sql.exec("SELECT * FROM users ORDER BY id").toArray());
  const settings = (body, [type, iterations, memory, parallelism], email) => {
    equal(body.kdf, type, "top-level KDF type");
    equal(body.kdfIterations, iterations, "top-level iterations");
    equal(body.kdfMemory ?? null, memory, "top-level memory");
    equal(body.kdfParallelism ?? null, parallelism, "top-level parallelism");
    equal(body.kdfSettings.kdfType, type, "nested KDF type");
    equal(body.kdfSettings.iterations, iterations, "nested iterations");
    equal(body.kdfSettings.memory, memory, "nested memory");
    equal(body.kdfSettings.parallelism, parallelism, "nested parallelism");
    equal(body.salt, email, "normalized salt");
  };

  await check("prelogin keeps real account KDF parameters on every alias without credential writes", async () => {
    const f = fixture();
    const email = "owner@example.test";
    const samples = [[0, 750000, null, null], [0, 5000, null, null], [1, 4, 96, 2]];
    for (const [index, values] of samples.entries()) {
      sql.exec("UPDATE users SET kdf_type=?,kdf_iterations=?,kdf_memory=?,kdf_parallelism=? WHERE email=?", ...values, email);
      const before = users();
      // All aliases share the same handler. Exercise their wiring with one sample.
      for (const path of index === 0 ? aliases : [aliases[0]]) {
        settings(await prelogin(f, " Owner@Example.TEST ", path), values, email);
      }
      equal(users(), before, "stored account and credential state");
    }
  });

  await check("prelogin rejects invalid persisted KDF settings without exposing their values", async () => {
    const samples = [
      ["malformed", 600000, null, null], [0, 4294967297, null, null], [1, 4, "malformed", 2],
      [2, 600000, null, null], [0, -1, null, null], [0, 0, null, null],
      [1, 0, 64, 4], [1, 4, null, 4], [1, 4, 64, null], [1, 4, 1025, 4], [1, 4, 64, 0],
    ];
    for (const [index, values] of samples.entries()) {
      const f = fixture();
      const email = "owner@example.test";
      sql.exec("UPDATE users SET kdf_type=?,kdf_iterations=?,kdf_memory=?,kdf_parallelism=? WHERE email=?", ...values, email);
      const before = users();
      for (const path of index === 0 ? aliases : [aliases[0]]) {
        const body = await expectJson(await request(f, email, path), 500);
        equal(body.message, "Internal server error");
        equal(body.code, 13);
      }
      equal(users(), before, "stored KDF settings after failed prelogin");
    }
  });

  await check("unknown prelogin stays stable across aliases, normalized emails and independent requests", async () => {
    const f = fixture({ empty: true });
    const before = users();
    const first = await prelogin(f, "unknown@example.test");
    // Independent HMAC vector: digest 76df0f736cbc9c66 selects bucket 1
    // with the fixture's persisted key. Truncating to WASM32 first selects 6.
    settings(first, [1, 3, 64, 4], "unknown@example.test");
    for (const path of aliases) {
      const response = await prelogin(f, " Unknown@Example.TEST ", path);
      equal(JSON.stringify(response), JSON.stringify(first), "stable prelogin response");
    }
    f.env.JWT_SECRET = "obsolete-legacy-binding-must-not-select-the-bucket";
    equal(JSON.stringify(await prelogin(f, "unknown@example.test")), JSON.stringify(first), "D1-owned key remains authoritative");
    equal(users(), before, "unknown prelogin cannot create accounts");
  });

  await check("unknown prelogin uses the persisted secret and never changes an existing account's settings", async () => {
    const f = fixture();
    const real = await prelogin(f, "owner@example.test");
    const before = users();
    const first = await prelogin(f, "unknown@example.test");
    const current = await openFixtureJwtKeys(
      sql.exec("SELECT access_secret,refresh_secret FROM jwt_keys WHERE id='global'").one(), f.env.KEY_ENCRYPTION_KEY);
    const rotated = await wrapFixtureJwtKeys({ ...current, access_secret: "rotated-prelogin-runtime-secret" }, f.env.KEY_ENCRYPTION_KEY);
    sql.exec("UPDATE jwt_keys SET access_secret=?,refresh_secret=? WHERE id='global'", rotated.access_secret, rotated.refresh_secret);
    const changed = await prelogin(f, "unknown@example.test");
    settings(changed, [0, 5000, null, null], "unknown@example.test");
    if (JSON.stringify(first) === JSON.stringify(changed)) throw new Error("persisted key did not affect the selected settings");
    equal(JSON.stringify(await prelogin(f, "owner@example.test")), JSON.stringify(real), "real account parameters ignore decoy key selection");
    equal(users(), before, "stored account and credential state");
  });

  await check("a failed prelogin database query fails instead of becoming an unknown-email response", async () => {
    const f = fixture({ empty: true });
    sql.exec("DROP TABLE users");
    for (const path of aliases) await expectStatus(await request(f, "unknown@example.test", path), 500);
  });
}

/** JWT persistence and API-key wrapping against compiled Rust and real SQLite. */
async function runJwtChecks({ fixture, check, accessToken, USER, CIPHER, FILE, sql }) {
  const base64 = toBase64Url;
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
    equal(fromBase64Url(keys.access_secret).length, 64); equal(fromBase64Url(keys.refresh_secret).length, 64);
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
    const access = fromBase64Url(wrapped.access_secret.slice(3)), refresh = fromBase64Url(wrapped.refresh_secret.slice(3));
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
      const packed = fromBase64Url(keys[field].slice(3)); packed[position < 0 ? packed.length - 1 : position] ^= 1;
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
    const packed = fromBase64Url(ciphertext.slice(3));
    const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.subarray(0, 12), additionalData: encoder.encode(USER) }, await aesKey(secret, "v2"), packed.subarray(12));
    equal(new TextDecoder().decode(opened), first.apiKey);
    const second = await (await expectStatus(await apiKey(f), 200)).json();
    equal(second.apiKey, first.apiKey);
    equal(sql.exec("SELECT encrypted_key FROM user_api_keys WHERE user_id=?", USER).one().encrypted_key, ciphertext);
    const rotated = await (await expectStatus(await apiKey(f, true), 200)).json();
    if (rotated.apiKey === first.apiKey) throw new Error("explicit API-key rotation preserved the old credential");
  });
}

/** OAuth aliases, safe cookie fallback and remembered-factor CAS contracts. */
async function runAuthSessionChecks({ fixture, check, sql, accessToken, USER }) {
  const DEVICE = "identity-parity-device", EMAIL = "owner@example.test", REMEMBER = "legacy-remember-proof";
  const token = (f, fields, headers = {}) => oauthToken(f, fields, {
    "device-type": "14", "Bitwarden-Client-Version": "2026.10.1", ...headers,
  });
  const login = (f, extra = {}, headers = {}) => token(f, { grant_type: "password", username: EMAIL, password: "hash",
    deviceIdentifier: DEVICE, deviceName: "Identity parity", deviceType: "14", ...extra }, headers);
  const state = () => JSON.stringify({ users: sql.exec("SELECT * FROM users ORDER BY id").toArray(),
    devices: sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray(),
    factors: sql.exec("SELECT * FROM two_factors ORDER BY id").toArray() });
  const refreshCookie = value => `bw_refresh_token=${value}`;
  const refresh = (f, value) => token(f, { grant_type: "refresh_token", refresh_token: value });
  const claims = value => JSON.parse(atob(value.split(".")[1].replaceAll("-", "+").replaceAll("_", "/")));
  const remembered = (days = 30, age = 0) => {
    const f = fixture(); f.env.TWO_FACTOR_REMEMBER_DAYS = String(days);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('identity-totp',?,0,1,'JBSWY3DPEHPK3PXP',0)", USER);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('identity-remember',?,5,1,?,0)", USER,
      JSON.stringify({ tokens: [{ device_id: DEVICE, token: REMEMBER, created_at: Math.floor(Date.now() / 1000) - age * 86400 }] }));
    return f;
  };

  await check("Bearer rejection challenges distinguish missing, invalid and unavailable authentication", async () => {
    const f = fixture(), path = "/api/accounts/profile";
    const challenge = response => response.headers.get("WWW-Authenticate");
    const authorized = (proof, prefix = "Bearer ") => f.fetch(path, { headers: { Authorization: prefix + proof } });
    equal(challenge(await expectStatus(await f.fetch(path), 401)), "Bearer");
    for (const authorization of ["Basic irrelevant", "Bearer\ttoken", "Bearer"]) {
      equal(challenge(await expectStatus(await f.fetch(path, { headers: { Authorization: authorization } }), 401)), "Bearer");
    }
    const proof = await accessToken();
    for (const prefix of ["bearer ", "Bearer   "]) await expectStatus(await authorized(proof, prefix), 200);
    for (const proof of ["invalid", await accessToken({ session_token: "revoked" })]) {
      equal(challenge(await expectStatus(await authorized(proof), 401)), 'Bearer error="invalid_token"');
    }
    equal(challenge(await expectStatus(await login(f, { password: "wrong" }), 401)), null);
    const execute = f.db.execute.bind(f.db);
    f.db.execute = (query, params) => {
      if (query.startsWith("SELECT d.session_token, u.security_stamp")) throw new Error("fixture session query unavailable");
      return execute(query, params);
    };
    equal(challenge(await expectStatus(await authorized(proof), 500)), null);
  });

  await check("token aliases normalize case and underscores while canonical duplicates fail before writes", async () => {
    const f = fixture();
    const response = await expectStatus(await token(f, { GrAnTtYpE: " password ", USERNAME: ` ${EMAIL.toUpperCase()} `, PASSWORD: "hash", DEVICEID: DEVICE, DEVICENAME: "Phone", DEVICETYPE: "14", CLIENTID: "web" }), 200);
    const body = await response.json();
    equal(body.MasterPasswordPolicy.Object, "masterPasswordPolicy"); equal(body.UserDecryptionOptions.Object, "userDecryptionOptions");
    const before = state();
    for (const [field, duplicates] of [
      ["grant_type", [["GRANTTYPE", "refresh_token"]]],
      ["twoFactorToken", [["twoFactorToken", " \t "], ["TWO_FACTOR_TOKEN", "proof"]]],
      ["deviceIdentifier", [["deviceId", "one"], ["DEVICE_IDENTIFIER", "two"]]],
      ["access_code", [["code", "one"], ["ACCESS_CODE", "two"]]],
    ]) {
      const fields = new URLSearchParams([["grant_type", "password"], ...duplicates]);
      const error = await (await expectStatus(await token(f, fields), 400)).json();
      equal(error.error, "invalid_request");
      equal(error.error_description, `Duplicate token field: ${field}`);
      equal(error.msg, `Invalid request: Duplicate token field: ${field}`);
      equal(state(), before);
    }
    for (const [fields, oauthError, description, code] of [
      [{}, "invalid_request", "Missing grant_type", 5],
      [{ grant_type: " " }, "invalid_request", "Missing grant_type", 5],
      [{ grant_type: "unsupported" }, "unsupported_grant_type", "Unsupported grant_type", 9002],
      [{ grant_type: "password", username: EMAIL, password: "wrong", deviceType: "invalid" }, "invalid_request", "Invalid token form", 5],
    ]) {
      const error = await (await expectStatus(await token(f, fields), 400)).json();
      equal(error.error, oauthError);
      equal(error.error_description, description);
      equal(error.code, code);
      equal(state(), before);
    }
  });

  await check("OAuth grant field errors preserve legacy codes and carry invalid_request", async () => {
    const f = fixture(), before = state();
    for (const [fields, description, code] of [
      [{ grant_type: "password", password: "hash" }, "Missing username", 5],
      [{ grant_type: "password", username: EMAIL }, "Missing password", 9002],
      [{ grant_type: "password", username: EMAIL, password: "hash", deviceType: "99" }, "Invalid device information", 5],
      [{ grant_type: "client_credentials", client_secret: "unused" }, "Missing client_id", 5],
      [{ grant_type: "client_credentials", client_id: "unused" }, "Missing client_secret", 5],
      [{ grant_type: "webauthn" }, "Missing passkey challenge token", 5],
      [{ grant_type: "webauthn", token: "unused" }, "Missing deviceResponse", 5],
      [{ grant_type: "webauthn", token: "unused", deviceResponse: "unused" }, "Missing deviceIdentifier", 5],
      [{ grant_type: "send_access" }, "Missing send_id", 5],
      [{ grant_type: "access_token" }, "Missing send_id", 5],
    ]) {
      const error = await (await expectStatus(await token(f, fields), 400)).json();
      equal(error.error, "invalid_request");
      equal(error.error_description, description);
      equal(error.code, code);
      equal(error.message, `${code === 9002 ? "Invalid query parameters" : "Invalid request"}: ${description}`);
      equal(state(), before);
    }

    const enabled = remembered();
    const error = await (await expectStatus(await login(enabled, { twoFactorProvider: "99", twoFactorToken: "123456" }), 400)).json();
    equal(error.error, "invalid_request");
    equal(error.error_description, "Invalid two factor provider");
    equal(error.code, 9002);
  });

  await check("OAuth form extractor preserves 415 and 413 in sanitized JSON", async () => {
    const f = fixture();
    for (const [contentType, body, status, description] of [
      ["application/json", '{"password":"fixture-private-field"}', 415, "Expected application/x-www-form-urlencoded"],
      ["application/x-www-form-urlencoded", "grant_type=password&password=fixture-private-field" + "x".repeat(2 * 1024 * 1024), 413, "Token form is too large"],
    ]) {
      const response = await expectStatus(await f.fetch("/identity/connect/token", {
        method: "POST", headers: { "Content-Type": contentType }, body,
      }), status);
      equal(response.headers.get("Content-Type"), "application/json");
      const raw = await response.text();
      equal(raw.includes("fixture-private-field"), false);
      const error = JSON.parse(raw);
      equal(error.error, "invalid_request");
      equal(error.error_description, description);
    }
  });

  await check("password login cannot replace a newer-generation nonce after validation", async () => {
    const f = fixture(), batch = f.db.batch.bind(f.db);
    let changed = false;
    f.db.batch = async statements => {
      if (!changed && statements.some(statement => statement.sql.startsWith("INSERT INTO devices (user_id, device_id"))) {
        changed = true;
        sql.exec("UPDATE users SET security_stamp='new-generation' WHERE id=?", USER);
        sql.exec("UPDATE devices SET session_token='new-nonce' WHERE user_id=? AND device_id='device'", USER);
      }
      return batch(statements);
    };
    await expectStatus(await login(f, { deviceIdentifier: "device" }), 409);
    equal(changed, true);
    equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token, "new-nonce");
    const fresh = await accessToken({ sstamp: "new-generation", session_token: "new-nonce" });
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${fresh}` } }), 200);
  });

  await check("password login checks the enabled factor snapshot at the session write", async () => {
    for (const change of ["enrolled", "removed", "reconfigured"]) {
      const f = change === "enrolled" ? fixture() : remembered();
      const fields = change === "enrolled" ? {} : { twoFactorProvider: "5", twoFactorToken: REMEMBER };
      sql.exec("UPDATE devices SET device_id=? WHERE user_id=? AND device_id='device'", DEVICE, USER);
      const batch = f.db.batch.bind(f.db);
      let reached = false;
      f.db.batch = async statements => {
        if (!reached && statements.some(statement => statement.sql.startsWith("INSERT INTO devices (user_id, device_id"))) {
          reached = true;
          if (change === "enrolled") {
            sql.exec("INSERT INTO two_factors VALUES('new-totp',?,0,1,'JBSWY3DPEHPK3PXP',0)", USER);
          } else if (change === "removed") {
            sql.exec("DELETE FROM two_factors WHERE id='identity-totp'");
          } else {
            sql.exec("UPDATE two_factors SET data='replacement' WHERE id='identity-totp'");
          }
        }
        return batch(statements);
      };
      const response = await expectStatus(await login(f, fields), 409);
      equal((await response.json()).message, "Conflict: Second-factor state changed during authentication. Retry login.", change);
      equal(reached, true, change);
      equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id=?", USER, DEVICE).one().session_token, "session", change);
      const proof = await accessToken({ device: DEVICE });
      await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${proof}` } }), 200);
    }
  });

  await check("JWT name fallback preserves login and the full legacy profile name", async () => {
    for (const [name, claim] of [["Legacy profile", "Legacy profile"], ["a".repeat(9000), "User"]]) {
      const f = fixture();
      sql.exec("UPDATE users SET name=? WHERE id=?", name, USER);
      const tokens = await (await expectStatus(await login(f), 200)).json();
      equal(claims(tokens.access_token).name, claim);
      const profile = await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${tokens.access_token}` } }), 200);
      equal((await profile.json()).name, name);
    }
  });

  await check("password and API-key signing failures preserve the prior device session", async () => {
    const f = fixture(), previous = await accessToken();
    const response = await expectStatus(await f.fetch("/api/accounts/api-key", {
      method: "POST", headers: bearerJsonHeaders(previous),
      body: JSON.stringify({ masterPasswordHash: "hash" }),
    }), 200);
    const { apiKey } = await response.json(), email = `${"a".repeat(9000)}@example.test`;
    sql.exec("UPDATE users SET email=? WHERE id=?", email, USER);
    for (const attempt of [
      () => login(f, { username: email, deviceIdentifier: "device" }),
      () => token(f, { grant_type: "client_credentials", client_id: `user.${USER}`, client_secret: apiKey,
        scope: "api offline_access", deviceIdentifier: "device" }),
    ]) {
      const error = await (await expectStatus(await attempt(), 500)).json();
      equal(error.code, 13);
      equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token, "session");
      equal(sql.exec("SELECT COUNT(*) AS count FROM user_api_key_sessions WHERE user_id=?", USER).one().count, 0);
      await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${previous}` } }), 200);
    }
  });

  await check("API-key login cannot replace a newer-generation nonce after validation", async () => {
    const f = fixture();
    const response = await expectStatus(await f.fetch("/api/accounts/api-key", {
      method: "POST", headers: bearerJsonHeaders(await accessToken()),
      body: JSON.stringify({ masterPasswordHash: "hash" }),
    }), 200);
    const { apiKey } = await response.json(), batch = f.db.batch.bind(f.db);
    let changed = false;
    f.db.batch = async statements => {
      if (!changed && statements.some(statement => statement.sql.includes("user_api_key_sessions(user_id,device_id,session_token)"))) {
        changed = true;
        sql.exec("UPDATE users SET security_stamp='new-generation' WHERE id=?", USER);
        sql.exec("UPDATE devices SET session_token='new-nonce' WHERE user_id=? AND device_id='device'", USER);
      }
      return batch(statements);
    };
    await expectStatus(await token(f, { grant_type: "client_credentials", client_id: `user.${USER}`, client_secret: apiKey,
      scope: "api offline_access", deviceIdentifier: "device" }), 409);
    equal(changed, true);
    equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token, "new-nonce");
    equal(sql.exec("SELECT COUNT(*) AS count FROM user_api_key_sessions WHERE user_id=?", USER).one().count, 0);
    const fresh = await accessToken({ sstamp: "new-generation", session_token: "new-nonce" });
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${fresh}` } }), 200);
  });

  await check("OAuth recovery-code rejection identifies the credential without mutating factors", async () => {
    const f = remembered();
    sql.exec("UPDATE users SET two_factor_recovery_code='recovery-code' WHERE id=?", USER);
    const before = state();
    for (const proof of [undefined, "wrong-recovery-code"]) {
      const fields = { twoFactorProvider: "8", ...(proof === undefined ? {} : { twoFactorToken: proof }) };
      const error = await (await expectStatus(await login(f, fields), 401)).json();
      equal(error.code, 2);
      equal(error.message, "Invalid credentials: Invalid recovery code");
      equal(state(), before);
    }
  });

  await check("client version rejection leaves a verified TOTP code usable", async () => {
    const f = fixture();
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    sql.exec("INSERT INTO two_factors VALUES('version-totp',?,0,1,?,0)", USER, secret);
    const step = Math.floor(Date.now() / 30000);
    const code = await totp(secret, step);
    const fields = { twoFactorProvider: "0", twoFactorToken: code, deviceIdentifier: "device" };
    const missing = { "Bitwarden-Client-Version": "" };
    await expectStatus(await login(f, { ...fields, twoFactorToken: "not a code" }, missing), 401);
    equal((await (await expectStatus(await login(f, fields, missing), 400)).json()).error, "version_header_missing");
    const last = () => sql.exec("SELECT last_used_step FROM two_factors WHERE id='version-totp'").one().last_used_step;
    equal(last(), 0);
    sql.exec("CREATE TRIGGER reject_totp_session BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'fixture session rejected'); END;");
    await expectStatus(await login(f, fields), 500);
    equal(last(), 0, "TOTP replay counter after rollback");
    equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token, "session");
    sql.exec("DROP TRIGGER reject_totp_session");
    await expectStatus(await login(f, fields), 200);
    equal(last(), step);
    await expectStatus(await login(f, fields), 401);
  });

  await check("refresh cookies are HttpOnly origin-scoped and refresh returns only standard OAuth fields", async () => {
    const f = fixture(), issued = await expectStatus(await login(f), 200);
    const cookies = issued.headers.get("set-cookie");
    for (const value of ["bw_refresh_token=", "HttpOnly", "SameSite=Strict", "Path=/identity/connect/token", "Secure"]) equal(cookies.includes(value), true, value);
    equal(issued.headers.get("cache-control"), "no-store");
    const tokens = await issued.json();
    const response = await expectStatus(await token(f, { GRANT_TYPE: "refresh_token" }, { Cookie: refreshCookie(tokens.refresh_token), Origin: "https://vault.test", "Sec-Fetch-Site": "same-origin" }), 200);
    const refreshed = await response.json();
    equal(Object.keys(refreshed).sort().join(","), "access_token,expires_in,refresh_token,scope,token_type");
    equal(refreshed.scope, "api offline_access");
    const before = state(), original = claims(tokens.refresh_token);
    for (const value of [refreshed.access_token, refreshed.refresh_token]) {
      const current = claims(value);
      equal(current.sstamp, original.sstamp); equal(current.session_token, original.session_token); equal(current.device, DEVICE);
    }
    await expectStatus(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${refreshed.access_token}` } }), 200);
    await expectStatus(await refresh(f, refreshed.refresh_token), 200); equal(state(), before);
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Cookie: `bw_access_token=${tokens.access_token}` } }), 401);
    await expectStatus(await token(f, { grant_type: "refresh_token" }, { Cookie: refreshCookie(tokens.refresh_token) }), 200);
  });

  await check("refresh form proofs take priority; cross-origin cookies and invalid grants never modify sessions", async () => {
    const f = fixture(), tokens = await (await expectStatus(await login(f), 200)).json(), before = state();
    for (const headers of [
      { Origin: "https://attacker.test" }, { Origin: "https://vault.test", "Sec-Fetch-Site": "cross-site" },
      { Origin: "https://vault.test", "Sec-Fetch-Site": "same-site" }, { Origin: "null" },
    ]) { await expectStatus(await token(f, { grant_type: "refresh_token" }, { Cookie: refreshCookie(tokens.refresh_token), ...headers }), 401); equal(state(), before); }
    await expectStatus(await token(f, { grant_type: "refresh_token" }, { Cookie: `${refreshCookie(tokens.refresh_token)}; ${refreshCookie(tokens.refresh_token)}` }), 400);
    for (const fields of [{ grant_type: "refresh_token" }, { grant_type: "refresh_token", refresh_token: "invalid" },
      { grant_type: "refresh_token", refresh_token: "" }]) {
      const response = await expectStatus(await token(f, fields, fields.refresh_token === "" ? { Cookie: refreshCookie(tokens.refresh_token) } : {}), 400);
      equal((await response.json()).error, "invalid_grant"); equal(state(), before);
    }
    const explicit = await expectStatus(await token(f, { grant_type: "refresh_token", refreshToken: tokens.refresh_token },
      { Cookie: "bw_refresh_token=bad; bw_refresh_token=also-bad", Origin: "https://attacker.test", "Sec-Fetch-Site": "cross-site" }), 200);
    equal(explicit.headers.get("set-cookie"), null); equal(state(), before);
  });

  // The adapter still executes production SQL in workerd SQLite. Each hook
  // models a completed credential/session change at one refresh read boundary.
  const revocations = [
    ["password change", "UPDATE users SET master_password_hash='concurrent-password-verifier',password_salt='concurrent-salt',key='2.password-rewrap',security_stamp='concurrent-generation' WHERE id=?"],
    ["KDF change", "UPDATE users SET kdf_iterations=650000,master_password_hash='concurrent-kdf-verifier',key='2.kdf-rewrap',security_stamp='concurrent-generation' WHERE id=?"],
    ["email change", "UPDATE users SET email='changed@example.test',is_email_verified=1,master_password_hash='concurrent-email-verifier',security_stamp='concurrent-generation' WHERE id=?"],
    ["explicit stamp reset", "UPDATE users SET security_stamp='concurrent-generation' WHERE id=?"],
    ["device nonce rotation", "UPDATE devices SET session_token='concurrent-session' WHERE user_id=? AND device_id=?"],
  ];
  const boundaries = [
    { name: "before session validation", query: "SELECT d.session_token, u.security_stamp", occurrence: 1, status: 400, nonceStatus: 400 },
    { name: "between validation and owner read", query: "SELECT * FROM users", occurrence: 1, status: 400, nonceStatus: 400 },
    { name: "between owner and device read", query: "SELECT * FROM devices", occurrence: 1, status: 409, nonceStatus: 400 },
    { name: "before the final account snapshot", query: "SELECT * FROM users", occurrence: 2, status: 409, nonceStatus: 200 },
    { name: "after the final account snapshot", query: "SELECT * FROM users", occurrence: 2, after: true, status: 200, nonceStatus: 200 },
  ];
  for (const boundary of boundaries) {
    await check(`refresh preserves its original generation when revoked ${boundary.name}`, async () => {
      for (const [name, mutation] of revocations) {
        const f = fixture(), tokens = await (await expectStatus(await login(f), 200)).json(), original = claims(tokens.refresh_token);
        const execute = f.db.execute.bind(f.db); let reads = 0, reached = false, revoked;
        const revoke = () => {
          reached = true;
          sql.exec(mutation, ...(name.startsWith("device") ? [USER, DEVICE] : [USER]));
          revoked = state();
        };
        f.db.execute = (query, params) => {
          const matches = !reached && query.startsWith(boundary.query) && ++reads === boundary.occurrence;
          if (matches && !boundary.after) revoke();
          const result = execute(query, params);
          if (matches && boundary.after) revoke();
          return result;
        };
        const status = name.startsWith("device") ? boundary.nonceStatus : boundary.status;
        const response = await refresh(f, tokens.refresh_token);
        equal(response.status, status, `${name} refresh status`);
        equal(reached, true, `${name} missed ${boundary.name}`); equal(state(), revoked, `${name} changed revoked state`);
        const body = await response.json();
        if (status === 400) equal(body.error, "invalid_grant", name);
        if (status === 200) {
          // Revocation after the last relevant read may race with issuance.
          // Such tokens must retain the old stamp/nonce and already be invalid.
          for (const value of [body.access_token, body.refresh_token]) {
            const issued = claims(value);
            equal(issued.sstamp, original.sstamp, `${name} adopted a newer stamp`);
            equal(issued.session_token, original.session_token, `${name} adopted a newer nonce`);
          }
          await expectStatus(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${body.access_token}` } }), 401);
          equal((await (await expectStatus(await refresh(f, body.refresh_token), 400)).json()).error, "invalid_grant");
        }
        await expectStatus(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${tokens.access_token}` } }), 401);
        equal(state(), revoked, `${name} revived a revoked session`);
      }
    });
  }

  await check("remember duration controls legacy proofs, hashes new secrets and emits matching cookie lifetimes", async () => {
    for (const [days, age, status, seconds] of [[1, 2, 400, 86400], [3, 2, 200, 259200], [0, 2, 400, 86400], [1000, 91, 400, 7776000], ["invalid", 2, 200, 2592000]]) {
      const f = remembered(days, age), before = state();
      const response = await expectStatus(await login(f, { two_factor_provider: "5", two_factor_token: REMEMBER, two_factor_remember: "true" }), status);
      if (status !== 200) {
        const challenge = await response.json();
        equal(challenge.error, "invalid_grant");
        equal(challenge.error_description, "Two factor required.");
        equal(JSON.stringify(challenge.TwoFactorProviders), '["0"]');
        equal(JSON.stringify(challenge.TwoFactorProviders2), '{"0":null}');
        equal(challenge.MasterPasswordPolicy.Object, "masterPasswordPolicy");
        equal(state(), before);
        continue;
      }
      const body = await response.json(); equal(typeof body.TwoFactorToken, "string");
      const record = sql.exec("SELECT data FROM two_factors WHERE id='identity-remember'").one().data;
      equal(record.includes(body.TwoFactorToken), false, "new remembered secret stored verbatim"); equal(record.includes("sha256:"), true);
      equal(response.headers.get("set-cookie").includes(`Max-Age=${seconds}`), true);
      await expectStatus(await login(f, { twoFactorProvider: "5", twoFactorToken: body.TwoFactorToken }), 200);
    }
  });

  await check("remember cookies use the same proof validation and reject browser cross-origin fallback", async () => {
    let f = remembered();
    await expectStatus(await login(f, { two_factor_token: " \t " }, { Cookie: `twoFactorRemember=${REMEMBER}; TwoFactorRemember=${REMEMBER}`, Origin: "https://vault.test", "Sec-Fetch-Site": "same-origin" }), 200);
    f = remembered(); const before = state();
    await expectStatus(await login(f, {}, { Cookie: `twoFactorRemember=${REMEMBER}`, Origin: "https://attacker.test" }), 401); equal(state(), before);
    await expectStatus(await login(f, {}, { Cookie: `twoFactorRemember=${REMEMBER}; TwoFactorRemember=different` }), 400); equal(state(), before);
    await expectStatus(await login(f, { twoFactorToken: REMEMBER, twoFactorProvider: "5" }, { Cookie: "twoFactorRemember=bad; twoFactorRemember=also-bad", Origin: "https://attacker.test" }), 200);
  });

  await check("remember renewal and non-renewing logins cannot resurrect or reuse concurrently revoked bypasses", async () => {
    for (const renew of [false, true]) {
      for (const mutation of ["delete", "change", "stamp", "cost"]) {
        const f = remembered(), batch = f.db.batch.bind(f.db); let reached = false, expected;
        sql.exec("UPDATE devices SET device_id=? WHERE user_id=? AND device_id='device'", DEVICE, USER);
        f.db.batch = async statements => {
          if (!reached && statements.some(statement => statement.sql.startsWith("INSERT INTO devices (user_id, device_id"))) {
            reached = true;
            if (mutation === "delete") sql.exec("DELETE FROM two_factors WHERE id='identity-remember'");
            else if (mutation === "change") sql.exec("UPDATE two_factors SET data='{}' WHERE id='identity-remember'");
            else if (mutation === "stamp") sql.exec("UPDATE users SET security_stamp='concurrent-stamp' WHERE id=?", USER);
            else sql.exec("UPDATE users SET password_iterations=1200000 WHERE id=?", USER);
            expected = state();
          }
          return batch(statements);
        };
        const response = await expectStatus(await login(f, { twoFactorProvider: "5", twoFactorToken: REMEMBER, twoFactorRemember: renew ? "1" : "0" }), 409);
        equal(reached, true, mutation); equal(state(), expected, mutation);
        if (!renew && mutation === "delete") {
          equal((await response.json()).message, "Conflict: Second-factor state changed during authentication. Retry login.");
          equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id=?", USER, DEVICE).one().session_token, "session");
          const proof = await accessToken({ device: DEVICE });
          await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${proof}` } }), 200);
        }
      }
    }
  });

  await check("a failed login keeps the remembered bypass and permits one successful renewal", async () => {
    const f = remembered(), before = state();
    sql.exec("CREATE TRIGGER reject_renewed_session BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'fixture session rejected'); END;");
    const fields = { twoFactorProvider: "5", twoFactorToken: REMEMBER, twoFactorRemember: "1" };
    await expectStatus(await login(f, fields), 500);
    equal(state(), before, "Remember rotation or verifier migration escaped the failed transaction");
    sql.exec("DROP TRIGGER reject_renewed_session");
    await expectStatus(await login(f, fields), 200);
    await expectStatus(await login(f, fields), 400);
  });

  await check("competing remember renewals preserve one winner instead of overwriting a newer proof", async () => {
    const f = remembered(), batch = f.db.batch.bind(f.db); let pending = 0, release;
    const ready = new Promise(resolve => { release = resolve; });
    f.db.batch = async statements => {
      if (statements.some(statement => statement.sql.startsWith("INSERT INTO two_factors") && statement.sql.includes("password_iterations=?7"))) {
        if (++pending === 2) release();
        await ready;
      }
      return batch(statements);
    };
    const responses = await Promise.all([0, 1].map(() => login(f, { twoFactorProvider: "5", twoFactorToken: REMEMBER, twoFactorRemember: "1" })));
    equal(pending, 2); equal(responses.map(response => response.status).sort().join(","), "200,409");
    for (const response of responses) await response.text();
  });

  const api = async (f, path, body, method = "POST") => f.fetch(path, { method,
    headers: bearerJsonHeaders(await accessToken()), body: JSON.stringify(body) });
  await check("approval requires the live approving device, and login consumes approval only with its session", async () => {
    const f = fixture();
    const send = (path, method, body, headers = {}) => f.fetch(path, {
      method, headers: { "Content-Type": "application/json", "device-type": "0", ...headers },
      body: JSON.stringify(body),
    });
    sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?,'approver','Approver',0,'approver-nonce','now','now')", USER);
    const code = "fixture-approval-code";
    const request = await (await expectStatus(await send("/api/auth-requests", "POST", {
      email: EMAIL, deviceIdentifier: "device", accessCode: code, publicKey: "fixture-public-key",
    }), 200)).json();
    const path = `/api/auth-requests/${request.id}`;
    const proof = { deviceIdentifier: "approver", key: "fixture-wrapped-key", requestApproved: true };
    const approver = nonce => accessToken({ device: "approver", session_token: nonce });
    const approve = async nonce => send(path, "PUT", proof, { Authorization: `Bearer ${await approver(nonce)}` });
    const execute = f.db.execute.bind(f.db);
    let reached = false;
    f.db.execute = (query, params) => {
      if (!reached && query.startsWith("UPDATE auth_requests SET approved")) {
        reached = true;
        sql.exec("UPDATE devices SET session_token='new-approver-nonce' WHERE user_id=? AND device_id='approver'", USER);
      }
      return execute(query, params);
    };
    const approval = () => sql.exec("SELECT approved,authenticated_at FROM auth_requests WHERE id=?", request.id).one();
    await expectStatus(await approve("approver-nonce"), 400);
    equal(reached, true);
    equal(approval().approved, null);
    await expectStatus(await approve("new-approver-nonce"), 200);
    const fields = { authRequest: request.id, access_code: code, deviceIdentifier: "device", deviceType: "0" };
    sql.exec("CREATE TRIGGER reject_approval_session BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'fixture session rejected'); END;");
    await expectStatus(await login(f, fields), 500);
    equal(approval().authenticated_at, null);
    equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token, "session");
    sql.exec("DROP TRIGGER reject_approval_session");
    await expectStatus(await login(f, fields), 200);
    equal(typeof approval().authenticated_at, "string");
    await expectStatus(await login(f, fields), 401);
  });

  const concat = (...values) => {
    const output = new Uint8Array(values.reduce((size, value) => size + value.length, 0));
    let offset = 0; for (const value of values) { output.set(value, offset); offset += value.length; } return output;
  };
  const cborHead = (kind, length) => length < 24 ? Uint8Array.of(kind * 32 + length)
    : length < 256 ? Uint8Array.of(kind * 32 + 24, length) : Uint8Array.of(kind * 32 + 25, length >> 8, length & 255);
  const cbor = value => {
    if (typeof value === "number") return cborHead(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
    if (typeof value === "string") { const bytes = new TextEncoder().encode(value); return concat(cborHead(3, bytes.length), bytes); }
    if (value instanceof Uint8Array) return concat(cborHead(2, value.length), value);
    if (value instanceof Map) return concat(cborHead(5, value.size), ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)]));
    throw new Error("Unsupported CBOR fixture");
  };
  const makePasskey = async (f, prf = {}) => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey), id = crypto.getRandomValues(new Uint8Array(16));
    const options = await (await expectStatus(await api(f, "/api/webauthn/attestation-options", { masterPasswordHash: "hash" }), 200)).json();
    const rp = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(options.options.rp.id)));
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, fromBase64Url(jwk.x)], [-3, fromBase64Url(jwk.y)]]));
    const auth = concat(rp, Uint8Array.of(0x45, 0, 0, 0, 0), new Uint8Array(16), Uint8Array.of(0, id.length), id, cose);
    const attestation = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", auth]]));
    const client = new TextEncoder().encode(JSON.stringify({ type: "webauthn.create", challenge: options.token, origin: "https://vault.test", crossOrigin: false }));
    const response = await expectStatus(await api(f, "/api/webauthn", { token: options.token, KeyName: "Runtime passkey", ...prf,
      deviceResponse: { response: { attestationObject: toBase64Url(attestation), clientDataJSON: toBase64Url(client) } } }), 200);
    return { saved: await response.json(), pair, id };
  };

  await check("passkey removal preserves the observed credential and revision if transaction authorization changes", async () => {
    for (const change of ["nonce", "target"]) {
      const f = fixture(), passkey = await makePasskey(f);
      const revision = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
      const batch = f.db.batch.bind(f.db);
      let reached = false;
      f.db.batch = async statements => {
        if (!reached && statements.some(statement => statement.sql.startsWith("DELETE FROM webauthn_credentials WHERE id="))) {
          reached = true;
          if (change === "nonce") sql.exec("UPDATE devices SET session_token='new' WHERE user_id=? AND device_id='device'", USER);
          else sql.exec("UPDATE webauthn_credentials SET public_key='new-credential' WHERE user_id=?", USER);
        }
        return batch(statements);
      };
      await expectStatus(await api(f, `/api/webauthn/${passkey.saved.id}/delete`, { masterPasswordHash: "hash" }), 409);
      equal(reached, true, change);
      equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id=?", USER).one().n, 1);
      equal(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at, revision);
    }
  });

  await check("PRF probe optional capability flags and fallback messages describe the supplied support", async () => {
    const f = fixture();
    for (const [body, supported] of [[{}, false], [{ supportsPrf: false }, false], [{ supportsPrf: true }, true]]) {
      const result = await (await expectStatus(await api(f, "/api/webauthn/prf-probe", body), 200)).json();
      equal(result.supportsPrf, supported); equal(result.canUsePasskeyUnlock, supported); equal(result.requiresPasswordLogin, !supported);
      equal(result.fallback, "master_password"); equal(typeof result.message, "string");
    }
    sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
    await expectStatus(await api(f, "/api/webauthn/prf-probe", {}), 401);
  });

  await check("verified passkey saves report actual complete, supported-only and unsupported PRF states", async () => {
    for (const [prf, status] of [
      [{ supportsPrf: false }, 2], [{ supportsPrf: true }, 1],
      [{ supportsPrf: true, encryptedUserKey: "2.user", encryptedPrivateKey: "2.private" }, 1],
      [{ supportsPrf: true, encryptedUserKey: "2.user", encryptedPrivateKey: "2.private", encryptedPublicKey: "2.public" }, 0],
    ]) {
      const f = fixture(), { saved } = await makePasskey(f, prf);
      equal(saved.success, true); equal(saved.name, "Runtime passkey"); equal(saved.prfStatus, status);
      equal(saved.canUsePasskeyUnlock, status === 0); equal(saved.requiresPasswordLogin, status !== 0); equal(typeof saved.message, "string");
      equal(saved.data.length, 1); equal(saved.Data.length, 1);
      equal(sql.exec("SELECT prf_status FROM webauthn_credentials WHERE user_id=?", USER).one().prf_status, status);
    }
  });

  const signedAssertion = async (passkey, rpId, challenge) => {
    const client = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge, origin: "https://vault.test", crossOrigin: false }, null, 2));
    const rp = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)));
    const auth = concat(rp, Uint8Array.of(0x05, 0, 0, 0, 1));
    const signed = concat(auth, new Uint8Array(await crypto.subtle.digest("SHA-256", client)));
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passkey.pair.privateKey, signed));
    // WebAuthn transports an ASN.1 DER ECDSA signature, WebCrypto returns r||s.
    const integer = bytes => { let first = 0; while (first < bytes.length - 1 && bytes[first] === 0) first++; const value = bytes.slice(first); return concat(Uint8Array.of(2, value.length + (value[0] >= 128 ? 1 : 0)), value[0] >= 128 ? Uint8Array.of(0) : new Uint8Array(), value); };
    const rs = concat(integer(signature.slice(0, 32)), integer(signature.slice(32)));
    return { id: toBase64Url(passkey.id), rawId: toBase64Url(passkey.id), type: "public-key", response: {
      clientDataJSON: toBase64Url(client), authenticatorData: toBase64Url(auth), signature: toBase64Url(concat(Uint8Array.of(0x30, rs.length), rs)) } };
  };

  const prfAssertion = async (f, passkey) => {
    const options = await (await expectStatus(await api(f, "/api/webauthn/assertion-options", { masterPasswordHash: "hash" }), 200)).json();
    return { token: options.token, encryptedUserKey: "2.new-user", encryptedPrivateKey: "2.new-private", encryptedPublicKey: "2.new-public",
      deviceResponse: await signedAssertion(passkey, options.options.rpId, options.token) };
  };

  await check("validation, signing and D1 failures leave the passkey assertion and prior session usable", async () => {
    const f = fixture(), passkey = await makePasskey(f);
    const options = await (await expectStatus(await f.fetch("/identity/accounts/webauthn/assertion-options"), 200)).json();
    const deviceResponse = await signedAssertion(passkey, options.options.rpId, options.options.challenge);
    const fields = { grant_type: "webauthn", token: options.token, deviceIdentifier: DEVICE, deviceResponse: JSON.stringify(deviceResponse) };
    const missing = { "Bitwarden-Client-Version": "" };
    const consumed = () => sql.exec("SELECT consumed_at FROM webauthn_challenges WHERE challenge=?", options.options.challenge).one().consumed_at;
    await expectStatus(await token(f, { ...fields, deviceResponse: "{}" }, missing), 401);
    equal((await (await expectStatus(await token(f, fields, missing), 400)).json()).error, "version_header_missing");
    equal((await (await expectStatus(await token(f, { ...fields, deviceName: "x".repeat(257) }), 400)).json()).error, "invalid_request");
    sql.exec("UPDATE devices SET device_id=? WHERE user_id=? AND device_id='device'", DEVICE, USER);
    sql.exec("UPDATE users SET email=? WHERE id=?", `${"a".repeat(9000)}@example.test`, USER);
    equal((await (await expectStatus(await token(f, fields), 500)).json()).code, 13);
    equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id=?", USER, DEVICE).one().session_token, "session");
    const previous = await accessToken({ device: DEVICE });
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${previous}` } }), 200);
    sql.exec("UPDATE users SET email=? WHERE id=?", EMAIL, USER);
    sql.exec("CREATE TRIGGER reject_passkey_session BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'fixture session rejected'); END;");
    await expectStatus(await token(f, fields), 500);
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${previous}` } }), 200);
    sql.exec("DROP TRIGGER reject_passkey_session");
    equal(consumed(), null);
    equal(sql.exec("SELECT sign_count FROM webauthn_credentials WHERE user_id=?", USER).one().sign_count, 0);
    await expectStatus(await token(f, fields), 200);
    equal(typeof consumed(), "string");
    equal(sql.exec("SELECT sign_count FROM webauthn_credentials WHERE user_id=?", USER).one().sign_count, 1);
    await expectStatus(await token(f, fields), 400);
  });

  await check("primary passkey login cannot start a session for a concurrently removed or changed credential", async () => {
    for (const change of ["removed", "public key changed"]) {
      const f = fixture(), passkey = await makePasskey(f);
      const options = await (await expectStatus(await f.fetch("/identity/accounts/webauthn/assertion-options"), 200)).json();
      const assertion = await signedAssertion(passkey, options.options.rpId, options.options.challenge);
      const batch = f.db.batch.bind(f.db);
      let reached = false;
      f.db.batch = async statements => {
        if (!reached && statements.some(statement => statement.sql.startsWith("INSERT INTO devices (user_id, device_id"))) {
          reached = true;
          if (change === "removed") {
            sql.exec("DELETE FROM webauthn_credentials WHERE user_id=? AND credential_use='login'", USER);
          } else {
            sql.exec("UPDATE webauthn_credentials SET public_key='changed' WHERE user_id=? AND credential_use='login'", USER);
          }
        }
        return batch(statements);
      };
      const response = await expectStatus(await token(f, {
        grant_type: "webauthn", token: options.token, deviceIdentifier: "device", deviceResponse: JSON.stringify(assertion),
      }), 400);
      equal((await response.json()).message, "Invalid request: WebAuthn challenge expired, used or counter changed", change);
      equal(reached, true, change);
      equal(sql.exec("SELECT consumed_at FROM webauthn_challenges WHERE challenge=?", options.options.challenge).one().consumed_at, null, change);
      const previous = await accessToken();
      await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${previous}` } }), 200);
    }
  });

  await check("client version rejection preserves a WebAuthn second-factor assertion", async () => {
    const f = fixture(), passkey = await makePasskey(f);
    sql.exec("UPDATE webauthn_credentials SET credential_use='2fa' WHERE user_id=?", USER);
    sql.exec("INSERT INTO two_factors VALUES('version-webauthn',?,7,1,'{}',0)", USER);
    const challenge = await (await expectStatus(await login(f), 400)).json();
    const options = challenge.TwoFactorProviders2["7"];
    const proof = await signedAssertion(passkey, options.rpId, options.challenge);
    const fields = { twoFactorProvider: "7", twoFactorToken: JSON.stringify(proof) };
    const consumed = () => sql.exec("SELECT consumed_at FROM webauthn_challenges WHERE challenge=?", options.challenge).one().consumed_at;

    const failed = await expectStatus(await login(f, fields, { "Bitwarden-Client-Version": "" }), 400);
    equal((await failed.json()).error, "version_header_missing");
    equal(consumed(), null);
    equal(sql.exec("SELECT sign_count FROM webauthn_credentials WHERE user_id=?", USER).one().sign_count, 0);

    sql.exec("CREATE TRIGGER reject_webauthn_factor_session BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'fixture session rejected'); END;");
    await expectStatus(await login(f, fields), 500);
    equal(consumed(), null);
    equal(sql.exec("SELECT sign_count FROM webauthn_credentials WHERE user_id=?", USER).one().sign_count, 0);
    sql.exec("DROP TRIGGER reject_webauthn_factor_session");
    await expectStatus(await login(f, fields), 200);
    equal(typeof consumed(), "string");
    await expectStatus(await login(f, fields), 400);
  });

  await check("a correct email code at the attempt limit survives client version rejection", async () => {
    const f = fixture(), code = "123456", purpose = "email-login", now = Math.floor(Date.now() / 1000);
    sql.exec("INSERT INTO two_factors VALUES('version-email',?,1,1,?,0)", USER, JSON.stringify({ email: EMAIL }));
    const secret = await fixtureAccessSecret(sql, f.env.KEY_ENCRYPTION_KEY);
    const hash = await emailCodeHash(secret, { owner: USER, purpose, recipient: EMAIL, context: "", code });
    sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,context,code_hash,security_stamp,session_token,issued_at,expires_at,ready,attempts) VALUES('version-email',?,?,?,?,'',?,'owner-stamp','',?,?,1,3)", USER, USER, purpose, EMAIL, hash, now, now + 600);
    const row = () => sql.exec("SELECT attempts,consumed_at FROM verification_codes WHERE id='version-email'").one();
    const missing = { "Bitwarden-Client-Version": "" };
    const fields = { twoFactorProvider: "1", twoFactorToken: code };
    const invalid = await (await expectStatus(await login(f, { ...fields, twoFactorToken: "654321" }, missing), 400)).json();
    equal(invalid.message, "Invalid request: Verification code is invalid, expired or already used");
    equal(row().attempts, 4);
    equal((await (await expectStatus(await login(f, fields, missing), 400)).json()).error, "version_header_missing");
    equal(row().attempts, 4); equal(row().consumed_at, null);
    sql.exec("CREATE TRIGGER reject_email_factor_session BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'fixture session rejected'); END;");
    await expectStatus(await login(f, fields), 500);
    equal(row().attempts, 4); equal(row().consumed_at, null);
    sql.exec("DROP TRIGGER reject_email_factor_session");
    await expectStatus(await login(f, fields), 200);
    equal(row().attempts, 5); equal(typeof row().consumed_at, "number");
  });

  await check("PRF enable requires all three wrappers and preserves signed session authorization", async () => {
    const f = fixture(), passkey = await makePasskey(f, { supportsPrf: true });
    const body = await prfAssertion(f, passkey), missing = structuredClone(body); delete missing.encryptedPublicKey;
    const path = `/api/webauthn/${passkey.saved.id}`;
    await expectStatus(await api(f, path, missing, "PUT"), 400);
    const invalid = structuredClone(body);
    const clientData = fromBase64Url(body.deviceResponse.response.clientDataJSON);
    for (const bytes of [Uint8Array.of(0x7b), concat(clientData, new Uint8Array(32768).fill(0x20))]) {
      invalid.deviceResponse.response.clientDataJSON = toBase64Url(bytes);
      const error = await (await expectStatus(await api(f, path, invalid, "PUT"), 401)).json();
      equal(error.message, "Invalid credentials: Invalid WebAuthn client data");
    }
    const result = await (await expectStatus(await api(f, path, body, "PUT"), 200)).json();
    equal(result.success, true); equal(result.data[0].prfStatus, 0); equal(result.data[0].encryptedPublicKey, "2.new-public");
  });

  await check("PRF collection updates use the signed credential ID when the route has no path ID", async () => {
    const f = fixture(), passkey = await makePasskey(f, { supportsPrf: true });
    const body = await prfAssertion(f, passkey), missing = structuredClone(body);
    delete missing.deviceResponse.id;
    delete missing.deviceResponse.rawId;
    const error = await (await expectStatus(await api(f, "/api/webauthn", missing, "PUT"), 400)).json();
    equal(error.message, "Invalid request: Missing WebAuthn credential ID");
    await expectStatus(await api(f, "/api/webauthn/%FF", body, "PUT"), 400);
    delete body.deviceResponse.id;
    const result = await (await expectStatus(await api(f, "/api/webauthn", body, "PUT"), 200)).json();
    equal(result.success, true); equal(result.data[0].prfStatus, 0);
  });

  await check("PRF final writes reject a revoked session or newer accepted assertion without changing wrappers", async () => {
    for (const mutation of ["nonce", "stamp", "counter", "challenge"]) {
      const f = fixture(), passkey = await makePasskey(f, { supportsPrf: true });
      const body = await prfAssertion(f, passkey), prepare = f.db.prepare.bind(f.db); let reached = false;
      f.db.prepare = query => {
        if (!reached && query.startsWith("UPDATE webauthn_credentials SET name=")) {
          reached = true;
          if (mutation === "nonce") sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
          else if (mutation === "stamp") sql.exec("UPDATE users SET security_stamp='revoked' WHERE id=?", USER);
          else if (mutation === "counter") sql.exec("UPDATE webauthn_credentials SET sign_count=sign_count+1 WHERE user_id=?", USER);
          else sql.exec("UPDATE webauthn_credentials SET last_challenge='newer-proof' WHERE user_id=?", USER);
        }
        return prepare(query);
      };
      await expectStatus(await api(f, `/api/webauthn/${passkey.saved.id}`, body, "PUT"), 409);
      equal(reached, true);
      equal(sql.exec("SELECT consumed_at FROM webauthn_challenges WHERE challenge=?", body.token).one().consumed_at, null);
      const record = sql.exec("SELECT prf_status,encrypted_public_key,encrypted_user_key,encrypted_private_key FROM webauthn_credentials WHERE user_id=?", USER).one();
      equal(record.prf_status, 1); equal(record.encrypted_public_key, null); equal(record.encrypted_user_key, null); equal(record.encrypted_private_key, null);
    }
  });

  await check("PRF write failure preserves the verified challenge and counter for one retry", async () => {
    const f = fixture(), passkey = await makePasskey(f, { supportsPrf: true });
    const body = await prfAssertion(f, passkey), path = `/api/webauthn/${passkey.saved.id}`;
    sql.exec("CREATE TRIGGER reject_prf_wrap BEFORE UPDATE OF prf_status ON webauthn_credentials BEGIN SELECT RAISE(ABORT, 'fixture assertion update rejected'); END;");
    await expectStatus(await api(f, path, body, "PUT"), 500);
    equal(sql.exec("SELECT consumed_at FROM webauthn_challenges WHERE challenge=?", body.token).one().consumed_at, null);
    equal(sql.exec("SELECT sign_count FROM webauthn_credentials WHERE user_id=?", USER).one().sign_count, 0);
    sql.exec("DROP TRIGGER reject_prf_wrap");
    await expectStatus(await api(f, path, body, "PUT"), 200);
    await expectStatus(await api(f, path, body, "PUT"), 400);
  });

  await check("a PRF assertion for the wrong credential leaves its challenge available", async () => {
    const f = fixture();
    const actual = await makePasskey(f, { supportsPrf: true });
    const target = await makePasskey(f, { supportsPrf: true });
    const actualSlot = Number(actual.saved.id), targetSlot = Number(target.saved.id);
    const body = await prfAssertion(f, actual);
    await expectStatus(await api(f, `/api/webauthn/${target.saved.id}`, body, "PUT"), 401);
    equal(sql.exec("SELECT consumed_at FROM webauthn_challenges WHERE challenge=?", body.token).one().consumed_at, null);
    equal(sql.exec("SELECT sign_count FROM webauthn_credentials WHERE user_id=? AND slot=?", USER, actualSlot).one().sign_count, 0);
    const updated = await (await expectStatus(await api(f, `/api/webauthn/${actual.saved.id}`, body, "PUT"), 200)).json();
    const prfStatus = new Map(updated.data.map(key => [key.id, key.prfStatus]));
    equal(prfStatus.get(actualSlot), 0);
    equal(prfStatus.get(targetSlot), 1);
  });
}
