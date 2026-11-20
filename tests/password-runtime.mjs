/** Account and Send verifiers exercised through compiled Rust and native SQL. */
export async function runPasswordCompatibility({ fixture, check, sql, accessToken, USER }) {
  const CLIENT_HASH = "password-runtime-client-authentication-hash";
  const NEXT_HASH = "password-runtime-replacement-authentication-hash";
  const EMAIL = "owner@example.test";
  const DEVICE = "password-runtime-new-session";
  const equal = (actual, expected, label = "value") => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const ok = (value, label) => { if (!value) throw new Error(label); };
  const expect = async (response, status) => {
    if (response.status !== status) throw new Error(`Expected HTTP ${status}, received ${response.status}: ${await response.text()}`);
    return response;
  };
  const bytes = salt => Uint8Array.from(atob(salt), char => char.charCodeAt(0));
  const salt = length => btoa(String.fromCharCode(...new Uint8Array(length).fill(42)));
  const derive = async (candidate, encodedSalt, iterations) => {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(candidate), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: bytes(encodedSalt), iterations }, key, 256);
    return btoa(String.fromCharCode(...new Uint8Array(bits)));
  };
  const row = () => sql.exec("SELECT master_password_hash,password_salt,password_iterations,security_stamp,updated_at FROM users WHERE id=?", USER).one();
  const login = (f, password = CLIENT_HASH, extra = {}) => f.fetch("/identity/connect/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "device-type": "14", "Bitwarden-Client-Version": "2026.11.0" },
    body: new URLSearchParams({ grant_type: "password", username: EMAIL, password,
      deviceIdentifier: DEVICE, deviceName: "Password Runtime", deviceType: "14", ...extra }),
  });
  const owner = async () => ({ Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" });
  const salted = async (iterations = 100000) => {
    const f = fixture(), encodedSalt = salt(16);
    const hash = await derive(CLIENT_HASH, encodedSalt, iterations);
    sql.exec("UPDATE users SET master_password_hash=?,password_salt=?,password_iterations=? WHERE id=?", hash, encodedSalt, iterations, USER);
    return f;
  };
  const validStoredPassword = async (candidate, current = row()) => {
    ok(await derive(candidate, current.password_salt, current.password_iterations) === current.master_password_hash, "Stored verifier does not match its own salt and iteration count");
  };
  const totp = async () => {
    const counter = new Uint8Array(8);
    new DataView(counter.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 30000)), false);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("12345678901234567890"), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
    const offset = digest[digest.length - 1] & 15;
    const value = new DataView(digest.buffer).getUint32(offset, false) & 0x7fffffff;
    return String(value % 1000000).padStart(6, "0");
  };

  await check("raw password verifiers upgrade only after success without moving the vault cursor or revoking another session", async () => {
    const f = fixture();
    sql.exec("UPDATE users SET master_password_hash=?,updated_at='2099-12-31T23:59:59.999Z' WHERE id=?", CLIENT_HASH, USER);
    const before = row(), oldBearer = await accessToken();
    await expect(await login(f, "wrong-password"), 401);
    equal(JSON.stringify(row()), JSON.stringify(before), "failed login changed credentials");
    await expect(await login(f), 200);
    const after = row();
    equal(after.password_iterations, 600000); equal(bytes(after.password_salt).length, 64);
    equal(after.updated_at, before.updated_at, "transparent upgrade changed the vault cursor");
    equal(after.security_stamp, before.security_stamp, "transparent upgrade revoked sessions");
    await validStoredPassword(CLIENT_HASH, after);
    await expect(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${oldBearer}` } }), 200);
    await expect(await login(f), 200);
    equal(JSON.stringify(row()), JSON.stringify(after), "current verifier was unnecessarily regenerated");
  });

  await check("salted Raywarden 100000-iteration verifiers upgrade using the recorded old cost", async () => {
    const f = await salted(); const before = row();
    await expect(await login(f, "wrong-password"), 401);
    equal(JSON.stringify(row()), JSON.stringify(before));
    await expect(await login(f), 200);
    const after = row();
    equal(after.password_iterations, 600000); equal(bytes(after.password_salt).length, 64);
    ok(after.password_salt !== before.password_salt, "old short salt was retained");
    equal(after.updated_at, before.updated_at); equal(after.security_stamp, before.security_stamp);
    await validStoredPassword(CLIENT_HASH, after);
  });

  await check("higher stored costs survive login and password changes, while empty replacement hashes are rejected", async () => {
    const f = await salted(1200000), before = row();
    await expect(await login(f), 200);
    equal(JSON.stringify(row()), JSON.stringify(before), "login lowered or rewrote a higher-cost verifier");
    const headers = await owner();
    await expect(await f.fetch("/api/accounts/password", { method: "POST", headers,
      body: JSON.stringify({ masterPasswordHash: CLIENT_HASH, newMasterPasswordHash: "", key: "2.next-user-key" }) }), 400);
    equal(JSON.stringify(row()), JSON.stringify(before), "empty replacement hash changed credentials");
    await expect(await f.fetch("/api/accounts/password", { method: "POST", headers,
      body: JSON.stringify({ masterPasswordHash: CLIENT_HASH, newMasterPasswordHash: NEXT_HASH, key: "2.next-user-key" }) }), 200);
    equal(row().password_iterations, 1200000);
    await validStoredPassword(NEXT_HASH);
  });

  await check("password cost is upgraded only after completing the required second factor", async () => {
    const f = await salted();
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('password-runtime-totp',?,0,1,'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',0)", USER);
    const before = row();
    await expect(await login(f), 400);
    equal(JSON.stringify(row()), JSON.stringify(before), "a second-factor challenge upgraded the verifier");
    await expect(await login(f, CLIENT_HASH, { twoFactorProvider: "0", twoFactorToken: "invalid" }), 401);
    equal(JSON.stringify(row()), JSON.stringify(before), "a failed second factor upgraded the verifier");
    await expect(await login(f, CLIENT_HASH, { twoFactorProvider: "0", twoFactorToken: await totp() }), 200);
    equal(row().password_iterations, 600000);
    await validStoredPassword(CLIENT_HASH);
  });

  await check("password upgrades reject concurrent hash, salt, cost, stamp and same-stamp envelope changes", async () => {
    for (const [column, value] of [["master_password_hash", "concurrent-hash"], ["password_salt", salt(32)],
      ["password_iterations", 120001], ["security_stamp", "concurrent-stamp"], ["key", "concurrent-wrapped-key"]]) {
      const f = await salted(), before = row();
      let reached = false;
      const prepare = f.db.prepare.bind(f.db);
      f.db.prepare = query => {
        if (!reached && query.startsWith("UPDATE users SET master_password_hash=") && query.includes("password_iterations=?3")) {
          reached = true;
          sql.exec(`UPDATE users SET ${column}=? WHERE id=?`, value, USER);
        }
        return prepare(query);
      };
      await expect(await login(f), 409);
      ok(reached, "concurrent credential test missed the upgrade commit");
      const current = sql.exec(`SELECT ${column} AS value FROM users WHERE id=?`, USER).one().value;
      equal(current, value, "upgrade overwrote a concurrent credential update");
      if (column !== "master_password_hash") equal(row().master_password_hash, before.master_password_hash);
      equal(sql.exec("SELECT COUNT(*) AS n FROM devices WHERE user_id=? AND device_id=?", USER, DEVICE).one().n, 0);
    }
  });

  await check("new account registration writes the current cost explicitly instead of inheriting the migration default", async () => {
    const f = fixture({ empty: true });
    f.env.ALLOWED_EMAILS = EMAIL; f.env.OWNER_SETUP_TOKEN = "password-runtime-private-owner-setup-token";
    await expect(await f.fetch("/api/accounts/register", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Raywarden-Setup-Token": f.env.OWNER_SETUP_TOKEN },
      body: JSON.stringify({ email: EMAIL, masterPasswordHash: CLIENT_HASH, key: "2.wrapped-user", kdf: 0, kdfIterations: 600000,
        keys: { publicKey: "public", encryptedPrivateKey: "2.private" } }),
    }), 200);
    const current = sql.exec("SELECT master_password_hash,password_salt,password_iterations FROM users WHERE email=?", EMAIL).one();
    equal(current.password_iterations, 600000); equal(bytes(current.password_salt).length, 64);
    await validStoredPassword(CLIENT_HASH, current);
  });

  const KEY_ID = "0123456789abcdef0123456789abcdef";
  const clientKdf = (iterations = 600000) => ({ kdfType: 0, iterations, memory: null, parallelism: null });
  const currentRequest = (kdf = clientKdf()) => ({ masterPasswordHash: CLIENT_HASH,
    authenticationData: { salt: EMAIL, kdf: { ...kdf }, masterPasswordAuthenticationHash: NEXT_HASH },
    unlockData: { salt: EMAIL, kdf: { ...kdf }, masterKeyWrappedUserKey: "2.new-wrapped-user" } });
  const change = async (f, action, body) => f.fetch(`/api/accounts/${action}`, {
    method: "POST", headers: await owner(), body: JSON.stringify(body),
  });
  const envelope = () => sql.exec("SELECT key,user_key_id,private_key,public_key,signed_public_key,security_state,security_version,signature_key_pair FROM users WHERE id=?", USER).one();
  const identityState = () => JSON.stringify({
    users: sql.exec("SELECT * FROM users ORDER BY id").toArray(),
    devices: sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray(),
    factors: sql.exec("SELECT * FROM two_factors ORDER BY id").toArray(),
    passkeys: sql.exec("SELECT * FROM webauthn_credentials ORDER BY id").toArray(),
  });
  const seedPrf = () => {
    for (const [id, snapshot] of [["current", envelope()], ["stale", { ...envelope(), key: "previous-generation" }]]) {
      sql.exec("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,sign_count,credential_use,prf_status,encrypted_public_key,encrypted_user_key,encrypted_private_key,account_snapshot,created_at,updated_at) VALUES(?,?,?,'PRF test',?,'public',0,'login',0,'prf-public','prf-user','prf-private',?,'old','old')",
        `password-prf-${id}`, USER, id === "current" ? 1 : 2, `password-wire-${id}`, JSON.stringify(snapshot));
    }
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('password-remember',?,5,1,'{}',0)", USER);
  };

  await check("current-only KDF requests and exact flat confirmations commit one coherent credential set", async () => {
    for (const repeatFlat of [false, true]) {
      const f = await salted(1200000);
      sql.exec("UPDATE users SET user_key_id=? WHERE id=?", KEY_ID, USER); seedPrf();
      const kdf = { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 }, body = currentRequest(kdf);
      body.unlockData.containedKeyId = KEY_ID;
      if (repeatFlat) Object.assign(body, { key: body.unlockData.masterKeyWrappedUserKey, newMasterPasswordHash: NEXT_HASH,
        kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 });
      const bearer = await accessToken();
      await expect(await change(f, "kdf", body), 200);
      const user = sql.exec("SELECT key,user_key_id,kdf_type,kdf_iterations,kdf_memory,kdf_parallelism,private_key FROM users WHERE id=?", USER).one();
      equal(user.key, body.unlockData.masterKeyWrappedUserKey); equal(user.user_key_id, KEY_ID);
      equal(user.kdf_type, 1); equal(user.kdf_iterations, 3); equal(user.kdf_memory, 64); equal(user.kdf_parallelism, 4); equal(user.private_key, "2.private");
      equal(row().password_iterations, 1200000); await validStoredPassword(NEXT_HASH);
      await expect(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 401);
      const prf = sql.exec("SELECT account_snapshot,encrypted_private_key FROM webauthn_credentials WHERE id='password-prf-current'").one();
      equal(JSON.parse(prf.account_snapshot).key, user.key); equal(prf.encrypted_private_key, "prf-private");
      equal(JSON.parse(sql.exec("SELECT account_snapshot FROM webauthn_credentials WHERE id='password-prf-stale'").one().account_snapshot).key, "previous-generation");
      equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=? AND provider_type=5", USER).one().n, 0);
      await expect(await login(f, NEXT_HASH), 200);
    }
  });

  await check("legacy KDF and current-only password requests keep their complete protocol behavior", async () => {
    {
      const f = await salted();
      await expect(await change(f, "kdf", { masterPasswordHash: CLIENT_HASH, newMasterPasswordHash: NEXT_HASH,
        key: "2.legacy-wrapper", kdf: 0, kdfIterations: 750000 }), 200);
      const user = sql.exec("SELECT key,kdf_type,kdf_iterations,kdf_memory,kdf_parallelism FROM users WHERE id=?", USER).one();
      equal(user.key, "2.legacy-wrapper"); equal(user.kdf_type, 0); equal(user.kdf_iterations, 750000);
      equal(user.kdf_memory, null); equal(user.kdf_parallelism, null); await validStoredPassword(NEXT_HASH);
    }
    {
      const f = await salted(); sql.exec("UPDATE users SET user_key_id=? WHERE id=?", KEY_ID, USER); seedPrf();
      const body = currentRequest(); body.masterPasswordHint = "new client hint";
      await expect(await change(f, "password", body), 200);
      const user = sql.exec("SELECT key,user_key_id,master_password_hint FROM users WHERE id=?", USER).one();
      equal(user.user_key_id, KEY_ID); equal(user.key, body.unlockData.masterKeyWrappedUserKey); equal(user.master_password_hint, body.masterPasswordHint);
      equal(JSON.parse(sql.exec("SELECT account_snapshot FROM webauthn_credentials WHERE id='password-prf-current'").one().account_snapshot).key, user.key);
      await validStoredPassword(NEXT_HASH); await expect(await login(f, NEXT_HASH), 200);
    }
  });

  await check("partial, conflicting and wrongly bound KDF or password requests never write authentication state", async () => {
    const invalid = [
      body => { delete body.authenticationData; }, body => { delete body.unlockData; },
      body => { body.unlockData.kdf.iterations++; },
      body => { body.authenticationData.salt = "other@example.test"; },
      body => { body.unlockData.salt = "other@example.test"; },
      body => { body.unlockData.containedKeyId = "ffffffffffffffffffffffffffffffff"; },
      body => { body.newMasterPasswordHash = "conflicting-flat-hash"; body.key = body.unlockData.masterKeyWrappedUserKey; },
      body => { body.key = body.unlockData.masterKeyWrappedUserKey; },
      body => { body.kdf = 0; body.kdfIterations = 700000; },
      body => { body.authenticationData.masterPasswordAuthenticationHash = ""; },
      body => { body.unlockData.masterKeyWrappedUserKey = " "; },
    ];
    for (const action of ["kdf", "password"]) {
      for (const mutate of invalid) {
        const f = fixture(); sql.exec("UPDATE users SET master_password_hash=?,user_key_id=? WHERE id=?", CLIENT_HASH, KEY_ID, USER); seedPrf();
        const body = currentRequest(); mutate(body);
        const before = identityState(), batches = f.db.batches;
        await expect(await change(f, action, body), 400);
        equal(identityState(), before, `${action} rejected request changed authentication state`); equal(f.db.batches, batches);
      }
    }
  });

  await check("password changes reject KDF changes, public identity replacement and private-key version changes", async () => {
    for (const v2 of [false, true]) {
      for (const mutation of ["kdf", "public", "private", "empty"]) {
        const f = fixture();
        sql.exec("UPDATE users SET master_password_hash=?,private_key=?,security_version=? WHERE id=?", CLIENT_HASH, v2 ? "7.old-private" : "2.private", v2 ? 2 : null, USER);
        const body = currentRequest(mutation === "kdf" ? clientKdf(700000) : clientKdf());
        body.userAsymmetricKeys = { publicKey: mutation === "public" ? "replacement-public-identity" : "public",
          encryptedPrivateKey: mutation === "empty" ? "" : mutation === "private" ? (v2 ? "2.downgrade" : "7.unexpected-v2") : (v2 ? "7.rewrapped" : "2.rewrapped") };
        const before = identityState(); await expect(await change(f, "password", body), 400); equal(identityState(), before);
      }
    }
  });

  await check("private-key password rewraps invalidate PRF material atomically while preserving credentials and public identity", async () => {
    for (const v2 of [false, true]) {
      const f = await salted();
      sql.exec("UPDATE users SET private_key=?,security_version=?,user_key_id=? WHERE id=?", v2 ? "7.old-private" : "2.private", v2 ? 2 : null, KEY_ID, USER); seedPrf();
      const other = JSON.stringify(sql.exec("SELECT * FROM users WHERE id='other-owner'").one());
      const body = currentRequest(); body.userAsymmetricKeys = { publicKey: "public", encryptedPrivateKey: v2 ? "7.rewrapped-private" : "2.rewrapped-private" };
      await expect(await change(f, "password", body), 200);
      const user = envelope(); equal(user.private_key, body.userAsymmetricKeys.encryptedPrivateKey); equal(user.public_key, "public"); equal(user.user_key_id, KEY_ID);
      const passkeys = sql.exec("SELECT credential_id,public_key,prf_status,encrypted_public_key,encrypted_user_key,encrypted_private_key,account_snapshot FROM webauthn_credentials WHERE user_id=?", USER).toArray();
      equal(passkeys.length, 2);
      for (const passkey of passkeys) {
        equal(passkey.public_key, "public"); equal(passkey.prf_status, 1);
        for (const field of ["encrypted_public_key", "encrypted_user_key", "encrypted_private_key", "account_snapshot"]) equal(passkey[field], null);
      }
      equal(JSON.stringify(sql.exec("SELECT * FROM users WHERE id='other-owner'").one()), other);
      await validStoredPassword(NEXT_HASH);
    }
  });

  await check("failed private-key and PRF rewrites roll back the complete credential transaction", async () => {
    const f = await salted(); seedPrf();
    const before = identityState(), body = currentRequest();
    body.userAsymmetricKeys = { publicKey: "public", encryptedPrivateKey: "2.new-private" };
    sql.exec("CREATE TRIGGER password_prf_failure BEFORE UPDATE ON webauthn_credentials BEGIN SELECT RAISE(ABORT,'injected PRF cleanup failure'); END;");
    await expect(await change(f, "password", body), 500); equal(identityState(), before);
  });

  const createSend = async (f, password = CLIENT_HASH) => {
    const response = await expect(await f.fetch("/api/sends", { method: "POST", headers: await owner(),
      body: JSON.stringify({ type: 0, name: "encrypted-send", key: "2.wrapped-send", password,
        text: { text: "encrypted-content", hidden: false }, deletionDate: new Date(Date.now() + 86400000).toISOString() }) }), 200);
    return response.json();
  };
  const issueSend = (f, accessId, password = CLIENT_HASH) => f.fetch("/identity/connect/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "send_access", send_id: accessId, password_hash_b64: password }),
  });

  await check("Send passwords keep their independent creation cost and honor stored non-default and legacy missing costs", async () => {
    const f = fixture(), send = await createSend(f);
    let current = sql.exec("SELECT password_hash,password_salt,password_iterations FROM sends WHERE id=?", send.id).one();
    equal(current.password_iterations, 100000); equal(bytes(current.password_salt).length, 16);
    ok(current.password_hash === await derive(CLIENT_HASH, current.password_salt, 100000), "new Send used the account password cost");
    await expect(await issueSend(f, send.accessId), 200);
    for (const iterations of [150001, null]) {
      const encodedSalt = salt(16), hash = await derive(CLIENT_HASH, encodedSalt, iterations ?? 100000);
      sql.exec("UPDATE sends SET password_hash=?,password_salt=?,password_iterations=? WHERE id=?", hash, encodedSalt, iterations, send.id);
      await expect(await issueSend(f, send.accessId), 200);
      await expect(await issueSend(f, send.accessId, "wrong-password"), 400);
    }
  });

  await check("invalid persisted Send costs fail without invoking an expensive key derivation", async () => {
    const f = fixture(), send = await createSend(f), subtle = crypto.subtle;
    const original = subtle.deriveBits;
    let calls = 0;
    subtle.deriveBits = () => { calls++; throw new Error("Invalid Send cost reached PBKDF2"); };
    try {
      for (const cost of [0, -1]) {
        sql.exec("UPDATE sends SET password_iterations=? WHERE id=?", cost, send.id);
        await expect(await issueSend(f, send.accessId), 500);
      }
      equal(calls, 0);
    } finally { subtle.deriveBits = original; }
  });
}
