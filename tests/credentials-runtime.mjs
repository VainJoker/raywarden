import { snapshotTables } from "./runtime-fixture.mjs";
import {
  bearerJsonHeaders,
  emailCodeHash,
  equal,
  expectJsonOrEmpty,
  expectStatus,
  fixtureAccessSecret,
  oauthToken,
  ok,
  totp,
} from "./runtime-tools.mjs";

export async function runCredentialTests(context) {
  await runPasswordChecks(context);
  await runSetPasswordChecks(context);
  await runTwoFactorChecks(context);
  await runRecoveryChecks(context);
  await runProtectedActionChecks(context);
}

/** Account and Send verifiers exercised through compiled Rust and native SQL. */
async function runPasswordChecks({ fixture, check, sql, accessToken, USER }) {
  const CLIENT_HASH = "password-runtime-client-authentication-hash";
  const NEXT_HASH = "password-runtime-replacement-authentication-hash";
  const EMAIL = "owner@example.test";
  const DEVICE = "password-runtime-new-session";
  const bytes = salt => Uint8Array.from(atob(salt), char => char.charCodeAt(0));
  const salt = length => btoa(String.fromCharCode(...new Uint8Array(length).fill(42)));
  const derive = async (candidate, encodedSalt, iterations) => {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(candidate), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: bytes(encodedSalt), iterations }, key, 256);
    return btoa(String.fromCharCode(...new Uint8Array(bits)));
  };
  const row = () => sql.exec("SELECT master_password_hash,password_salt,password_iterations,security_stamp,updated_at FROM users WHERE id=?", USER).one();
  const login = (f, password = CLIENT_HASH, extra = {}) => oauthToken(f, {
    grant_type: "password", username: EMAIL, password,
    deviceIdentifier: DEVICE, deviceName: "Password Runtime", deviceType: "14", ...extra,
  }, { "device-type": "14", "Bitwarden-Client-Version": "2026.11.0" });
  const owner = async () => bearerJsonHeaders(await accessToken());
  const salted = async (iterations = 100000) => {
    const f = fixture(), encodedSalt = salt(16);
    const hash = await derive(CLIENT_HASH, encodedSalt, iterations);
    sql.exec("UPDATE users SET master_password_hash=?,password_salt=?,password_iterations=? WHERE id=?", hash, encodedSalt, iterations, USER);
    return f;
  };
  const validStoredPassword = async (candidate, current = row()) => {
    ok(await derive(candidate, current.password_salt, current.password_iterations) === current.master_password_hash, "Stored verifier does not match its own salt and iteration count");
  };
  await check("raw password verifiers upgrade only after success without moving the vault cursor or revoking another session", async () => {
    const f = fixture();
    sql.exec("UPDATE users SET master_password_hash=?,updated_at='2099-12-31T23:59:59.999Z' WHERE id=?", CLIENT_HASH, USER);
    const before = row(), oldBearer = await accessToken();
    await expectStatus(await login(f, "wrong-password"), 401);
    equal(JSON.stringify(row()), JSON.stringify(before), "failed login changed credentials");
    await expectStatus(await login(f), 200);
    const after = row();
    equal(after.password_iterations, 600000); equal(bytes(after.password_salt).length, 64);
    equal(after.updated_at, before.updated_at, "transparent upgrade changed the vault cursor");
    equal(after.security_stamp, before.security_stamp, "transparent upgrade revoked sessions");
    await validStoredPassword(CLIENT_HASH, after);
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${oldBearer}` } }), 200);
    await expectStatus(await login(f), 200);
    equal(JSON.stringify(row()), JSON.stringify(after), "current verifier was unnecessarily regenerated");
  });

  await check("salted Raywarden 100000-iteration verifiers upgrade using the recorded old cost", async () => {
    const f = await salted(); const before = row();
    await expectStatus(await login(f, "wrong-password"), 401);
    equal(JSON.stringify(row()), JSON.stringify(before));
    await expectStatus(await login(f), 200);
    const after = row();
    equal(after.password_iterations, 600000); equal(bytes(after.password_salt).length, 64);
    ok(after.password_salt !== before.password_salt, "old short salt was retained");
    equal(after.updated_at, before.updated_at); equal(after.security_stamp, before.security_stamp);
    await validStoredPassword(CLIENT_HASH, after);
  });

  await check("higher stored costs survive login and password changes, while empty replacement hashes are rejected", async () => {
    const f = await salted(1200000), before = row();
    await expectStatus(await login(f), 200);
    equal(JSON.stringify(row()), JSON.stringify(before), "login lowered or rewrote a higher-cost verifier");
    const headers = await owner();
    await expectStatus(await f.fetch("/api/accounts/password", { method: "POST", headers,
      body: JSON.stringify({ masterPasswordHash: CLIENT_HASH, newMasterPasswordHash: "", key: "2.next-user-key" }) }), 400);
    equal(JSON.stringify(row()), JSON.stringify(before), "empty replacement hash changed credentials");
    await expectStatus(await f.fetch("/api/accounts/password", { method: "POST", headers,
      body: JSON.stringify({ masterPasswordHash: CLIENT_HASH, newMasterPasswordHash: NEXT_HASH, key: "2.next-user-key" }) }), 200);
    equal(row().password_iterations, 1200000);
    await validStoredPassword(NEXT_HASH);
  });

  await check("password cost is upgraded only after completing the required second factor", async () => {
    const f = await salted();
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('password-runtime-totp',?,0,1,?,0)", USER, secret);
    const before = row();
    await expectStatus(await login(f), 400);
    equal(JSON.stringify(row()), JSON.stringify(before), "a second-factor challenge upgraded the verifier");
    await expectStatus(await login(f, CLIENT_HASH, { twoFactorProvider: "0", twoFactorToken: "invalid" }), 401);
    equal(JSON.stringify(row()), JSON.stringify(before), "a failed second factor upgraded the verifier");
    await expectStatus(await login(f, CLIENT_HASH, { twoFactorProvider: "0", twoFactorToken: await totp(secret) }), 200);
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
      await expectStatus(await login(f), 409);
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
    await expectStatus(await f.fetch("/api/accounts/register", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Raywarden-Setup-Token": f.env.OWNER_SETUP_TOKEN },
      body: JSON.stringify({ email: EMAIL, masterPasswordHash: CLIENT_HASH, key: "2.wrapped-user", kdf: 0, kdfIterations: 600000,
        keys: { publicKey: "public", encryptedPrivateKey: "2.private" } }),
    }), 200);
    const current = sql.exec("SELECT master_password_hash,password_salt,password_iterations FROM users WHERE email=?", EMAIL).one();
    equal(current.password_iterations, 600000); equal(bytes(current.password_salt).length, 64);
    await validStoredPassword(CLIENT_HASH, current);
  });

  await check("production PBKDF2 ceiling permits registration, login and existing higher-cost verifiers", async () => {
    const higherCost = await salted(1200000);
    const subtle = crypto.subtle, nativeDerive = subtle.deriveBits;
    let rejected = 0;
    subtle.deriveBits = function (algorithm, ...args) {
      if (algorithm.name === "PBKDF2" && algorithm.iterations > 100000) {
        rejected++;
        return Promise.reject(new DOMException("PBKDF2 iteration counts above 100000 are not supported", "NotSupportedError"));
      }
      return nativeDerive.call(this, algorithm, ...args);
    };
    let current;
    try {
      await expectStatus(await login(higherCost), 200);
      equal(row().password_iterations, 1200000);
      await expectStatus(await login(higherCost, "wrong-password"), 401);

      const f = fixture({ empty: true });
      f.env.ALLOWED_EMAILS = EMAIL; f.env.OWNER_SETUP_TOKEN = "password-runtime-private-owner-setup-token";
      await expectStatus(await f.fetch("/identity/accounts/register/finish", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Raywarden-Setup-Token": f.env.OWNER_SETUP_TOKEN },
        body: JSON.stringify({ email: EMAIL, masterPasswordHash: CLIENT_HASH, key: "2.wrapped-user", kdf: 0, kdfIterations: 600000,
          keys: { publicKey: "public", encryptedPrivateKey: "2.private" } }),
      }), 200);
      await expectStatus(await login(f), 200);
      current = sql.exec("SELECT master_password_hash,password_salt,password_iterations FROM users WHERE email=?", EMAIL).one();
      equal(current.password_iterations, 600000);
      equal(rejected, 0, "application sent an unsupported iteration count to Web Crypto");
    } finally {
      subtle.deriveBits = nativeDerive;
    }
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
      await expectStatus(await change(f, "kdf", body), 200);
      const user = sql.exec("SELECT key,user_key_id,kdf_type,kdf_iterations,kdf_memory,kdf_parallelism,private_key FROM users WHERE id=?", USER).one();
      equal(user.key, body.unlockData.masterKeyWrappedUserKey); equal(user.user_key_id, KEY_ID);
      equal(user.kdf_type, 1); equal(user.kdf_iterations, 3); equal(user.kdf_memory, 64); equal(user.kdf_parallelism, 4); equal(user.private_key, "2.private");
      equal(row().password_iterations, 1200000); await validStoredPassword(NEXT_HASH);
      await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 401);
      const prf = sql.exec("SELECT account_snapshot,encrypted_private_key FROM webauthn_credentials WHERE id='password-prf-current'").one();
      equal(JSON.parse(prf.account_snapshot).key, user.key); equal(prf.encrypted_private_key, "prf-private");
      equal(JSON.parse(sql.exec("SELECT account_snapshot FROM webauthn_credentials WHERE id='password-prf-stale'").one().account_snapshot).key, "previous-generation");
      equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=? AND provider_type=5", USER).one().n, 0);
      await expectStatus(await login(f, NEXT_HASH), 200);
    }
  });

  await check("legacy KDF and current-only password requests keep their complete protocol behavior", async () => {
    {
      const f = await salted();
      await expectStatus(await change(f, "kdf", { masterPasswordHash: CLIENT_HASH, newMasterPasswordHash: NEXT_HASH,
        key: "2.legacy-wrapper", kdf: 0, kdfIterations: 750000 }), 200);
      const user = sql.exec("SELECT key,kdf_type,kdf_iterations,kdf_memory,kdf_parallelism FROM users WHERE id=?", USER).one();
      equal(user.key, "2.legacy-wrapper"); equal(user.kdf_type, 0); equal(user.kdf_iterations, 750000);
      equal(user.kdf_memory, null); equal(user.kdf_parallelism, null); await validStoredPassword(NEXT_HASH);
    }
    {
      const f = await salted(); sql.exec("UPDATE users SET user_key_id=? WHERE id=?", KEY_ID, USER); seedPrf();
      const body = currentRequest(); body.masterPasswordHint = "new client hint";
      await expectStatus(await change(f, "password", body), 200);
      const user = sql.exec("SELECT key,user_key_id,master_password_hint FROM users WHERE id=?", USER).one();
      equal(user.user_key_id, KEY_ID); equal(user.key, body.unlockData.masterKeyWrappedUserKey); equal(user.master_password_hint, body.masterPasswordHint);
      equal(JSON.parse(sql.exec("SELECT account_snapshot FROM webauthn_credentials WHERE id='password-prf-current'").one().account_snapshot).key, user.key);
      await validStoredPassword(NEXT_HASH); await expectStatus(await login(f, NEXT_HASH), 200);
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
        await expectStatus(await change(f, action, body), 400);
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
        const before = identityState(); await expectStatus(await change(f, "password", body), 400); equal(identityState(), before);
      }
    }
  });

  await check("private-key password rewraps invalidate PRF material atomically while preserving credentials and public identity", async () => {
    for (const v2 of [false, true]) {
      const f = await salted();
      sql.exec("UPDATE users SET private_key=?,security_version=?,user_key_id=? WHERE id=?", v2 ? "7.old-private" : "2.private", v2 ? 2 : null, KEY_ID, USER); seedPrf();
      const other = JSON.stringify(sql.exec("SELECT * FROM users WHERE id='other-owner'").one());
      const body = currentRequest(); body.userAsymmetricKeys = { publicKey: "public", encryptedPrivateKey: v2 ? "7.rewrapped-private" : "2.rewrapped-private" };
      await expectStatus(await change(f, "password", body), 200);
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
    await expectStatus(await change(f, "password", body), 500); equal(identityState(), before);
  });

  const createSend = async (f, password = CLIENT_HASH) => {
    const response = await expectStatus(await f.fetch("/api/sends", { method: "POST", headers: await owner(),
      body: JSON.stringify({ type: 0, name: "encrypted-send", key: "2.wrapped-send", password,
        text: { text: "encrypted-content", hidden: false }, deletionDate: new Date(Date.now() + 86400000).toISOString() }) }), 200);
    return response.json();
  };
  const issueSend = (f, accessId, password = CLIENT_HASH) => oauthToken(f, {
    grant_type: "send_access", send_id: accessId, password_hash_b64: password,
  });

  await check("Send passwords keep their independent creation cost and honor stored non-default and legacy missing costs", async () => {
    const f = fixture(), send = await createSend(f);
    let current = sql.exec("SELECT password_hash,password_salt,password_iterations FROM sends WHERE id=?", send.id).one();
    equal(current.password_iterations, 100000); equal(bytes(current.password_salt).length, 16);
    ok(current.password_hash === await derive(CLIENT_HASH, current.password_salt, 100000), "new Send used the account password cost");
    await expectStatus(await issueSend(f, send.accessId), 200);
    for (const iterations of [150001, null]) {
      const encodedSalt = salt(16), hash = await derive(CLIENT_HASH, encodedSalt, iterations ?? 100000);
      sql.exec("UPDATE sends SET password_hash=?,password_salt=?,password_iterations=? WHERE id=?", hash, encodedSalt, iterations, send.id);
      await expectStatus(await issueSend(f, send.accessId), 200);
      await expectStatus(await issueSend(f, send.accessId, "wrong-password"), 400);
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
        await expectStatus(await issueSend(f, send.accessId), 500);
      }
      equal(calls, 0);
    } finally { subtle.deriveBits = original; }
  });
}

/** First-password compatibility for existing authenticated empty accounts. */
async function runSetPasswordChecks({ fixture, check, sql, accessToken, USER }) {
  const HASH = "set-password-client-authentication-hash", EMAIL = "owner@example.test";
  const owner = async () => bearerJsonHeaders(await accessToken());
  const post = async (f, body, headers) => f.fetch("/api/accounts/set-password", {
    method: "POST", headers: headers ?? await owner(), body: JSON.stringify(body),
  });
  const legacy = () => ({ masterPasswordHash: HASH, key: "2.new-wrapped-user", masterPasswordHint: "test hint" });
  const current = () => ({ masterPasswordAuthentication: { hash: HASH, salt: EMAIL,
    kdf: { kdfType: 0, iterations: 700000, memory: null, parallelism: null } },
    masterPasswordUnlock: { key: "2.current-wrapper", salt: EMAIL,
      kdf: { kdfType: 0, iterations: 700000, memory: null, parallelism: null } },
    userAsymmetricKeys: { publicKey: "public", encryptedPrivateKey: "2.initial-private" } });
  const state = () => snapshotTables(sql, ["users", "devices", "two_factors", "auth_requests", "webauthn_credentials", "ciphers"]);
  const other = () => JSON.stringify({ user: sql.exec("SELECT * FROM users WHERE id='other-owner'").one(),
    factors: sql.exec("SELECT * FROM two_factors WHERE user_id='other-owner'").toArray(),
    passkeys: sql.exec("SELECT * FROM webauthn_credentials WHERE user_id='other-owner'").toArray() });
  const emptyOwner = () => {
    const f = fixture();
    sql.exec("UPDATE users SET master_password_hash='',password_salt=NULL,private_key='',public_key='',key='2.existing-wrapper',signed_public_key=NULL,security_state=NULL,security_version=NULL,signature_key_pair=NULL WHERE id=?", USER);
    for (const user of [USER, "other-owner"]) {
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,5,1,'remember',0)", `set-remember-${user}`, user);
      sql.exec("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,prf_status,encrypted_public_key,encrypted_user_key,encrypted_private_key,created_at,updated_at) VALUES(?,?,1,'PRF',?,'public','login',0,'prf-public','prf-user','prf-private','old','old')", `set-prf-${user}`, user, `set-wire-${user}`);
      sql.exec("INSERT INTO auth_requests(id,user_id,request_device_id,device_type,request_ip,access_code,public_key,security_stamp,created_at,expires_at) VALUES(?,?,'requested-device',14,'ip','code','public','stamp','old','2099-01-01T00:00:00Z')", `set-request-${user}`, user);
    }
    return f;
  };
  const assertVerifier = async () => {
    const user = sql.exec("SELECT master_password_hash,password_salt,password_iterations FROM users WHERE id=?", USER).one();
    const salt = Uint8Array.from(atob(user.password_salt), char => char.charCodeAt(0)); equal(salt.length, 64);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(HASH), "PBKDF2", false, ["deriveBits"]);
    const derived = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: user.password_iterations }, key, 256));
    equal(user.master_password_hash, btoa(String.fromCharCode(...derived)));
  };
  const login = (f, password) => f.fetch("/identity/connect/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "device-type": "14", "Bitwarden-Client-Version": "2026.10.1" },
    body: new URLSearchParams({ grant_type: "password", username: EMAIL, password, deviceIdentifier: "set-password-login", deviceType: "14" }) });
  const isInitialization = writes => writes[0]?.sql.includes("account_write_token=?12");

  await check("set-password never creates an account and initialized accounts cannot reuse it", async () => {
    let f = fixture({ empty: true }); const initial = state();
    await expectStatus(await post(f, legacy(), { "Content-Type": "application/json" }), 401);
    await expectStatus(await post(f, legacy()), 401); equal(state(), initial);
    f = fixture(); const existing = state();
    const rejected = await expectStatus(await post(f, { accountKeys: {} }), 400);
    equal((await rejected.json()).message, "Invalid request: Account already initialized, cannot set password");
    equal(state(), existing);
    equal(sql.exec("SELECT COUNT(*) AS n FROM users").one().n, 2);
  });

  await check("an empty account cannot authenticate with an empty master password but a trusted session can initialize it", async () => {
    const f = emptyOwner(), before = state();
    for (const password of ["", " "]) {
      await expectStatus(await login(f, password), 401);
      await expectStatus(await f.fetch("/api/accounts/verify-password", { method: "POST", headers: await owner(), body: JSON.stringify({ masterPasswordHash: password }) }), 401);
      equal(state(), before);
    }
    const cipher = JSON.stringify(sql.exec("SELECT * FROM ciphers ORDER BY id").toArray()), unrelated = other();
    const prelogin = await (await expectStatus(await f.fetch("/api/accounts/prelogin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: EMAIL }) }), 200)).json();
    await expectStatus(await post(f, legacy()), 200); await assertVerifier();
    const user = sql.exec("SELECT * FROM users WHERE id=?", USER).one();
    equal(user.key, "2.new-wrapped-user"); equal(user.kdf_type, prelogin.kdf); equal(user.kdf_iterations, prelogin.kdfIterations);
    equal(user.password_iterations, 600000); equal(user.security_stamp, "owner-stamp"); equal(user.master_password_hint, "test hint");
    equal(JSON.stringify(sql.exec("SELECT * FROM ciphers ORDER BY id").toArray()), cipher);
    equal(other(), unrelated); equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=? AND provider_type=5", USER).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM auth_requests WHERE user_id=?", USER).one().n, 0);
    const prf = sql.exec("SELECT * FROM webauthn_credentials WHERE user_id=?", USER).one();
    equal(prf.credential_id, `set-wire-${USER}`);
    equal(prf.prf_status, 1); equal(prf.encrypted_user_key, null); equal(prf.encrypted_private_key, null);
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: await owner() }), 200);
    // This reference flow deliberately retains the session for late key setup.
    await expectStatus(await f.fetch("/api/accounts/keys", { method: "POST", headers: await owner(), body: JSON.stringify({ publicKey: "public", encryptedPrivateKey: "2.late-private" }) }), 200);
    await expectStatus(await login(f, HASH), 200);
    const completed = state(); await expectStatus(await post(f, legacy()), 400); equal(state(), completed);
  });

  await check("modern V1 initialization and explicit legacy Argon settings preserve stronger server costs", async () => {
    for (const format of ["legacy", "modern", "modern-keys-alias", "modern-v1-contained-id"]) {
      const modern = format !== "legacy";
      const f = emptyOwner(); sql.exec("UPDATE users SET password_iterations=1200000 WHERE id=?", USER);
      const body = modern ? current() : { ...legacy(), kdf: 1, kdfIterations: 3, keys: { publicKey: "public", encryptedPrivateKey: "2.initial-private" } };
      if (format === "modern-keys-alias") { body.keys = body.userAsymmetricKeys; delete body.userAsymmetricKeys; }
      if (format === "modern-v1-contained-id") body.masterPasswordUnlock.containedKeyId = "0123456789abcdef0123456789abcdef";
      await expectStatus(await post(f, body), 200); await assertVerifier();
      const user = sql.exec("SELECT * FROM users WHERE id=?", USER).one();
      equal(user.public_key, "public"); equal(user.private_key, "2.initial-private"); equal(user.password_iterations, 1200000);
      equal(user.user_key_id, null, "optional V1 containedKeyId must not establish V2 identity");
      equal(user.kdf_type, modern ? 0 : 1); equal(user.kdf_iterations, modern ? 700000 : 3);
      equal(user.kdf_memory, modern ? null : 64); equal(user.kdf_parallelism, modern ? null : 4);
      await expectStatus(await login(f, HASH), 200);
    }
  });

  await check("set-password preserves an existing public identity and rejects incomplete, mixed and V2 material without writes", async () => {
    const invalid = [
      () => ({ ...legacy(), masterPasswordHash: "" }), () => ({ ...legacy(), key: " " }),
      () => ({ ...legacy(), kdf: 1 }), () => ({ ...legacy(), kdfMemory: 64 }),
      () => ({ ...legacy(), keys: { publicKey: "different-identity", encryptedPrivateKey: "2.private" } }),
      () => ({ ...legacy(), keys: { publicKey: "public", encryptedPrivateKey: "7.private" } }),
      () => ({ ...legacy(), accountKeys: {} }),
      () => ({ ...current(), keys: { publicKey: "public", encryptedPrivateKey: "2.private" } }),
      () => { const body = current(); delete body.masterPasswordUnlock; return body; },
      () => { const body = current(); body.masterPasswordUnlock.kdf.iterations++; return body; },
      () => { const body = current(); body.masterPasswordAuthentication.salt = "other@example.test"; return body; },
      () => { const body = current(); body.masterPasswordUnlock.containedKeyId = "invalid-key-id"; return body; },
      () => ({ ...current(), ...legacy() }),
    ];
    for (const make of invalid) {
      const f = emptyOwner(); sql.exec("UPDATE users SET public_key='public' WHERE id=?", USER);
      const before = state(); await expectStatus(await post(f, make()), 400); equal(state(), before);
    }
    const f = emptyOwner(); sql.exec("UPDATE users SET public_key='existing-public' WHERE id=?", USER);
    await expectStatus(await post(f, legacy()), 200);
    equal(sql.exec("SELECT public_key FROM users WHERE id=?", USER).one().public_key, "existing-public");
  });

  await check("partial initialization, V2 state and revoked sessions cannot authorize first-password writes", async () => {
    for (const [column, value] of [["master_password_hash", "existing-hash"], ["private_key", "2.existing"], ["security_version", 2], ["signed_public_key", "signed"]]) {
      const f = emptyOwner(); sql.exec(`UPDATE users SET ${column}=? WHERE id=?`, value, USER);
      const before = state(); await expectStatus(await post(f, legacy()), 400); equal(state(), before);
    }
    for (const [table, column, value] of [["devices", "session_token", "revoked"], ["users", "security_stamp", "revoked"]]) {
      const f = emptyOwner(); sql.exec(`UPDATE ${table} SET ${column}=? WHERE ${table === "users" ? "id" : "user_id"}=?`, value, USER);
      const before = state(); await expectStatus(await post(f, legacy()), 401); equal(state(), before);
    }
  });

  await check("initialization fences concurrent credentials, KDF, envelope and device-session changes before any cleanup", async () => {
    const changes = [["users", "master_password_hash", "concurrent-hash"], ["users", "private_key", "2.concurrent-private"],
      ["users", "public_key", "concurrent-public"], ["users", "key", "concurrent-wrapper"],
      ["users", "password_salt", "concurrent-salt"], ["users", "password_iterations", 1200000],
      ["users", "security_stamp", "concurrent-stamp"], ["users", "security_version", 2], ["users", "user_key_id", "new-id"],
      ["users", "kdf_type", 1], ["users", "kdf_iterations", 700000], ["users", "kdf_memory", 64],
      ["users", "kdf_parallelism", 4], ["devices", "session_token", "concurrent-nonce"]];
    for (const [table, column, value] of changes) {
      const f = emptyOwner(); let expected;
      const reached = f.db.beforeNextBatch(isInitialization, () => {
        sql.exec(`UPDATE ${table} SET ${column}=? WHERE ${table === "users" ? "id" : "user_id"}=?`, value, USER);
        expected = state();
      });
      await expectStatus(await post(f, legacy()), 409); equal(reached(), true); equal(state(), expected);
    }
  });

  await check("concurrent first-password submissions have one winner and late-key races cannot overwrite identity", async () => {
    {
      const f = emptyOwner(), batch = f.db.batch.bind(f.db); let pending = 0, release;
      const ready = new Promise(resolve => { release = resolve; });
      f.db.batch = async writes => { if (isInitialization(writes)) { if (++pending === 2) release(); await ready; } return batch(writes); };
      const replies = await Promise.all([post(f, legacy()), post(f, legacy())]);
      equal(pending, 2); equal(replies.map(response => response.status).sort().join(","), "200,409");
      for (const response of replies) await response.text(); await assertVerifier();
    }
    {
      const f = emptyOwner(), batch = f.db.batch.bind(f.db); let reached = false, expected;
      f.db.batch = async writes => {
        if (!reached && isInitialization(writes)) {
          reached = true;
          await expectStatus(await f.fetch("/api/accounts/keys", { method: "POST", headers: await owner(), body: JSON.stringify({ publicKey: "concurrent-identity", encryptedPrivateKey: "2.concurrent-private" }) }), 200);
          expected = state();
        }
        return batch(writes);
      };
      await expectStatus(await post(f, current()), 409); equal(reached, true); equal(state(), expected);
    }
  });

  await check("late initialization cleanup failure rolls back password, wrapper, private keys and Remember", async () => {
    const f = emptyOwner(), before = state();
    sql.exec("CREATE TRIGGER initialization_failure BEFORE UPDATE ON webauthn_credentials BEGIN SELECT RAISE(ABORT,'injected initialization failure'); END;");
    await expectStatus(await post(f, current()), 500); equal(state(), before);
  });
}

// Actual authenticator HTTP handlers and native SQLite transactions. The test
// client computes its TOTP independently with WebCrypto HMAC-SHA1.
async function runTwoFactorChecks({ fixture, check, accessToken, USER, sql }) {
  async function request(f, path, body, bearer, method = "POST") {
    return f.fetch(path, { method, headers: bearerJsonHeaders(bearer ?? await accessToken()), body: JSON.stringify(body) });
  }
  async function responseJson(response, status) {
    const text = await (await expectStatus(response, status)).text();
    try { return JSON.parse(text); } catch { throw new Error(`Non-JSON HTTP ${status}: ${text}`); }
  }
  const get = (f, bearer) => request(f, "/api/two-factor/get-authenticator", { masterPasswordHash: "hash" }, bearer).then(response => responseJson(response, 200));
  const activate = async (f, setup, bearer) => request(f, "/api/two-factor/authenticator", {
    key: setup.key, token: await totp(setup.key), userVerificationToken: setup.userVerificationToken,
  }, bearer);
  const disable = (f, setup, bearer) => request(f, "/api/two-factor/authenticator", {
    key: setup.key, type: 0, userVerificationToken: setup.userVerificationToken,
  }, bearer, "DELETE");
  const remember = () => sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('totp-runtime-remember',?,5,1,'{}',0)", USER);
  const count = type => sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=? AND provider_type=?", USER, type).one().n;
  function shape(body, enabled) {
    equal(body.enabled, enabled); equal(body.authenticator.enabled, enabled);
    equal(body.authenticator.key, body.key); ok(typeof body.key === "string" && body.key.length > 0, "missing TOTP key");
  }

  await check("profile and sync agree on enabled login factors without counting Remember or internal records", async () => {
    for (const [type, enabled, expected] of [[0, 1, true], [1, 1, true], [7, 1, true], [5, 1, false], [0, 0, false], [1, 0, false], [7, 0, false], [1000, 1, false], [2, 1, true]]) {
      const f = fixture();
      const data = type === 1 ? JSON.stringify({ email: "factor@example.test" }) : type === 0 ? "JBSWY3DPEHPK3PXP" : "{}";
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('status-factor',?,?,?,?,0)", USER, type, enabled, data);
      const headers = { Authorization: `Bearer ${await accessToken()}` };
      const profile = await responseJson(await f.fetch("/api/accounts/profile", { headers }), 200);
      const sync = await responseJson(await f.fetch("/api/sync?excludeDomains=true", { headers }), 200);
      equal(profile.twoFactorEnabled, expected, `profile factor ${type}/${enabled}`);
      equal(sync.profile.twoFactorEnabled, expected, `sync factor ${type}/${enabled}`);
    }
  });

  const emailFactor = address => sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('email-runtime-factor',?,1,1,?,0)", USER, JSON.stringify({ email: address }));
  const emailProof = async (f, bearer) => responseJson(await request(f, "/api/two-factor/get-email", { masterPasswordHash: "hash" }, bearer), 200);

  await check("email action proofs keep their own purpose and provider-state binding across both handlers", async () => {
    const f = fixture(); emailFactor("first-factor@example.test"); remember();
    const proof = await emailProof(f); const setup = await get(f);
    await responseJson(await request(f, "/api/two-factor/email", { userVerificationToken: setup.userVerificationToken }, undefined, "DELETE"), 401);
    await responseJson(await request(f, "/api/two-factor/get-authenticator", { userVerificationToken: proof.userVerificationToken }), 400);
    equal(count(1), 1); equal(count(5), 1);
    sql.exec("UPDATE two_factors SET data=? WHERE user_id=? AND provider_type=1", JSON.stringify({ email: "new-factor@example.test" }), USER);
    await responseJson(await request(f, "/api/two-factor/disable", { type: 1, userVerificationToken: proof.userVerificationToken }), 401);
    equal(count(1), 1); equal(count(5), 1);
    const current = await emailProof(f);
    await responseJson(await request(f, "/api/two-factor/disable", { type: 1, userVerificationToken: current.userVerificationToken }), 200);
    equal(count(1), 0); equal(count(5), 0);
  });

  await check("a valid new session cannot reuse an email action proof but can mint its own", async () => {
    const f = fixture(); emailFactor("factor@example.test"); remember();
    const proof = await emailProof(f);
    sql.exec("UPDATE devices SET session_token='email-new-session' WHERE user_id=? AND device_id='device'", USER);
    const bearer = await accessToken({ session_token: "email-new-session" });
    await responseJson(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 200);
    await responseJson(await request(f, "/api/two-factor/email", { userVerificationToken: proof.userVerificationToken }, bearer, "DELETE"), 401);
    equal(count(1), 1); equal(count(5), 1);
    const current = await emailProof(f, bearer);
    await responseJson(await request(f, "/api/two-factor/email", { userVerificationToken: current.userVerificationToken }, bearer, "DELETE"), 200);
    equal(count(1), 0); equal(count(5), 0);
  });

  await check("TOTP real setup proof activates and disables; get actions reject proof renewal", async () => {
    const f = fixture(); const setup = await get(f);
    shape(setup, false); ok(setup.userVerificationToken, "missing setup proof");
    for (const path of ["/api/two-factor/get-authenticator", "/api/two-factor/get-recover"]) {
      await responseJson(await request(f, path, { userVerificationToken: setup.userVerificationToken }), 400);
    }
    const enabled = await responseJson(await activate(f, setup), 200);
    shape(enabled, true); equal(count(0), 1);
    const first = sql.exec("SELECT * FROM two_factors WHERE user_id=? AND provider_type=0", USER).one();
    ok(first.last_used_step > 0, "setup did not consume the accepted TOTP step");
    await responseJson(await activate(f, setup), 400);
    const current = await get(f); shape(current, true); equal(current.key, setup.key);
    const disabled = await responseJson(await disable(f, current), 200);
    equal(disabled.enabled, false); equal(disabled.type, 0); equal(count(0), 0);
  });

  await check("invalid Base32 in a submitted TOTP key is a client error and stored corruption is a server error", async () => {
    const f = fixture();
    for (const key of ["0" + "A".repeat(31), "ſ" + "A".repeat(31)]) {
      const error = await responseJson(await request(f, "/api/two-factor/authenticator", {
        key, token: "123456", masterPasswordHash: "hash",
      }), 400);
      equal(error.message, "Invalid request: Invalid Base32 key");
    }
    equal(count(0), 0);
    sql.exec("INSERT INTO two_factors VALUES('invalid-totp',?,0,1,?,0)", USER, "0" + "A".repeat(31));
    const failure = await responseJson(await oauthToken(f, {
      grant_type: "password", username: "owner@example.test", password: "hash",
      deviceIdentifier: "invalid-totp-device", deviceName: "Runtime test", deviceType: "14",
      twoFactorProvider: "0", twoFactorToken: "123456",
    }, { "Bitwarden-Client-Version": "2026.10.1", "device-type": "14" }), 500);
    equal(failure.code, 3); equal(failure.message, "Internal server error");
    equal(sql.exec("SELECT last_used_step FROM two_factors WHERE id='invalid-totp'").one().last_used_step, 0);
  });

  await check("TOTP POST/PUT aliases preserve setup proof purpose and replay protection", async () => {
    for (const method of ["POST", "PUT"]) {
      const f = fixture(); const setup = await get(f);
      const body = { key: setup.key, token: await totp(setup.key), userVerificationToken: setup.userVerificationToken };
      shape(await responseJson(await request(f, "/api/two-factor/authenticator", body, undefined, method), 200), true);
      await responseJson(await request(f, "/api/two-factor/authenticator", body, undefined, method), 400);
      const current = await get(f);
      sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,code_hash,issued_at,expires_at) VALUES('protected',?,?,'protected-action','owner@example.test','hash',100,700)", USER, USER);
      await responseJson(await request(f, "/api/two-factor/disable", { type: 0, userVerificationToken: current.userVerificationToken }, undefined, method), 200);
      equal(count(0), 0);
      equal(sql.exec("SELECT COUNT(*) AS count FROM verification_codes WHERE id='protected'").one().count, 0);
      await responseJson(await request(f, "/api/two-factor/disable", { type: 0, userVerificationToken: current.userVerificationToken }, undefined, method), 400);
    }
  });

  await check("modern TOTP recovery writes roll back enrollment and preserve recovery for legacy factors", async () => {
    const f = fixture(), setup = await get(f); remember();
    const recovery = () => sql.exec("SELECT two_factor_recovery_code AS code FROM users WHERE id=?", USER).one().code;
    sql.exec("CREATE TRIGGER reject_recovery BEFORE UPDATE OF two_factor_recovery_code ON users BEGIN SELECT RAISE(ABORT,'injected recovery failure'); END");
    await responseJson(await activate(f, setup), 500);
    equal(count(0), 0); equal(count(5), 1); equal(recovery(), null);
    sql.exec("DROP TRIGGER reject_recovery");
    await responseJson(await activate(f, setup), 200);
    const code = recovery(); ok(code, "successful activation did not initialize recovery");
    sql.exec("INSERT INTO two_factors VALUES('legacy-factor',?,2,1,'legacy',0)", USER);
    const current = await get(f);
    await responseJson(await disable(f, current), 200);
    equal(count(0), 0); equal(count(2), 1); equal(recovery(), code);
    await responseJson(await request(f, "/api/two-factor/disable", { type: 2, masterPasswordHash: "hash" }), 200);
    equal(recovery(), null);
  });

  await check("MFA activation claims a protected-action OTP only when the factor is enabled", async () => {
    for (const type of [0, 1]) {
      const f = fixture(); remember();
      const isEmail = type === 1;
      const path = `/api/two-factor/${isEmail ? "email" : "authenticator"}`;
      const key = isEmail ? undefined : (await get(f)).key;
      const codes = {};
      f.env.MAIL_WEBHOOK_URL = "https://mfa-mail.runtime.test/send";
      const fetch = globalThis.fetch;
      globalThis.fetch = async input => {
        const outbound = input instanceof Request ? input : new Request(input);
        equal(outbound.url, f.env.MAIL_WEBHOOK_URL);
        const message = await outbound.json();
        codes[message.purpose] = message.text.split("\n\n")[1];
        return Response.json({});
      };
      try {
        await responseJson(await request(f, "/api/accounts/request-otp", {}), 200);
        if (isEmail) {
          await responseJson(await request(f, "/api/two-factor/send-email", {
            email: "factor@example.test", masterPasswordHash: "hash",
          }), 200);
        }
      } finally {
        globalThis.fetch = fetch;
      }

      const otp = codes["protected-action"];
      ok(otp, "the protected-action code was not delivered");
      if (isEmail) ok(codes["email-setup"], "the mailbox code was not delivered");
      const token = () => isEmail ? codes["email-setup"] : totp(key);
      const activate = async () => request(f, path, { key, otp, token: await token() });
      const proof = purpose => sql.exec("SELECT attempts, consumed_at FROM verification_codes WHERE user_id=? AND purpose=?", USER, purpose).one();
      const expectPending = () => {
        equal(count(type), 0);
        equal(count(5), 1);
        equal(proof("protected-action").attempts, 1);
        equal(proof("protected-action").consumed_at, null);
        if (isEmail) {
          equal(proof("email-setup").attempts, 1);
          equal(proof("email-setup").consumed_at, null);
        }
      };

      await responseJson(await request(f, path, { key, otp: "wrong", token: await token() }), 400);
      await responseJson(await request(f, path, { key, otp, token: "wrong" }), isEmail ? 400 : 401);
      expectPending();

      sql.exec("CREATE TRIGGER reject_otp_enrollment BEFORE UPDATE OF two_factor_recovery_code ON users BEGIN SELECT RAISE(ABORT,'injected OTP enrollment failure'); END");
      await responseJson(await activate(), 500);
      expectPending();
      sql.exec("DROP TRIGGER reject_otp_enrollment");

      const batch = f.db.batch.bind(f.db); let raced = false;
      f.db.batch = async statements => {
        if (!raced && statements.some(statement => /^INSERT INTO\s+two_factors/.test(statement.sql.trim()))) {
          raced = true;
          sql.exec("UPDATE devices SET session_token='replaced' WHERE user_id=? AND device_id='device'", USER);
        }
        return batch(statements);
      };
      await responseJson(await activate(), 409);
      equal(raced, true, "activation did not reach its write transaction");
      expectPending();
      sql.exec("UPDATE devices SET session_token='session' WHERE user_id=? AND device_id='device'", USER);

      const enabled = await responseJson(await activate(), 200);
      equal(enabled.enabled, true);
      equal(count(type), 1);
      equal(count(5), 0);
      equal(proof("protected-action").attempts, 2);
      ok(proof("protected-action").consumed_at, "authorization OTP was left reusable");
      if (isEmail) {
        equal(sql.exec("SELECT COUNT(*) AS n FROM verification_codes WHERE user_id=? AND purpose='email-setup'", USER).one().n, 0);
      }
      await responseJson(await activate(), 400);
    }
  });

  await check("two concurrent activations of the same TOTP setup publish only one factor", async () => {
    const f = fixture(); const setup = await get(f); remember();
    const code = await totp(setup.key);
    const body = { key: setup.key, token: code, userVerificationToken: setup.userVerificationToken };
    const responses = await Promise.all([request(f, "/api/two-factor/authenticator", body), request(f, "/api/two-factor/authenticator", body)]);
    equal(responses.filter(response => response.status === 200).length, 1);
    for (const response of responses) {
      const text = await response.text();
      ok([200, 400, 401, 409].includes(response.status), `Unexpected activation HTTP ${response.status}: ${text}`);
    }
    equal(count(0), 1); equal(count(5), 0, "successful setup did not atomically clear Remember tokens");
    equal(sql.exec("SELECT data FROM two_factors WHERE user_id=? AND provider_type=0", USER).one().data, setup.key);
  });

  await check("a valid new session cannot reuse the previous session's TOTP proof", async () => {
    const f = fixture(); const setup = await get(f); remember();
    sql.exec("UPDATE devices SET session_token='new-session' WHERE user_id=? AND device_id='device'", USER);
    const bearer = await accessToken({ session_token: "new-session" });
    const positive = await f.fetch("/api/two-factor/get-device-verification-settings", { headers: { Authorization: `Bearer ${bearer}` } });
    await responseJson(positive, 200);
    await responseJson(await activate(f, setup, bearer), 401);
    equal(count(0), 0); equal(count(5), 1, "rejected proof changed Remember state");
  });

  await check("a stale TOTP delete snapshot rolls back before clearing Remember tokens", async () => {
    const f = fixture(); const setup = await get(f);
    await responseJson(await activate(f, setup), 200);
    const current = await get(f); remember();
    const batch = f.db.batch.bind(f.db); let changed = false;
    f.db.batch = async statements => {
      if (!changed && statements.some(statement => /^DELETE FROM two_factors WHERE id=/.test(statement.sql.trim()))) {
        changed = true;
        sql.exec("UPDATE two_factors SET last_used_step=last_used_step+1 WHERE user_id=? AND provider_type=0", USER);
      }
      return batch(statements);
    };
    await responseJson(await disable(f, current), 409);
    equal(changed, true, "delete did not reach the actual snapshot transaction");
    equal(count(0), 1); equal(count(5), 1, "failed configuration snapshot cleared Remember tokens");
  });
}

/** Recovery-code ownership, snapshot and transaction regressions. */
async function runRecoveryChecks({ fixture, check, sql }) {
  const CODE = "ABCDEF0123456789ABCDEF0123456789";
  const EMAIL = "owner@example.test";
  const seed = () => {
    const f = fixture();
    const owner = sql.exec("SELECT id FROM users WHERE email=?", EMAIL).one().id;
    for (const user of [owner, "other-owner"]) {
      sql.exec("UPDATE users SET two_factor_recovery_code=? WHERE id=?", CODE, user);
      for (const kind of [0, 1, 5, 7]) {
        sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,?,1,'factor-data',0)", `${user}-${kind}`, user, kind);
      }
      sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,code_hash,issued_at,expires_at,ready) VALUES(?,?,?,'email-2fa',?,'code-hash',1,9999999999,1)", `code-${user}`, user, user, `${user}@example.test`);
      for (const use of ["login", "2fa"]) {
        const key = `${user}-${use}`;
        sql.exec("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,created_at,updated_at) VALUES(?,?,1,'key',?,'public',?,'before','before')", key, user, key, use);
      }
    }
    return { ...f, owner };
  };
  const state = () => JSON.stringify({
    users: sql.exec("SELECT * FROM users ORDER BY id").toArray(),
    devices: sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray(),
    providers: sql.exec("SELECT * FROM two_factors ORDER BY id").toArray(),
    codes: sql.exec("SELECT * FROM verification_codes ORDER BY id").toArray(),
    passkeys: sql.exec("SELECT * FROM webauthn_credentials ORDER BY id").toArray(),
  });
  const otherState = () => JSON.stringify({
    user: sql.exec("SELECT * FROM users WHERE id='other-owner'").one(),
    providers: sql.exec("SELECT * FROM two_factors WHERE user_id='other-owner' ORDER BY id").toArray(),
    codes: sql.exec("SELECT * FROM verification_codes WHERE user_id='other-owner' ORDER BY id").toArray(),
    passkeys: sql.exec("SELECT * FROM webauthn_credentials WHERE user_id='other-owner' ORDER BY id").toArray(),
  });
  const recover = (f, override = {}, headers = {}) => f.fetch("/api/two-factor/recover", {
    method: "POST", headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ email: EMAIL, masterPasswordHash: "hash", recoveryCode: CODE, ...override }),
  });
  const login = (f, { version = "2026.10.1", code = CODE, username = EMAIL, device = "recovery-runtime-client" } = {}) => oauthToken(f, {
    grant_type: "password", username, password: "hash",
    deviceIdentifier: device, deviceName: "Recovery Browser", deviceType: "14",
    twoFactorProvider: "8", twoFactorToken: code, twoFactorRemember: "1",
  }, { "device-type": "14", ...(version === null ? {} : { "Bitwarden-Client-Version": version }) });
  const call = (kind, f) => kind === "recover" ? recover(f) : login(f);
  const isRecovery = statements => statements.some(statement => statement.sql.startsWith("UPDATE users SET two_factor_recovery_code=NULL,account_write_token="));
  const assertCleared = (f, other) => {
    equal(sql.exec("SELECT two_factor_recovery_code FROM users WHERE id=?", f.owner).one().two_factor_recovery_code, null);
    equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=?", f.owner).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM verification_codes WHERE user_id=?", f.owner).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id=? AND credential_use='2fa'", f.owner).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id=? AND credential_use='login'", f.owner).one().n, 1);
    equal(otherState(), other, "other user's authentication state");
  };

  await check("public recovery atomically consumes its code and factors while preserving login keys and other users", async () => {
    const f = seed(), other = otherState();
    const stamp = sql.exec("SELECT security_stamp FROM users WHERE id=?", f.owner).one().security_stamp;
    const devices = JSON.stringify(sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray());
    await expectStatus(await recover(f, { email: " Owner@Example.TEST ", recoveryCode: CODE.toLowerCase() }), 200);
    assertCleared(f, other);
    equal(sql.exec("SELECT security_stamp FROM users WHERE id=?", f.owner).one().security_stamp, stamp);
    equal(JSON.stringify(sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray()), devices, "public recovery retains the existing session policy");
    const completed = state();
    await expectStatus(await recover(f), 401);
    equal(state(), completed, "replayed public recovery cannot change state");
  });

  await check("incorrect recovery credentials leave every provider and verification record intact", async () => {
    const f = seed(), before = state();
    for (const body of [{ masterPasswordHash: "wrong-password" }, { recoveryCode: "wrong-code" }, { email: "missing@example.test" }]) {
      const response = await expectStatus(await recover(f, body), 401);
      if (body.recoveryCode) {
        const error = await response.json();
        equal(error.code, 2);
        equal(error.message, "Invalid credentials: Invalid recovery code");
      }
      equal(state(), before);
    }
    sql.exec("UPDATE users SET two_factor_recovery_code='' WHERE id=?", f.owner);
    const invalid = state();
    await expectStatus(await recover(f, { recoveryCode: "" }), 401);
    equal(state(), invalid);
  });

  await check("both recovery entry points reject changed credential and raw-code snapshots before cleanup", async () => {
    for (const kind of ["recover", "login"]) {
      for (const [column, value] of [
        ["security_stamp", "changed-stamp"], ["master_password_hash", "changed-password-hash"],
        ["password_salt", "changed-password-salt"], ["password_iterations", 1200000],
        ["two_factor_recovery_code", "new-recovery-code"], ["two_factor_recovery_code", CODE.toLowerCase()],
        ["email", "changed-owner@example.test"],
      ]) {
        const f = seed(), batch = f.db.batch.bind(f.db);
        let changed = false, expected;
        f.db.batch = async statements => {
          if (!changed && isRecovery(statements)) {
            changed = true;
            sql.exec(`UPDATE users SET ${column}=? WHERE id=?`, value, f.owner);
            expected = state();
          }
          return batch(statements);
        };
        await expectStatus(await call(kind, f), 409);
        equal(changed, true, `${kind} did not reach the actual recovery batch`);
        equal(state(), expected, `${kind} cleaned state after ${column} changed`);
      }
    }
  });

  await check("simultaneous verified recovery attempts commit one winner through either entry point", async () => {
    for (const kind of ["recover", "login"]) {
      const f = seed(), other = otherState(), batch = f.db.batch.bind(f.db);
      let pending = 0, release;
      const ready = new Promise(resolve => { release = resolve; });
      f.db.batch = async statements => {
        if (isRecovery(statements)) {
          if (++pending === 2) release();
          await ready;
        }
        return batch(statements);
      };
      const responses = await Promise.all([call(kind, f), call(kind, f)]);
      equal(pending, 2, "both requests must reach the verified snapshot write");
      equal(responses.map(response => response.status).sort().join(","), "200,409");
      for (const response of responses) await response.text();
      assertCleared(f, other);
    }
  });

  await check("a late database failure rolls back recovery code consumption and every cleanup", async () => {
    for (const kind of ["recover", "login"]) {
      const f = seed();
      sql.exec("CREATE TRIGGER recovery_runtime_failure BEFORE DELETE ON two_factors BEGIN SELECT RAISE(ABORT, 'injected recovery cleanup failure'); END;");
      const before = state();
      await expectStatus(await call(kind, f), 500);
      equal(state(), before, `${kind} partially committed recovery cleanup`);
    }
  });

  await check("recovery login keeps factors and the prior session on signing or session-write failure", async () => {
    for (const failure of ["signing", "device upsert"]) {
      const f = seed();
      let username = EMAIL;
      if (failure === "signing") {
        username = `${"a".repeat(9000)}@example.test`;
        sql.exec("UPDATE users SET email=? WHERE id=?", username, f.owner);
      } else {
        sql.exec("CREATE TRIGGER reject_recovery_session BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'fixture session rejected'); END;");
      }
      const before = state();
      await expectStatus(await login(f, { username, device: "device" }), 500);
      equal(state(), before, `${failure} changed recovery or session state`);
      if (failure === "signing") {
        sql.exec("UPDATE users SET email=? WHERE id=?", EMAIL, f.owner);
      } else {
        sql.exec("DROP TRIGGER reject_recovery_session");
      }
      const other = otherState();
      const tokens = await (await expectStatus(await login(f, { device: "device" }), 200)).json();
      assertCleared(f, other);
      await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${tokens.access_token}` } }), 200);
    }
  });

  await check("public recovery enforces real IP and normalized-email rate limits including unknown accounts", async () => {
    class Ratelimit {
      calls = []; counts = new Map();
      constructor(prefix) { this.prefix = prefix; }
      async limit({ key }) {
        this.calls.push(key);
        const count = (this.counts.get(key) ?? 0) + 1; this.counts.set(key, count);
        return { success: !key.startsWith(this.prefix) || count === 1 };
      }
    }
    {
      const f = fixture(), limiter = new Ratelimit("twofactor-recover:");
      f.env.LOGIN_RATE_LIMITER = limiter;
      await expectStatus(await recover(f, { email: " Missing@Example.TEST " }, { "cf-connecting-ip": "198.51.100.1" }), 401);
      await expectStatus(await recover(f, { email: "missing@example.test" }, { "cf-connecting-ip": "198.51.100.2" }), 429);
      equal(limiter.calls.join("|"), "twofactor-recover-ip:198.51.100.1|twofactor-recover:missing@example.test|twofactor-recover-ip:198.51.100.2|twofactor-recover:missing@example.test");
    }
    {
      const f = fixture(), limiter = new Ratelimit("twofactor-recover-ip:");
      f.env.LOGIN_RATE_LIMITER = limiter;
      await expectStatus(await recover(f, { email: "missing-one@example.test" }, { "cf-connecting-ip": "198.51.100.3" }), 401);
      await expectStatus(await recover(f, { email: "missing-two@example.test" }, { "cf-connecting-ip": "198.51.100.3" }), 429);
      equal(limiter.calls.length, 3, "denied IP must stop before the email bucket and password lookup");
    }
  });

  await check("password login recovery consumes second factors without issuing a new Remember token", async () => {
    const f = seed(), other = otherState();
    const response = await expectStatus(await login(f), 200);
    const token = await response.json();
    if (typeof token.access_token !== "string") throw new Error("recovery login did not issue the normal access token");
    equal(Object.hasOwn(token, "TwoFactorToken"), false, "recovery login recreated remembered 2FA");
    assertCleared(f, other);
  });

  await check("recovery login rejects empty and whitespace-only stored codes without changing authentication state", async () => {
    for (const [stored, submitted] of [["", ""], [" ", " "], ["\t", "\t"], [CODE, ""], [CODE, " "], [CODE, "\t"]]) {
      const f = seed();
      sql.exec("UPDATE users SET two_factor_recovery_code=? WHERE id=?", stored, f.owner);
      const before = state();
      await expectStatus(await login(f, { code: submitted }), 401);
      equal(state(), before, "invalid recovery code changed authentication state");
    }
  });

  await check("recovery login checks client compatibility before consuming a verified recovery code", async () => {
    for (const version of [null, "invalid-version", "2026.9.0"]) {
      const f = seed();
      sql.exec("UPDATE users SET security_version=2,private_key='7.private' WHERE id=?", f.owner);
      const before = state();
      await expectStatus(await login(f, { version }), 400);
      equal(state(), before, "an incompatible client consumed or upgraded authentication state");
    }
  });
}

/** Export authorization consumes scoped OTPs in the compiled Worker and SQLite. */
async function runProtectedActionChecks({ fixture, check, sql, accessToken, USER }) {
  const CODE = "123456", EMAIL = "owner@example.test";
  const post = async (f, path = "/api/accounts/verify-otp", body = { otp: CODE }, bearer) => f.fetch(path, {
    method: "POST", headers: bearerJsonHeaders(bearer ?? await accessToken()),
    body: JSON.stringify(body),
  });
  const row = () => sql.exec("SELECT * FROM verification_codes WHERE id='export-proof'").one();
  const seed = async (f, overrides = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const value = { owner: USER, user: USER, purpose: "protected-action", recipient: EMAIL, context: "",
      stamp: "owner-stamp", session: "session", expires: now + 600, ready: 1, attempts: 0, ...overrides };
    const secret = await fixtureAccessSecret(sql, f.env.KEY_ENCRYPTION_KEY);
    const hash = await emailCodeHash(secret, { owner: value.owner, purpose: value.purpose,
      recipient: value.recipient, context: value.context, code: CODE });
    sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,context,code_hash,security_stamp,session_token,issued_at,expires_at,ready,attempts) VALUES('export-proof',?,?,?,?,?,?,?,?,?,?,?,?)",
      value.owner, value.user, value.purpose, value.recipient, value.context, hash, value.stamp, value.session, now, value.expires, value.ready, value.attempts);
  };

  await check("protected-action OTP delivery failures return 503 and release the reservation", async () => {
    const f = fixture();
    const webhook = "https://mail.runtime.test/send";
    f.env.MAIL_WEBHOOK_URL = webhook;
    const headers = { Authorization: `Bearer ${await accessToken()}` };
    const request = () => f.fetch("/api/accounts/request-otp", { method: "POST", headers });
    const previousFetch = globalThis.fetch;
    let delivery = 503, calls = 0;
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      equal(request.url, webhook);
      equal(request.method, "POST");
      equal(sql.exec("SELECT ready FROM verification_codes WHERE purpose='protected-action'").one().ready, 0);
      calls++;
      if (delivery === null) throw new Error("fixture outbound provider rejection");
      return new Response("fixture provider detail", { status: delivery });
    };
    try {
      for (delivery of [503, null]) {
        const failure = await expectJsonOrEmpty(await request(), 503);
        equal(failure.code, 12);
        equal(failure.message, "Internal server error");
        equal(sql.exec("SELECT count(*) AS n FROM verification_codes").one().n, 0);
      }
      delivery = 200;
      await expectJsonOrEmpty(await request(), 200);
      equal(calls, 3);
      equal(sql.exec("SELECT ready FROM verification_codes WHERE purpose='protected-action'").one().ready, 1);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  await check("export OTP verification consumes its proof through both aliases and prevents later reuse", async () => {
    for (const path of ["/api/accounts/verify-otp", "/accounts/verify-otp"]) {
      const f = fixture(); await seed(f);
      await expectJsonOrEmpty(await post(f, path, { OTP: CODE }), 200);
      equal(row().consumed_at !== null, true, "successful export authorization left a reusable OTP");
      equal(row().attempts, 1);
      const consumed = JSON.stringify(row());
      await expectJsonOrEmpty(await post(f), 400);
      await expectJsonOrEmpty(await post(f, "/api/two-factor/get-authenticator"), 400);
      equal(JSON.stringify(row()), consumed, "replay changed a consumed proof");
    }
  });

  await check("concurrent export authorization accepts exactly one use of the same OTP", async () => {
    const f = fixture(); await seed(f);
    const responses = await Promise.all([post(f), post(f)]);
    equal(responses.map(response => response.status).sort().join(","), "200,400");
    for (const response of responses) await response.text();
    equal(row().attempts, 1); equal(row().consumed_at !== null, true);
  });

  await check("export OTPs retain owner, purpose, recipient, context, account, session and delivery bindings", async () => {
    for (const scope of [{ owner: "other-owner", user: "other-owner" }, { purpose: "email-login" },
      { recipient: "other@example.test" }, { context: "another-operation" }, { stamp: "old-stamp" },
      { session: "other-session" }, { ready: 0 }]) {
      const f = fixture(); await seed(f, scope); const before = JSON.stringify(row());
      await expectJsonOrEmpty(await post(f), 400); equal(JSON.stringify(row()), before, JSON.stringify(scope));
    }
    const f = fixture(); await seed(f);
    sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?, 'export-other-device','Browser',14,'other-session','old','old')", USER);
    const other = await accessToken({ device: "export-other-device", session_token: "other-session" });
    const before = JSON.stringify(row()); await expectJsonOrEmpty(await post(f, undefined, undefined, other), 400);
    equal(JSON.stringify(row()), before, "another active session changed the proof");
    await expectJsonOrEmpty(await f.fetch("/api/accounts/verify-otp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ otp: CODE }) }), 401);
    sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=? AND device_id='device'", USER);
    await expectJsonOrEmpty(await post(f), 401); equal(JSON.stringify(row()), before, "revoked session changed the proof");
  });

  await check("wrong export OTP attempts remain bounded and expiry never consumes a valid-looking code", async () => {
    let f = fixture(); await seed(f);
    await expectJsonOrEmpty(await post(f, undefined, { otp: "654321" }), 400);
    equal(row().attempts, 1); equal(row().consumed_at, null);
    await expectJsonOrEmpty(await post(f), 200); equal(row().attempts, 2); equal(row().consumed_at !== null, true);
    f = fixture(); await seed(f);
    for (let attempt = 0; attempt < 5; attempt++) await expectJsonOrEmpty(await post(f, undefined, { otp: "654321" }), 400);
    await expectJsonOrEmpty(await post(f), 400); equal(row().attempts, 5); equal(row().consumed_at, null);
    f = fixture(); await seed(f, { expires: Math.floor(Date.now() / 1000) - 1 });
    await expectJsonOrEmpty(await post(f), 400); equal(row().attempts, 0); equal(row().consumed_at, null);
  });

  await check("failed export proof consumption rolls back without returning authorization", async () => {
    const f = fixture(); await seed(f);
    sql.exec("CREATE TRIGGER export_consume_failure BEFORE UPDATE OF consumed_at ON verification_codes BEGIN SELECT RAISE(ABORT,'injected OTP consumption failure'); END");
    const before = JSON.stringify(row()); await expectJsonOrEmpty(await post(f), 500); equal(JSON.stringify(row()), before);
    sql.exec("DROP TRIGGER export_consume_failure");
    await expectJsonOrEmpty(await post(f), 200); equal(row().consumed_at !== null, true);
  });

  await check("other protected actions still consume independently issued OTPs before issuing management proofs", async () => {
    const f = fixture(); await seed(f);
    const result = await expectJsonOrEmpty(await post(f, "/api/two-factor/get-authenticator"), 200);
    equal(typeof result.userVerificationToken, "string"); equal(row().consumed_at !== null, true);
    await expectJsonOrEmpty(await post(f), 400);
  });
}
