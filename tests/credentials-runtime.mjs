import { Ratelimit, snapshotTables } from "./runtime-fixture.mjs";
import {
  bearerJsonHeaders,
  emailCodeHash,
  equal,
  expectJson,
  expectJsonOrEmpty,
  expectStatus,
  fixtureAccessSecret,
  oauthToken,
  ok,
  requestJson,
  totp,
  withFetchMock,
} from "./runtime-tools.mjs";

export const credentialsChecks = [runPasswordChecks, runTwoFactorChecks, runRecoveryChecks, runProtectedActionChecks];

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

  await check("password changes preserve higher stored costs and reject empty replacement hashes", async () => {
    const f = await salted(1200000), before = row();
    const headers = await owner();
    const replace = newMasterPasswordHash => requestJson(f, "/api/accounts/password", {
      masterPasswordHash: CLIENT_HASH, newMasterPasswordHash, key: "2.next-user-key",
    }, { headers });
    await expectStatus(await replace(""), 400);
    equal(JSON.stringify(row()), JSON.stringify(before), "empty replacement hash changed credentials");
    await expectStatus(await replace(NEXT_HASH), 200);
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

  await check("password upgrades reject concurrent credential, stamp and envelope changes", async () => {
    for (const [column, value] of [["master_password_hash", "concurrent-hash"],
      ["security_stamp", "concurrent-stamp"], ["key", "concurrent-wrapped-key"]]) {
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

  await check("production PBKDF2 ceiling permits registration, login and existing higher-cost verifiers", async () => {
    const higherCost = await salted(1200000), before = row();
    const subtle = crypto.subtle, nativeDerive = subtle.deriveBits;
    let rejected = 0;
    subtle.deriveBits = function (algorithm, ...args) {
      if (algorithm.name === "PBKDF2") {
        rejected++;
        return Promise.reject(new DOMException("PBKDF2 iteration counts above 100000 are not supported", "NotSupportedError"));
      }
      return nativeDerive.call(this, algorithm, ...args);
    };
    let current;
    try {
      await expectStatus(await login(higherCost), 200);
      await expectStatus(await login(higherCost, "wrong-password"), 401);
      equal(JSON.stringify(row()), JSON.stringify(before), "login rewrote a higher-cost verifier");

      const f = fixture({ empty: true });
      f.env.ALLOWED_EMAILS = EMAIL; f.env.OWNER_SETUP_TOKEN = "password-runtime-private-owner-setup-token";
      await expectStatus(await f.fetch("/identity/accounts/register/finish", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Raywarden-Setup-Token": f.env.OWNER_SETUP_TOKEN },
        body: JSON.stringify({ email: EMAIL, masterPasswordHash: CLIENT_HASH, key: "2.wrapped-user", kdf: 0, kdfIterations: 600000,
          keys: { publicKey: "public", encryptedPrivateKey: "2.private" } }),
      }), 200);
      current = sql.exec("SELECT master_password_hash,password_salt,password_iterations FROM users WHERE email=?", EMAIL).one();
      equal(current.password_iterations, 600000); equal(bytes(current.password_salt).length, 64);
      await expectStatus(await login(f), 200);
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
  const change = async (f, action, body) => requestJson(f, `/api/accounts/${action}`, body, { headers: await owner() });
  const envelope = () => sql.exec("SELECT key,user_key_id,private_key,public_key,signed_public_key,security_state,security_version,signature_key_pair FROM users WHERE id=?", USER).one();
  const identityState = () => snapshotTables(sql, ["users", "devices", "two_factors", "webauthn_credentials"]);
  const seedPrf = () => {
    for (const [id, snapshot] of [["current", envelope()], ["stale", { ...envelope(), key: "previous-generation" }]]) {
      sql.exec("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,sign_count,credential_use,prf_status,encrypted_public_key,encrypted_user_key,encrypted_private_key,account_snapshot,created_at,updated_at) VALUES(?,?,?,'PRF test',?,'public',0,'login',0,'prf-public','prf-user','prf-private',?,'old','old')",
        `password-prf-${id}`, USER, id === "current" ? 1 : 2, `password-wire-${id}`, JSON.stringify(snapshot));
    }
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('password-remember',?,5,1,'{}',0)", USER);
  };

  await check("current-only KDF requests commit one coherent credential set", async () => {
    const f = await salted(1200000);
    sql.exec("UPDATE users SET user_key_id=? WHERE id=?", KEY_ID, USER); seedPrf();
    const kdf = { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 }, body = currentRequest(kdf);
    body.unlockData.containedKeyId = KEY_ID;
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
      body => { delete body.authenticationData; },
      body => { body.unlockData.kdf.iterations++; },
      body => { body.authenticationData.salt = "other@example.test"; },
      body => { body.unlockData.containedKeyId = "ffffffffffffffffffffffffffffffff"; },
      body => { body.newMasterPasswordHash = "conflicting-flat-hash"; body.key = body.unlockData.masterKeyWrappedUserKey; },
      body => { body.authenticationData.masterPasswordAuthenticationHash = ""; },
    ];
    for (const action of ["kdf", "password"]) {
      for (const mutate of invalid) {
        const f = fixture(); sql.exec("UPDATE users SET master_password_hash=?,password_salt=NULL,user_key_id=? WHERE id=?", CLIENT_HASH, KEY_ID, USER); seedPrf();
        const body = currentRequest(); mutate(body);
        const before = identityState();
        await expectStatus(await change(f, action, body), 400);
        equal(identityState(), before, `${action} rejected request changed authentication state`);
      }
    }
  });

  await check("password changes reject KDF changes, public identity replacement and private-key version changes", async () => {
    for (const v2 of [false, true]) {
      for (const mutation of ["kdf", "public", "private", "empty"]) {
        const f = fixture();
        sql.exec("UPDATE users SET master_password_hash=?,password_salt=NULL,private_key=?,security_version=? WHERE id=?", CLIENT_HASH, v2 ? "7.old-private" : "2.private", v2 ? 2 : null, USER);
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

  const createSend = async (f, password = CLIENT_HASH) => {
    const response = await expectStatus(await f.fetch("/api/sends", { method: "POST", headers: await owner(),
      body: JSON.stringify({ type: 0, name: "encrypted-send", key: "2.wrapped-send", password,
        text: { text: "encrypted-content", hidden: false }, deletionDate: new Date(Date.now() + 86400000).toISOString() }) }), 200);
    return response.json();
  };
  const issueSend = (f, accessId, password = CLIENT_HASH) => oauthToken(f, {
    grant_type: "send_access", send_id: accessId, password_hash_b64: password,
  });

  await check("Send passwords keep their independent creation cost and reject invalid stored costs", async () => {
    const f = fixture(), send = await createSend(f);
    const current = sql.exec("SELECT password_hash,password_salt,password_iterations FROM sends WHERE id=?", send.id).one();
    equal(current.password_iterations, 100000); equal(bytes(current.password_salt).length, 16);
    await expectStatus(await issueSend(f, send.accessId), 200);
    await expectStatus(await issueSend(f, send.accessId, "wrong-password"), 400);
    sql.exec("UPDATE sends SET password_iterations=0 WHERE id=?", send.id);
    await expectStatus(await issueSend(f, send.accessId), 500);
  });
}

// Actual authenticator HTTP handlers and native SQLite transactions. The test
// client computes its TOTP independently with WebCrypto HMAC-SHA1.
async function runTwoFactorChecks({ fixture, check, accessToken, USER, sql }) {
  const request = async (f, path, body, bearer, method) =>
    requestJson(f, path, body, { method, headers: bearerJsonHeaders(bearer ?? await accessToken()) });
  const get = (f, bearer) => request(f, "/api/two-factor/get-authenticator", { masterPasswordHash: "hash" }, bearer).then(response => expectJson(response, 200));
  const activate = async (f, setup, bearer, method = "POST") => request(f, "/api/two-factor/authenticator", {
    key: setup.key, token: await totp(setup.key), userVerificationToken: setup.userVerificationToken,
  }, bearer, method);
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
    for (const [type, enabled, expected] of [[0, 1, true], [2, 1, true], [5, 1, false], [0, 0, false], [1000, 1, false]]) {
      const f = fixture();
      const data = type === 1 ? JSON.stringify({ email: "factor@example.test" }) : type === 0 ? "JBSWY3DPEHPK3PXP" : "{}";
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('status-factor',?,?,?,?,0)", USER, type, enabled, data);
      const headers = { Authorization: `Bearer ${await accessToken()}` };
      const profile = await expectJson(await f.fetch("/api/accounts/profile", { headers }), 200);
      const sync = await expectJson(await f.fetch("/api/sync?excludeDomains=true", { headers }), 200);
      equal(profile.twoFactorEnabled, expected, `profile factor ${type}/${enabled}`);
      equal(sync.profile.twoFactorEnabled, expected, `sync factor ${type}/${enabled}`);
    }
  });

  const emailFactor = address => sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('email-runtime-factor',?,1,1,?,0)", USER, JSON.stringify({ email: address }));
  const emailProof = async (f, bearer) => expectJson(await request(f, "/api/two-factor/get-email", { masterPasswordHash: "hash" }, bearer), 200);

  await check("email action proofs keep their own purpose and provider-state binding across both handlers", async () => {
    const f = fixture(); emailFactor("first-factor@example.test"); remember();
    const proof = await emailProof(f); const setup = await get(f);
    await expectJson(await request(f, "/api/two-factor/email", { userVerificationToken: setup.userVerificationToken }, undefined, "DELETE"), 401);
    await expectJson(await request(f, "/api/two-factor/get-authenticator", { userVerificationToken: proof.userVerificationToken }), 400);
    equal(count(1), 1); equal(count(5), 1);
    sql.exec("UPDATE two_factors SET data=? WHERE user_id=? AND provider_type=1", JSON.stringify({ email: "new-factor@example.test" }), USER);
    await expectJson(await request(f, "/api/two-factor/disable", { type: 1, userVerificationToken: proof.userVerificationToken }), 401);
    equal(count(1), 1); equal(count(5), 1);
    const current = await emailProof(f);
    await expectJson(await request(f, "/api/two-factor/disable", { type: 1, userVerificationToken: current.userVerificationToken }), 200);
    equal(count(1), 0); equal(count(5), 0);
  });

  await check("a valid new session cannot reuse an email action proof but can mint its own", async () => {
    const f = fixture(); emailFactor("factor@example.test"); remember();
    const proof = await emailProof(f);
    sql.exec("UPDATE devices SET session_token='email-new-session' WHERE user_id=? AND device_id='device'", USER);
    const bearer = await accessToken({ session_token: "email-new-session" });
    await expectJson(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 200);
    await expectJson(await request(f, "/api/two-factor/email", { userVerificationToken: proof.userVerificationToken }, bearer, "DELETE"), 401);
    equal(count(1), 1); equal(count(5), 1);
    const current = await emailProof(f, bearer);
    await expectJson(await request(f, "/api/two-factor/email", { userVerificationToken: current.userVerificationToken }, bearer, "DELETE"), 200);
    equal(count(1), 0); equal(count(5), 0);
  });

  await check("TOTP real setup proof activates and disables; get actions reject proof renewal", async () => {
    const f = fixture(); const setup = await get(f);
    shape(setup, false); ok(setup.userVerificationToken, "missing setup proof");
    for (const path of ["/api/two-factor/get-authenticator", "/api/two-factor/get-recover"]) {
      await expectJson(await request(f, path, { userVerificationToken: setup.userVerificationToken }), 400);
    }
    const enabled = await expectJson(await activate(f, setup), 200);
    shape(enabled, true); equal(count(0), 1);
    const first = sql.exec("SELECT * FROM two_factors WHERE user_id=? AND provider_type=0", USER).one();
    ok(first.last_used_step > 0, "setup did not consume the accepted TOTP step");
    await expectJson(await activate(f, setup), 400);
    const current = await get(f); shape(current, true); equal(current.key, setup.key);
    const disabled = await expectJson(await disable(f, current), 200);
    equal(disabled.enabled, false); equal(disabled.type, 0); equal(count(0), 0);
  });

  await check("invalid Base32 in a submitted TOTP key is a client error and stored corruption is a server error", async () => {
    const f = fixture();
    for (const key of ["0" + "A".repeat(31), "ſ" + "A".repeat(31)]) {
      const error = await expectJson(await request(f, "/api/two-factor/authenticator", {
        key, token: "123456", masterPasswordHash: "hash",
      }), 400);
      equal(error.message, "Invalid request: Invalid Base32 key");
    }
    equal(count(0), 0);
    sql.exec("INSERT INTO two_factors VALUES('invalid-totp',?,0,1,?,0)", USER, "0" + "A".repeat(31));
    const failure = await expectJson(await oauthToken(f, {
      grant_type: "password", username: "owner@example.test", password: "hash",
      deviceIdentifier: "invalid-totp-device", deviceName: "Runtime test", deviceType: "14",
      twoFactorProvider: "0", twoFactorToken: "123456",
    }, { "Bitwarden-Client-Version": "2026.10.1", "device-type": "14" }), 500);
    equal(failure.code, 3); equal(failure.message, "Invalid Base32 encoding");
    equal(sql.exec("SELECT last_used_step FROM two_factors WHERE id='invalid-totp'").one().last_used_step, 0);
  });

  await check("TOTP PUT aliases clear pending protection and reject replay across methods", async () => {
    const f = fixture(); const setup = await get(f);
    await expectJson(await activate(f, setup, undefined, "PUT"), 200);
    await expectJson(await activate(f, setup), 400);
    const current = await get(f);
    const proof = { type: 0, userVerificationToken: current.userVerificationToken };
    sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,code_hash,issued_at,expires_at) VALUES('protected',?,?,'protected-action','owner@example.test','hash',100,700)", USER, USER);
    await expectJson(await request(f, "/api/two-factor/disable", proof, undefined, "PUT"), 200);
    equal(count(0), 0);
    equal(sql.exec("SELECT COUNT(*) AS count FROM verification_codes WHERE id='protected'").one().count, 0);
    await expectJson(await request(f, "/api/two-factor/disable", proof), 400);
  });

  await check("modern TOTP recovery writes roll back enrollment and preserve recovery for legacy factors", async () => {
    const f = fixture(), setup = await get(f); remember();
    const recovery = () => sql.exec("SELECT two_factor_recovery_code AS code FROM users WHERE id=?", USER).one().code;
    sql.exec("CREATE TRIGGER reject_recovery BEFORE UPDATE OF two_factor_recovery_code ON users BEGIN SELECT RAISE(ABORT,'injected recovery failure'); END");
    await expectJson(await activate(f, setup), 500);
    equal(count(0), 0); equal(count(5), 1); equal(recovery(), null);
    sql.exec("DROP TRIGGER reject_recovery");
    await expectJson(await activate(f, setup), 200);
    const code = recovery(); ok(code, "successful activation did not initialize recovery");
    sql.exec("INSERT INTO two_factors VALUES('legacy-factor',?,2,1,'legacy',0)", USER);
    const current = await get(f);
    await expectJson(await disable(f, current), 200);
    equal(count(0), 0); equal(count(2), 1); equal(recovery(), code);
    await expectJson(await request(f, "/api/two-factor/disable", { type: 2, masterPasswordHash: "hash" }), 200);
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
      await withFetchMock(async input => {
        const outbound = input instanceof Request ? input : new Request(input);
        equal(outbound.url, f.env.MAIL_WEBHOOK_URL);
        const message = await outbound.json();
        codes[message.purpose] = message.text.split("\n\n")[1];
        return Response.json({});
      }, async () => {
        await expectJson(await request(f, "/api/accounts/request-otp", {}), 200);
        if (isEmail) {
          await expectJson(await request(f, "/api/two-factor/send-email", {
            email: "factor@example.test", masterPasswordHash: "hash",
          }), 200);
        }
      });

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

      await expectJson(await request(f, path, { key, otp: "wrong", token: await token() }), 400);
      await expectJson(await request(f, path, { key, otp, token: "wrong" }), isEmail ? 400 : 401);
      expectPending();

      sql.exec("CREATE TRIGGER reject_otp_enrollment BEFORE UPDATE OF two_factor_recovery_code ON users BEGIN SELECT RAISE(ABORT,'injected OTP enrollment failure'); END");
      await expectJson(await activate(), 500);
      expectPending();
      sql.exec("DROP TRIGGER reject_otp_enrollment");

      const raced = f.db.beforeNextBatch(
        statements => statements.some(statement => /^INSERT INTO\s+two_factors/.test(statement.sql.trim())),
        () => sql.exec("UPDATE devices SET session_token='replaced' WHERE user_id=? AND device_id='device'", USER),
      );
      await expectJson(await activate(), 409);
      equal(raced(), true, "activation did not reach its write transaction");
      expectPending();
      sql.exec("UPDATE devices SET session_token='session' WHERE user_id=? AND device_id='device'", USER);

      const enabled = await expectJson(await activate(), 200);
      equal(enabled.enabled, true);
      equal(count(type), 1);
      equal(count(5), 0);
      equal(proof("protected-action").attempts, 2);
      ok(proof("protected-action").consumed_at, "authorization OTP was left reusable");
      if (isEmail) {
        equal(sql.exec("SELECT COUNT(*) AS n FROM verification_codes WHERE user_id=? AND purpose='email-setup'", USER).one().n, 0);
      }
      await expectJson(await activate(), 400);
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
    await expectJson(positive, 200);
    await expectJson(await activate(f, setup, bearer), 401);
    equal(count(0), 0); equal(count(5), 1, "rejected proof changed Remember state");
  });

  await check("a stale TOTP delete snapshot rolls back before clearing Remember tokens", async () => {
    const f = fixture(); const setup = await get(f);
    await expectJson(await activate(f, setup), 200);
    const current = await get(f); remember();
    const changed = f.db.beforeNextBatch(
      statements => statements.some(statement => /^DELETE FROM two_factors WHERE id=/.test(statement.sql.trim())),
      () => sql.exec("UPDATE two_factors SET last_used_step=last_used_step+1 WHERE user_id=? AND provider_type=0", USER),
    );
    await expectJson(await disable(f, current), 409);
    equal(changed(), true, "delete did not reach the actual snapshot transaction");
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
  const state = () => snapshotTables(sql, ["users", "devices", "two_factors", "verification_codes", "webauthn_credentials"]);
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

  await check("simultaneous verified recovery attempts commit one winner and enforce IP/email rate limits", async () => {
    for (const kind of ["recover", "login"]) {
      const f = seed(), other = otherState();
      const responses = await f.db.beforeBothBatches(isRecovery, () => call(kind, f));
      equal(responses.map(response => response.status).sort().join(","), "200,409");
      for (const response of responses) await response.text();
      assertCleared(f, other);
    }

    const f = fixture();
    const limiter = new Ratelimit((key, keys) => !key.startsWith("twofactor-recover:") || keys.indexOf(key) === keys.length - 1);
    f.env.LOGIN_RATE_LIMITER = limiter;
    await expectStatus(await recover(f, { email: " Missing@Example.TEST " }, { "cf-connecting-ip": "198.51.100.1" }), 401);
    await expectStatus(await recover(f, { email: "missing@example.test" }, { "cf-connecting-ip": "198.51.100.2" }), 429);
  });

  await check("password login recovery consumes second factors without Remember token and checks client compatibility", async () => {
    const f = seed(), other = otherState();
    const token = await expectJson(await login(f), 200);
    equal(Object.hasOwn(token, "TwoFactorToken"), false);
    assertCleared(f, other);

    const fV2 = seed();
    sql.exec("UPDATE users SET security_version=2,private_key='7.private' WHERE id=?", fV2.owner);
    const before = state();
    await expectStatus(await login(fV2, { version: null }), 400);
    equal(state(), before);
  });
}

/** Export authorization consumes scoped OTPs in the compiled Worker and SQLite. */
async function runProtectedActionChecks({ fixture, check, sql, accessToken, USER }) {
  const CODE = "123456", EMAIL = "owner@example.test";
  const post = async (f, path = "/api/accounts/verify-otp", body = { otp: CODE }, bearer) =>
    requestJson(f, path, body, { headers: bearerJsonHeaders(bearer ?? await accessToken()) });
  const row = () => sql.exec("SELECT * FROM verification_codes WHERE id='export-proof'").one();
  const seed = async (f, overrides = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const value = { owner: USER, user: USER, purpose: "protected-action", recipient: EMAIL,
      stamp: "owner-stamp", session: "session", expires: now + 600, ready: 1, attempts: 0, ...overrides };
    const secret = await fixtureAccessSecret(sql, f.env.KEY_ENCRYPTION_KEY);
    const hash = await emailCodeHash(secret, { owner: value.owner, purpose: value.purpose,
      recipient: value.recipient, code: CODE });
    sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,context,code_hash,security_stamp,session_token,issued_at,expires_at,ready,attempts) VALUES('export-proof',?,?,?,?, '',?,?,?,?,?,?,?)",
      value.owner, value.user, value.purpose, value.recipient, hash, value.stamp, value.session, now, value.expires, value.ready, value.attempts);
  };

  await check("protected-action OTP delivery failures return 503 and release the reservation", async () => {
    const f = fixture();
    const webhook = "https://mail.runtime.test/send";
    f.env.MAIL_WEBHOOK_URL = webhook;
    const headers = { Authorization: `Bearer ${await accessToken()}` };
    const request = () => f.fetch("/api/accounts/request-otp", { method: "POST", headers });
    let delivery = 503;
    await withFetchMock(async () => {
      if (delivery === null) throw new Error("fixture outbound provider rejection");
      return new Response("fixture provider detail", { status: delivery });
    }, async () => {
      for (delivery of [503, null]) {
        const failure = await expectJsonOrEmpty(await request(), 503);
        equal(failure.code, 12);
        equal(sql.exec("SELECT count(*) AS n FROM verification_codes").one().n, 0);
      }
      delivery = 200;
      await expectJsonOrEmpty(await request(), 200);
      equal(sql.exec("SELECT ready FROM verification_codes WHERE purpose='protected-action'").one().ready, 1);
    });
  });

  await check("export OTP verification enforces single-use, session/recipient/purpose bindings, and attempt limits", async () => {
    for (const path of ["/api/accounts/verify-otp", "/accounts/verify-otp"]) {
      const f = fixture(); await seed(f);
      await expectJsonOrEmpty(await post(f, path, { OTP: CODE }), 200);
      equal(row().consumed_at !== null, true);
      await expectJsonOrEmpty(await post(f), 400);
    }
    const fRace = fixture(); await seed(fRace);
    const responses = await Promise.all([post(fRace), post(fRace)]);
    equal(responses.map(r => r.status).sort().join(","), "200,400");

    for (const scope of [{ owner: "other-owner", user: "other-owner" }, { purpose: "email-login" },
      { recipient: "other@example.test" }, { stamp: "old-stamp" }, { session: "other-session" }, { ready: 0 }]) {
      const f = fixture(); await seed(f, scope);
      await expectJsonOrEmpty(await post(f), 400);
    }

    const fLimit = fixture(); await seed(fLimit);
    for (let attempt = 0; attempt < 5; attempt++) await expectJsonOrEmpty(await post(fLimit, undefined, { otp: "654321" }), 400);
    await expectJsonOrEmpty(await post(fLimit), 400);

    const fOther = fixture(); await seed(fOther);
    const result = await expectJsonOrEmpty(await post(fOther, "/api/two-factor/get-authenticator"), 200);
    equal(typeof result.userVerificationToken, "string");
  });
}
