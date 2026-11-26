import {
  bearerJsonHeaders,
  emailCodeHash,
  equal,
  expectJson,
  expectStatus,
  fixtureAccessSecret,
  fromBase64Url,
  jwtClaims as claims,
  oauthToken,
  openFixtureJwtKeys,
  ok,
  requestJson,
  toBase64Url,
  totp,
  wrapFixtureJwtKeys,
} from "./runtime-tools.mjs";
import { snapshotTables, token as signToken } from "./runtime-fixture.mjs";

export const authChecks = [runPreloginChecks, runJwtChecks, runAuthSessionChecks];

/** Stable unknown-email KDF responses through compiled Rust and real SQLite. */
async function runPreloginChecks({ fixture, check, sql }) {
  const aliases = [
    "/api/accounts/prelogin", "/api/accounts/prelogin/password",
    "/identity/accounts/prelogin", "/identity/accounts/prelogin/password",
  ];
  const request = (f, email, path = aliases[0]) => requestJson(f, path, { email });
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
      ["malformed", 600000, null, null],
      [2, 600000, null, null],
      [0, 0, null, null],
      [1, 0, 64, 4],
      [1, 4, null, 4],
    ];
    for (const values of samples) {
      const f = fixture();
      const email = "owner@example.test";
      sql.exec("UPDATE users SET kdf_type=?,kdf_iterations=?,kdf_memory=?,kdf_parallelism=? WHERE email=?", ...values, email);
      const before = users();
      const body = await expectJson(await request(f, email), 500);
      equal(
        [
          "Internal server error: Stored database record does not match expected schema",
          "Internal server error: Stored PBKDF2 iterations must be positive",
          "Internal server error: Invalid stored KDF settings",
        ].includes(body.message),
        true,
        body.message,
      );
      equal(body.code, 13);
      equal(users(), before, "stored KDF settings after failed prelogin");
    }
  });

  await check("unknown prelogin stays stable across normalized emails and independent requests", async () => {
    const f = fixture({ empty: true });
    const before = users();
    const first = await prelogin(f, "unknown@example.test");
    // Independent HMAC vector: digest 76df0f736cbc9c66 selects bucket 1
    // with the fixture's persisted key. Truncating to WASM32 first selects 6.
    settings(first, [1, 3, 64, 4], "unknown@example.test");
    const response = await prelogin(f, " Unknown@Example.TEST ");
    equal(JSON.stringify(response), JSON.stringify(first), "stable prelogin response");
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
    await expectStatus(await request(f, "unknown@example.test"), 500);
  });
}

/** JWT persistence and API-key wrapping against compiled Rust and real SQLite. */
async function runJwtChecks({ fixture, check, accessToken, USER, CIPHER, FILE, sql }) {
  const base64 = toBase64Url;
  const encoder = new TextEncoder();
  const rootSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  const row = () => sql.exec("SELECT access_secret,refresh_secret FROM jwt_keys WHERE id='global'").toArray()[0];
  const empty = () => sql.exec("DELETE FROM users; DELETE FROM jwt_keys;");
  const writeRow = keys => sql.exec("UPDATE jwt_keys SET access_secret=?,refresh_secret=? WHERE id='global'", keys.access_secret, keys.refresh_secret);
  const openRow = (keys = row()) => openFixtureJwtKeys(keys, rootSecret);
  async function aesKey(secret) {
    const hmac = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const raw = await crypto.subtle.sign("HMAC", hmac, encoder.encode("raywarden/api-key-encryption/v2"));
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  const apiKey = async (f, rotate = false) => requestJson(f, `/api/accounts/${rotate ? "rotate-api-key" : "api-key"}`,
    { masterPasswordHash: "hash" }, { headers: bearerJsonHeaders(await accessToken()) });

  await check("invalid configured JWT lifetimes fail before serving authenticated APIs", async () => {
    for (const duration of ["0", "-1", "not-seconds", "9223372036854775807"]) {
      const f = fixture(), before = JSON.stringify(row()); f.env.JWT_DURATION_SECONDS = duration;
      await expectStatus(await f.fetch("/api/alive"), 500);
      equal(JSON.stringify(row()), before);
    }
    const f = fixture(); f.env.JWT_DURATION_SECONDS = "1800";
    await expectStatus(await f.fetch("/api/alive"), 200);
  });

  await check("concurrent empty-database initialization persists one random winner and populated DB rejects missing keys", async () => {
    const f = fixture(); empty();
    for (const response of await Promise.all([f.fetch("/api/alive"), f.fetch("/api/alive")])) await expectStatus(response, 200);
    const stored = row(), keys = await openRow(stored);
    equal(fromBase64Url(keys.access_secret).length, 64); equal(fromBase64Url(keys.refresh_secret).length, 64);
    equal(sql.exec("SELECT count(*) AS n FROM jwt_keys").one().n, 1);

    const populated = fixture(); sql.exec("DELETE FROM jwt_keys;");
    const failure = await expectJson(await populated.fetch("/api/alive"), 500);
    equal(failure.code, 13);
    equal(row(), undefined);
  });

  await check("JWT envelopes require a valid KEY_ENCRYPTION_KEY and reject wrong keys or tampered ciphertext", async () => {
    for (const key of [undefined, {}, " ", "short", base64(new Uint8Array(32).fill(9))]) {
      const f = fixture(), before = JSON.stringify(row());
      f.env.KEY_ENCRYPTION_KEY = key;
      await expectStatus(await f.fetch("/api/alive"), 500);
      equal(JSON.stringify(row()), before);
    }
    for (const mutate of [
      keys => ({ ...keys, access_secret: "plaintext" }),
      keys => ({ access_secret: keys.refresh_secret, refresh_secret: keys.access_secret }),
      keys => ({ access_secret: keys.access_secret.replace("v1.", "v2."), refresh_secret: keys.refresh_secret.replace("v1.", "v2.") }),
    ]) {
      const f = fixture(), invalid = mutate(row()); writeRow(invalid);
      await expectStatus(await f.fetch("/api/alive"), 500);
    }
  });

  await check("scoped attachment tokens retain 64-bit dates and cannot become user access tokens", async () => {
    const f = fixture(), secret = (await openRow()).access_secret;
    const signed = await signToken({ sub: USER, cipher_id: CIPHER, attachment_id: FILE, scope: "attachment.download", exp: 4294967595, iat: undefined, nbf: undefined }, secret);
    const download = `/api/ciphers/${CIPHER}/attachment/${FILE}/download?token=`;
    const response = await expectStatus(await f.fetch(download + signed), 200);
    equal((await response.arrayBuffer()).byteLength, 6);
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${signed}` } }), 401);
    await expectStatus(await f.fetch(download + await accessToken()), 401);
  });

  await check("API-key ciphertext uses v2 domain separation and survives later requests", async () => {
    const f = fixture(), secret = (await openRow()).access_secret;
    const first = await expectJson(await apiKey(f), 200);
    const ciphertext = sql.exec("SELECT encrypted_key FROM user_api_keys WHERE user_id=?", USER).one().encrypted_key;
    if (!ciphertext.startsWith("v2.")) throw new Error("new API key did not use v2 ciphertext");
    const packed = fromBase64Url(ciphertext.slice(3));
    const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.subarray(0, 12), additionalData: encoder.encode(USER) }, await aesKey(secret), packed.subarray(12));
    equal(new TextDecoder().decode(opened), first.apiKey);
    const second = await expectJson(await apiKey(f), 200);
    equal(second.apiKey, first.apiKey);
    const rotated = await expectJson(await apiKey(f, true), 200);
    if (rotated.apiKey === first.apiKey) throw new Error("explicit API-key rotation preserved the old credential");
  });
}

/** OAuth aliases, safe cookie fallback and remembered-factor CAS contracts. */
async function runAuthSessionChecks({ fixture, check, sql, accessToken, USER }) {
  const DEVICE = "identity-parity-device", EMAIL = "owner@example.test", REMEMBER = "remember-proof-token";
  const rememberDigest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(REMEMBER))), b => b.toString(16).padStart(2, "0")).join("");
  const token = (f, fields, headers = {}) => oauthToken(f, fields, {
    "device-type": "14", "Bitwarden-Client-Version": "2026.10.1", ...headers,
  });
  const login = (f, extra = {}, headers = {}) => token(f, { grant_type: "password", username: EMAIL, password: "hash",
    deviceIdentifier: DEVICE, deviceName: "Identity parity", deviceType: "14", ...extra }, headers);
  const state = () => snapshotTables(sql, ["users", "devices", "two_factors"]);
  const refreshCookie = value => `bw_refresh_token=${value}`;
  const refresh = (f, value) => token(f, { grant_type: "refresh_token", refresh_token: value });
  const remembered = (days = 30, age = 0) => {
    const f = fixture(); f.env.TWO_FACTOR_REMEMBER_DAYS = String(days);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('identity-totp',?,0,1,'JBSWY3DPEHPK3PXP',0)", USER);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('identity-remember',?,5,1,?,0)", USER,
      JSON.stringify({ tokens: [{ device_id: DEVICE, token: `sha256:${rememberDigest}`, created_at: Math.floor(Date.now() / 1000) - age * 86400 }] }));
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
    f.db.failQuery(query => query.startsWith("SELECT d.session_token, u.security_stamp"), "fixture session query unavailable");
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
      const error = await expectJson(await token(f, fields), 400);
      equal(error.error, "invalid_request");
      equal(error.error_description, `Duplicate token field: ${field}`);
      equal(error.message, `Invalid request: Duplicate token field: ${field}`);
      equal(state(), before);
    }
    for (const [fields, oauthError, description, code] of [
      [{}, "invalid_request", "Missing grant_type", 5],
      [{ grant_type: "unsupported" }, "unsupported_grant_type", "Unsupported grant_type", 9002],
      [{ grant_type: "password", username: EMAIL, password: "wrong", deviceType: "invalid" }, "invalid_request", "Invalid token form", 5],
    ]) {
      const error = await expectJson(await token(f, fields), 400);
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
    ]) {
      const error = await expectJson(await token(f, fields), 400);
      equal(error.error, "invalid_request");
      equal(error.error_description, description);
      equal(error.code, code);
      equal(state(), before);
    }

    const enabled = remembered();
    const error = await expectJson(await login(enabled, { twoFactorProvider: "99", twoFactorToken: "123456" }), 400);
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

  async function assertNewSessionSurvives(f, matches, attempt) {
    const changed = f.db.beforeNextBatch(matches, () => {
      sql.exec("UPDATE users SET security_stamp='new-generation' WHERE id=?", USER);
      sql.exec("UPDATE devices SET session_token='new-nonce' WHERE user_id=? AND device_id='device'", USER);
    });
    await expectStatus(await attempt(), 409);
    ok(changed(), "fixture missed the device session write");
    equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token, "new-nonce");
    const fresh = await accessToken({ sstamp: "new-generation", session_token: "new-nonce" });
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${fresh}` } }), 200);
  }

  const apiKeyRequest = (f, bearer) => requestJson(f, "/api/accounts/api-key",
    { masterPasswordHash: "hash" }, { headers: bearerJsonHeaders(bearer) });
  const isDeviceWrite = statements => statements.some(statement => statement.sql.startsWith("INSERT INTO devices (user_id, device_id"));
  await check("password login cannot replace a newer-generation nonce after validation", async () => {
    const f = fixture();
    await assertNewSessionSurvives(f, isDeviceWrite, () => login(f, { deviceIdentifier: "device" }));
  });

  await check("password login checks the enabled factor snapshot at the session write", async () => {
    for (const change of ["enrolled", "removed", "reconfigured"]) {
      const f = change === "enrolled" ? fixture() : remembered();
      const fields = change === "enrolled" ? {} : { twoFactorProvider: "5", twoFactorToken: REMEMBER };
      sql.exec("UPDATE devices SET device_id=? WHERE user_id=? AND device_id='device'", DEVICE, USER);
      const reached = f.db.beforeNextBatch(isDeviceWrite, () => {
        if (change === "enrolled") {
          sql.exec("INSERT INTO two_factors VALUES('new-totp',?,0,1,'JBSWY3DPEHPK3PXP',0)", USER);
        } else if (change === "removed") {
          sql.exec("DELETE FROM two_factors WHERE id='identity-totp'");
        } else {
          sql.exec("UPDATE two_factors SET data='replacement' WHERE id='identity-totp'");
        }
      });
      const response = await expectStatus(await login(f, fields), 409);
      equal((await response.json()).message, "Conflict: Second-factor state changed during authentication. Retry login.", change);
      ok(reached(), change);
      equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id=?", USER, DEVICE).one().session_token, "session", change);
      const proof = await accessToken({ device: DEVICE });
      await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${proof}` } }), 200);
    }
  });

  await check("JWT name fallback preserves login and the full legacy profile name", async () => {
    for (const [name, claim] of [["Legacy profile", "Legacy profile"], ["a".repeat(9000), "User"]]) {
      const f = fixture();
      sql.exec("UPDATE users SET name=? WHERE id=?", name, USER);
      const tokens = await expectJson(await login(f), 200);
      equal(claims(tokens.access_token).name, claim);
      const profile = await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${tokens.access_token}` } }), 200);
      equal((await profile.json()).name, name);
    }
  });

  await check("password and API-key signing failures preserve the prior device session", async () => {
    const f = fixture(), previous = await accessToken();
    const { apiKey } = await expectJson(await apiKeyRequest(f, previous), 200);
    const email = `${"a".repeat(9000)}@example.test`;
    sql.exec("UPDATE users SET email=? WHERE id=?", email, USER);
    for (const attempt of [
      () => login(f, { username: email, deviceIdentifier: "device" }),
      () => token(f, { grant_type: "client_credentials", client_id: `user.${USER}`, client_secret: apiKey,
        scope: "api offline_access", deviceIdentifier: "device" }),
    ]) {
      const error = await expectJson(await attempt(), 500);
      equal(error.code, 13);
      equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token, "session");
      equal(sql.exec("SELECT COUNT(*) AS count FROM user_api_key_sessions WHERE user_id=?", USER).one().count, 0);
      await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${previous}` } }), 200);
    }
  });

  await check("API-key login cannot replace a newer-generation nonce after validation", async () => {
    const f = fixture();
    const { apiKey } = await expectJson(await apiKeyRequest(f, await accessToken()), 200);
    await assertNewSessionSurvives(f,
      statements => statements.some(statement => statement.sql.includes("user_api_key_sessions(user_id,device_id,session_token)")),
      () => token(f, { grant_type: "client_credentials", client_id: `user.${USER}`, client_secret: apiKey,
        scope: "api offline_access", deviceIdentifier: "device" }),
    );
    equal(sql.exec("SELECT COUNT(*) AS count FROM user_api_key_sessions WHERE user_id=?", USER).one().count, 0);
  });

  await check("OAuth recovery-code rejection identifies the credential without mutating factors", async () => {
    const f = remembered();
    sql.exec("UPDATE users SET two_factor_recovery_code='recovery-code' WHERE id=?", USER);
    const before = state();
    for (const proof of [undefined, "wrong-recovery-code"]) {
      const fields = { twoFactorProvider: "8", ...(proof === undefined ? {} : { twoFactorToken: proof }) };
      const error = await expectJson(await login(f, fields), 401);
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
    equal((await expectJson(await login(f, fields, missing), 400)).error, "version_header_missing");
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
    const f = fixture(), tokens = await expectJson(await login(f), 200), before = state();
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

  await check("refresh rejects revoked sessions and rotates remembered-device tokens with sha256 hashes", async () => {
    const f = fixture(), tokens = await expectJson(await login(f), 200);
    sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=? AND device_id=?", USER, DEVICE);
    equal((await expectJson(await refresh(f, tokens.refresh_token), 400)).error, "invalid_grant");

    for (const [days, age, status, seconds] of [[1, 2, 400, 86400], [3, 2, 200, 259200], [1000, 91, 400, 7776000]]) {
      const rem = remembered(days, age), before = state();
      const response = await expectStatus(await login(rem, { two_factor_provider: "5", two_factor_token: REMEMBER, two_factor_remember: "true" }), status);
      if (status !== 200) {
        equal((await response.json()).error_description, "Two factor required.");
        equal(state(), before);
        continue;
      }
      const body = await response.json();
      const record = sql.exec("SELECT data FROM two_factors WHERE id='identity-remember'").one().data;
      equal(record.includes(body.TwoFactorToken), false);
      equal(record.includes("sha256:"), true);
      equal(response.headers.get("set-cookie").includes(`Max-Age=${seconds}`), true);
      await expectStatus(await login(rem, { twoFactorProvider: "5", twoFactorToken: body.TwoFactorToken }), 200);
    }

    const cookieFixture = remembered();
    await expectStatus(await login(cookieFixture, { two_factor_token: " \t " }, { Cookie: `twoFactorRemember=${REMEMBER}`, Origin: "https://vault.test", "Sec-Fetch-Site": "same-origin" }), 200);
    await expectStatus(await login(remembered(), {}, { Cookie: `twoFactorRemember=${REMEMBER}`, Origin: "https://attacker.test" }), 401);
  });

  const api = async (f, path, body, method) => requestJson(f, path, body, { method, headers: bearerJsonHeaders(await accessToken()) });
  await check("approval requires the live approving device, and login consumes approval only with its session", async () => {
    const f = fixture();
    const send = (path, method, body, headers) => requestJson(f, path, body, { method, headers: { "device-type": "0", ...headers } });
    sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?,'approver','Approver',0,'approver-nonce','now','now')", USER);
    const code = "fixture-approval-code";
    const request = await expectJson(await send("/api/auth-requests", "POST", {
      email: EMAIL, deviceIdentifier: "device", accessCode: code, publicKey: "fixture-public-key",
    }), 200);
    const path = `/api/auth-requests/${request.id}`;
    const proof = { deviceIdentifier: "approver", key: "fixture-wrapped-key", requestApproved: true };
    const approver = nonce => accessToken({ device: "approver", session_token: nonce });
    await expectStatus(await send(path, "PUT", proof, { Authorization: `Bearer ${await approver("stale")}` }), 401);
    await expectStatus(await send(path, "PUT", proof, { Authorization: `Bearer ${await approver("approver-nonce")}` }), 200);
    const fields = { authRequest: request.id, access_code: code, deviceIdentifier: "device", deviceType: "0" };
    await expectStatus(await login(f, fields), 200);
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
    const options = await expectJson(await api(f, "/api/webauthn/attestation-options", { masterPasswordHash: "hash" }), 200);
    const rp = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(options.options.rp.id)));
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, fromBase64Url(jwk.x)], [-3, fromBase64Url(jwk.y)]]));
    const auth = concat(rp, Uint8Array.of(0x45, 0, 0, 0, 0), new Uint8Array(16), Uint8Array.of(0, id.length), id, cose);
    const attestation = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", auth]]));
    const client = new TextEncoder().encode(JSON.stringify({ type: "webauthn.create", challenge: options.token, origin: "https://vault.test", crossOrigin: false }));
    const response = await expectStatus(await api(f, "/api/webauthn", { token: options.token, KeyName: "Runtime passkey", ...prf,
      deviceResponse: { response: { attestationObject: toBase64Url(attestation), clientDataJSON: toBase64Url(client) } } }), 200);
    const list = await response.json();
    return { saved: list.data.at(-1), list, pair, id };
  };

  await check("verified passkey saves report PRF states and support passkey login, 2FA, PRF enable, and deletion", async () => {
    for (const [prf, status] of [
      [{ supportsPrf: false }, 2], [{ supportsPrf: true }, 1],
      [{ supportsPrf: true, encryptedUserKey: "2.user", encryptedPrivateKey: "2.private", encryptedPublicKey: "2.public" }, 0],
    ]) {
      const f = fixture(), { saved, list } = await makePasskey(f, prf);
      equal(list.object, "list"); equal(saved.name, "Runtime passkey"); equal(saved.prfStatus, status);
      equal(sql.exec("SELECT prf_status FROM webauthn_credentials WHERE user_id=?", USER).one().prf_status, status);
    }
  });

  const signedAssertion = async (passkey, rpId, challenge) => {
    const client = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge, origin: "https://vault.test", crossOrigin: false }, null, 2));
    const rp = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)));
    const auth = concat(rp, Uint8Array.of(0x05, 0, 0, 0, 1));
    const signed = concat(auth, new Uint8Array(await crypto.subtle.digest("SHA-256", client)));
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passkey.pair.privateKey, signed));
    const integer = bytes => { let first = 0; while (first < bytes.length - 1 && bytes[first] === 0) first++; const value = bytes.slice(first); return concat(Uint8Array.of(2, value.length + (value[0] >= 128 ? 1 : 0)), value[0] >= 128 ? Uint8Array.of(0) : new Uint8Array(), value); };
    const rs = concat(integer(signature.slice(0, 32)), integer(signature.slice(32)));
    return { id: toBase64Url(passkey.id), rawId: toBase64Url(passkey.id), type: "public-key", response: {
      clientDataJSON: toBase64Url(client), authenticatorData: toBase64Url(auth), signature: toBase64Url(concat(Uint8Array.of(0x30, rs.length), rs)) } };
  };

  const prfAssertion = async (f, passkey) => {
    const options = await expectJson(await api(f, "/api/webauthn/assertion-options", { masterPasswordHash: "hash" }), 200);
    return { token: options.token, encryptedUserKey: "2.new-user", encryptedPrivateKey: "2.new-private", encryptedPublicKey: "2.new-public",
      deviceResponse: await signedAssertion(passkey, options.options.rpId, options.token) };
  };

  await check("passkey login, WebAuthn 2FA, email 2FA, and PRF enable enforce challenge and credential binding", async () => {
    const f = fixture(), passkey = await makePasskey(f);
    const options = await expectJson(await f.fetch("/identity/accounts/webauthn/assertion-options"), 200);
    const deviceResponse = await signedAssertion(passkey, options.options.rpId, options.options.challenge);
    const fields = { grant_type: "webauthn", token: options.token, deviceIdentifier: DEVICE, deviceResponse: JSON.stringify(deviceResponse) };
    equal((await expectJson(await token(f, fields, { "Bitwarden-Client-Version": "" }), 400)).error, "version_header_missing");
    await expectStatus(await token(f, fields), 200);
    await expectStatus(await token(f, fields), 400);

    const fPrf = fixture();
    const actual = await makePasskey(fPrf, { supportsPrf: true });
    const target = await makePasskey(fPrf, { supportsPrf: true });
    const body = await prfAssertion(fPrf, actual);
    await expectStatus(await api(fPrf, `/api/webauthn/${target.saved.id}`, body, "PUT"), 401);
    const updated = await expectJson(await api(fPrf, `/api/webauthn/${actual.saved.id}`, body, "PUT"), 200);
    const prfStatus = new Map(updated.data.map(key => [key.id, key.prfStatus]));
    equal(prfStatus.get(actual.saved.id), 0);
    equal(prfStatus.get(target.saved.id), 1);
    await expectStatus(await api(fPrf, `/api/webauthn/${actual.saved.id}/delete`, { masterPasswordHash: "hash" }), 200);
  });
}
