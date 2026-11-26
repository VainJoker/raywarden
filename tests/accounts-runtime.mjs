import {
  bearerJsonHeaders,
  emailCodeHash,
  equal,
  expectJson,
  expectJsonOrEmpty,
  expectStatus,
  fixtureAccessSecret,
  fromBase64Url,
  oauthToken,
  ok,
  requestJson,
  toBase64Url,
  withFetchMock,
} from "./runtime-tools.mjs";
import { snapshotTables, DurableObjectNamespace, captureNotifications, token } from "./runtime-fixture.mjs";

export const accountsChecks = [runSetupChecks, runAccountChecks, runAccountSettingsChecks, runRouteParityChecks];

/** Private account enrollment through compiled Rust, real migrations and SQLite. */
async function runSetupChecks({ fixture, check, accessToken, sql }) {
  const EMAIL = "owner@example.test", TOKEN = "owner-setup-runtime-token-32-characters";
  const COOKIE = "raywarden_owner_setup";
  const aliases = ["/api/accounts/register", "/identity/accounts/register", "/identity/accounts/register/finish"];
  const post = (f, path, body, headers) => requestJson(f, path, body, { headers });
  const empty = () => {
    const f = fixture({ empty: true });
    f.env.ALLOWED_EMAILS = EMAIL; f.env.OWNER_SETUP_TOKEN = TOKEN;
    f.env.DISABLE_USER_REGISTRATION = "false";
    return f;
  };
  const count = () => sql.exec("SELECT COUNT(*) AS n FROM users").one().n;
  const payload = (email = EMAIL) => ({ email, masterPasswordHash: "client-owned-authentication-hash", key: "2.client-owned-wrapped-user-key",
    kdf: 0, kdfIterations: 600000, userAsymmetricKeys: { publicKey: "client-owned-public-key", encryptedPrivateKey: "2.client-owned-private-key" } });
  const configuration = async (f, cookie) => {
    const response = await expectStatus(await f.fetch("/api/config", { headers: cookie ? { Cookie: cookie } : {} }), 200);
    equal(response.headers.get("cache-control"), "no-store");
    return response.json();
  };
  const authorize = async (f, headers) => {
    const response = await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN }, headers), 200);
    equal(response.headers.get("cache-control"), "no-store");
    const set = response.headers.get("set-cookie");
    for (const part of [COOKIE + "=", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=600", "Secure"]) ok(set?.includes(part), `Missing cookie ${part}`);
    const body = await response.text();
    ok(!body.includes(TOKEN) && !body.includes(set.split(";")[0].split("=")[1]), "setup credentials leaked into JSON");
    return set.split(";")[0];
  };

  await check("public registration stays closed on every alias until independent owner authorization", async () => {
    const f = empty();
    equal((await configuration(f)).settings.disableUserRegistration, true);
    for (const path of aliases) await expectStatus(await post(f, path, payload()), 401);
    await expectStatus(await post(f, "/identity/accounts/register/send-verification-email", { email: EMAIL }), 401);
    equal(count(), 0);
    await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN + "wrong" }), 401);
    equal((await configuration(f)).settings.disableUserRegistration, true);
    await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN }, { Origin: "https://unrelated.test" }), 401);
    equal(count(), 0);
  });

  await check("setup configuration rejects missing and glob account identities and malformed tokens", async () => {
    const f = empty();
    for (const invalid of ["", "*", "owner*@example.test", "owner@@example.test"]) {
      f.env.ALLOWED_EMAILS = invalid;
      await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN }), 400);
    }
    delete f.env.ALLOWED_EMAILS;
    await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN }), 400);
    f.env.ALLOWED_EMAILS = EMAIL;
    for (const invalid of ["short", "x".repeat(513), " " + TOKEN, TOKEN + "\n"]) {
      f.env.OWNER_SETUP_TOKEN = invalid;
      await expectStatus(await post(f, "/api/accounts/setup", { token: invalid }), 400);
    }
    equal(count(), 0);
  });

  await check("setup page is private, cookie scope is strict and ordinary token classes cannot authorize signup", async () => {
    const f = empty();
    const page = await expectStatus(await f.fetch("/setup"), 200);
    equal(page.headers.get("cache-control"), "no-store");
    ok(page.headers.get("content-security-policy")?.includes("frame-ancestors 'none'"), "setup page has no frame protection");
    const html = await page.text();
    ok(html.includes('type="password"') && html.includes('/#/signup'), "setup page does not use the real signup route");
    ok(!html.includes(TOKEN), "setup page contained the secret");
    const cookie = await authorize(f);
    equal((await configuration(f, cookie)).settings.disableUserRegistration, false);
    equal((await configuration(f)).settings.disableUserRegistration, true);
    const verificationPath = "/identity/accounts/register/send-verification-email";
    const verification = await expectStatus(await post(f, verificationPath, { email: " Owner@Example.TEST " }, { Cookie: cookie }), 200);
    equal(await verification.json(), "email-verification-not-required");
    const invalidEmail = "owner@@example.test";
    await expectStatus(await post(f, verificationPath, { email: invalidEmail }, { Cookie: cookie }), 401);
    await expectStatus(await post(f, verificationPath, { email: EMAIL + "\t" }, { Cookie: cookie }), 401);
    await expectStatus(await post(f, aliases[0], payload(invalidEmail), { Cookie: cookie }), 401);
    await expectStatus(await post(f, aliases[0], payload("other@example.test"), { Cookie: cookie }), 401);
    const now = Math.floor(Date.now() / 1000);
    const secret = await fixtureAccessSecret(sql, f.env.KEY_ENCRYPTION_KEY);
    const proof = { sub: EMAIL, aud: "https://vault.test", purpose: "owner-setup" };
    const invalid = [
      await accessToken(),
      await token({ ...proof, purpose: "email-factor" }, secret),
      await token({ ...proof, aud: "https://other.test" }, secret),
      await token({ ...proof, sub: "other@example.test" }, secret),
      await token({ ...proof, iat: now - 600, nbf: now - 600, exp: now }, secret),
    ];
    for (const invalidToken of invalid) {
      const badCookie = `${COOKIE}=${invalidToken}`;
      equal((await configuration(f, badCookie)).settings.disableUserRegistration, true);
      await expectStatus(await post(f, aliases[0], payload(), { Cookie: badCookie }), 401);
    }
    equal(count(), 0);
  });

  await check("each registration alias accepts only client-owned material and then clears bootstrap authorization", async () => {
    for (const path of aliases) {
      const f = empty(); f.env.ALLOWED_EMAILS = " Owner@Example.TEST ";
      const cookie = await authorize(f);
      const request = payload(" Owner@Example.TEST ");
      const response = await expectStatus(await post(f, path, request, { Cookie: cookie }), 200);
      ok(response.headers.get("set-cookie")?.includes("Max-Age=0"), "successful signup kept setup cookie");
      const user = sql.exec("SELECT email,key,private_key,public_key FROM users").one();
      equal(user.email, EMAIL); equal(user.key, request.key);
      equal(user.private_key, request.userAsymmetricKeys.encryptedPrivateKey); equal(user.public_key, request.userAsymmetricKeys.publicKey);
      if (path === aliases[0]) {
        await expectStatus(await post(f, path, payload(), { Cookie: cookie }), 409);
        equal((await configuration(f, cookie)).settings.disableUserRegistration, true);
        await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN }), 409);
        await expectStatus(await post(f, "/identity/accounts/register/send-verification-email", { email: EMAIL }, { Cookie: cookie }), 409);
      }
    }
  });

  await check("simultaneous registration for the same email commits once and reports a conflict", async () => {
    const f = empty(); const cookie = await authorize(f);
    const responses = await Promise.all([
      post(f, aliases[0], payload(), { Cookie: cookie }),
      post(f, aliases[1], payload(), { Cookie: cookie }),
    ]);
    const statuses = responses.map(response => response.status).sort();
    equal(statuses.join(","), "200,409"); equal(count(), 1);
    for (const response of responses) await response.text();
  });

  await check("private enrollment creates multiple independent accounts and follows whitelist changes", async () => {
    const f = empty();
    f.env.ALLOWED_EMAILS = `${EMAIL},second@example.test`;
    const cookie = await authorize(f);
    await expectStatus(await post(f, aliases[0], payload(), { Cookie: cookie }), 200);
    equal(count(), 1);
    f.env.ALLOWED_EMAILS = `second@example.test,${EMAIL},${EMAIL}`;
    equal((await configuration(f, cookie)).settings.disableUserRegistration, false);
    await expectStatus(await post(f, aliases[0], payload("outsider@example.test"), { Cookie: cookie }), 401);
    await expectStatus(await post(f, aliases[0], payload("second@example.test")), 401);
    await expectStatus(await post(f, aliases[0], payload("second@example.test"), { Cookie: cookie }), 200);
    equal(count(), 2);
    equal((await configuration(f, cookie)).settings.disableUserRegistration, true);
    await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN }), 409);
    // Expanding or restricting the list invalidates old cookie scope immediately.
    f.env.ALLOWED_EMAILS += ",third@example.test";
    equal((await configuration(f, cookie)).settings.disableUserRegistration, true);
    await expectStatus(await post(f, aliases[0], payload("third@example.test"), { Cookie: cookie }), 401);
    const updated = await authorize(f);
    await expectStatus(await post(f, aliases[0], payload("third@example.test"), { Cookie: updated }), 200);
    equal(count(), 3);
    f.env.ALLOWED_EMAILS = "third@example.test";
    const login = await expectStatus(await oauthToken(f, {
      grant_type: "password", username: EMAIL, password: payload().masterPasswordHash,
      deviceIdentifier: "private-enrollment-login", deviceName: "Test Browser", deviceType: "14",
    }, { "Bitwarden-Client-Version": "2026.11.0" }), 200);
    const bearer = (await login.json()).access_token;
    const profile = await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 200);
    equal((await profile.json()).email, EMAIL);
  });

  await check("concurrent enrollment accepts two different allowed emails", async () => {
    const f = empty();
    f.env.ALLOWED_EMAILS = `${EMAIL}\nsecond@example.test`;
    const cookie = await authorize(f);
    const responses = await Promise.all([
      post(f, aliases[0], payload(), { Cookie: cookie }),
      post(f, aliases[1], payload("second@example.test"), { Cookie: cookie }),
    ]);
    for (const response of responses) await expectStatus(response, 200);
    equal(count(), 2);
  });

  await check("registration consumes its email code only when the account is created", async () => {
    const f = empty(); f.env.REQUIRE_EMAIL_VERIFICATION = "true";
    const secret = await fixtureAccessSecret(sql, f.env.KEY_ENCRYPTION_KEY);
    const digest = await emailCodeHash(secret, { owner: EMAIL, purpose: "registration", recipient: EMAIL, context: "", code: "123456" });
    const now = Math.floor(Date.now() / 1000);
    sql.exec("INSERT INTO verification_codes(id,owner_key,purpose,recipient,context,code_hash,issued_at,expires_at,ready) VALUES('setup-email',?,'registration',?,'',?,?,?,1)", EMAIL, EMAIL, digest, now, now + 600);
    const request = { ...payload(), emailVerificationToken: "123456" };
    const proof = () => sql.exec("SELECT attempts,consumed_at FROM verification_codes WHERE id='setup-email'").one();
    await expectStatus(await post(f, aliases[0], request), 401);
    const before = proof();
    equal(before.attempts, 0); equal(before.consumed_at, null);
    const cookie = await authorize(f);

    await expectStatus(await post(f, aliases[0], { ...request, kdfIterations: 1 }, { Cookie: cookie }), 400);
    equal(count(), 0);
    equal(JSON.stringify(proof()), JSON.stringify(before), "invalid KDF consumed the code");

    sql.exec("CREATE TRIGGER fixture_registration_failure BEFORE INSERT ON users BEGIN SELECT RAISE(ABORT,'fixture registration failed'); END");
    try {
      await expectStatus(await post(f, aliases[0], request, { Cookie: cookie }), 500);
      equal(count(), 0);
      equal(JSON.stringify(proof()), JSON.stringify(before), "failed account insert consumed the code");
    } finally {
      sql.exec("DROP TRIGGER fixture_registration_failure");
    }

    await expectStatus(await post(f, aliases[0], request, { Cookie: cookie }), 200);
    equal(count(), 1);
    equal(proof().attempts, 1);
    ok(proof().consumed_at !== null, "authorized signup did not consume the email code");
  });

  await check("bootstrap checks database errors and permits insecure cookies only on local loopback", async () => {
    const f = empty(); f.env.DOMAIN = "http://127.0.0.2:8787";
    const local = await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN }), 200);
    ok(!local.headers.get("set-cookie").includes("; Secure"), "loopback bootstrap required HTTPS cookie");
    f.env.DOMAIN = "HTTPS://VAULT.TEST:443/";
    const cookie = await authorize(f, { Origin: "https://vault.test" });
    equal((await configuration(f, cookie)).settings.disableUserRegistration, false);
    f.env.DOMAIN = "https://other.test";
    equal((await configuration(f, cookie)).settings.disableUserRegistration, true);
    f.env.DOMAIN = "https://vault.test";
    sql.exec("DROP TABLE users");
    await expectStatus(await post(f, "/api/accounts/setup", { token: TOKEN }), 500);
  });
}

/** Account HTTP regressions against the compiled Worker and workerd SQLite. */
async function runAccountChecks({ fixture, check, accessToken, USER, CIPHER, sql }) {
  const id = "0123456789abcdef0123456789abcdef";
  const oldId = "00000000-0000-4000-8000-000000000099";
  const kdf = { kdfType: 0, iterations: 600000, memory: null, parallelism: null };
  const signature = { signatureAlgorithm: "ed25519", wrappedSigningKey: "7.wrapped-signing", verifyingKey: "verifying-key" };
  const keys = () => ({
    userKeyEncryptedAccountPrivateKey: "7.wrapped-private", accountPublicKey: "public",
    publicKeyEncryptionKeyPair: { publicKey: "public", wrappedPrivateKey: "7.wrapped-private", signedPublicKey: "signed-public" },
    signatureKeyPair: { ...signature }, securityState: { securityState: "encrypted-security-state", securityVersion: 2 },
  });
  const json = (f, path, body, bearer, method, headers) => requestJson(f, path, body, {
    method, headers: { ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}), ...headers },
  });
  const login = (f, email, password, version, deviceType = "14") => oauthToken(f, {
    grant_type: "password", username: email, password,
    deviceIdentifier: "account-runtime-login", deviceName: "Runtime Browser", deviceType: "14",
  }, { "device-type": deviceType, ...(version ? { "Bitwarden-Client-Version": version } : {}) });
  const removeVault = () => {
    sql.exec("DELETE FROM attachments_pending; DELETE FROM attachments; DELETE FROM ciphers; DELETE FROM folders; DELETE FROM sends;");
  };
  const upgrade = (old = null, ciphers = []) => ({
    oldUserKeyId: old, newUserKeyId: id,
    wrappedAccountCryptographicState: { publicKeyEncryptionKeyPair: keys().publicKeyEncryptionKeyPair,
      signatureKeyPair: { ...signature }, securityState: keys().securityState },
    unlockMethodData: { unlockMethod: 1, masterPasswordUnlockData: {
      kdf: { ...kdf }, salt: "owner@example.test", masterKeyWrappedUserKey: "7.new-wrapped-user", containedKeyId: id,
    } },
    unlockData: { passkeyUnlockData: [], v2UpgradeToken: { wrappedUserKey1: "7.bridge-one", wrappedUserKey2: "7.bridge-two" } },
    accountData: { ciphers, folders: [], sends: [] },
  });

  const envelope = () => sql.exec("SELECT key,user_key_id,private_key,public_key,signed_public_key,security_state,security_version,signature_key_pair FROM users WHERE id=?", USER).one();
  const seedPrf = () => {
    const current = JSON.stringify(envelope());
    for (const [slot, snapshot] of [[1, current], [2, JSON.stringify({ ...envelope(), key: "older-generation" })]]) {
      sql.exec("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,sign_count,credential_use,prf_status,encrypted_public_key,encrypted_user_key,encrypted_private_key,account_snapshot,created_at,updated_at) VALUES(?,?,?,?,?,? ,0,'login',0,?,?,?,?,?,?)",
        `account-passkey-${slot}`, USER, slot, "PRF fixture", `account-wire-${slot}`, "opaque-public-key",
        "prf-public", "prf-user", "prf-private", snapshot, "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z");
    }
  };
  const readyEmailCode = async (f, recipient, purpose = "change-email", session = "session") => {
    const secret = await fixtureAccessSecret(sql, f.env.KEY_ENCRYPTION_KEY);
    const digest = await emailCodeHash(secret, { owner: USER, purpose, recipient, context: "", code: "123456" });
    const now = Math.floor(Date.now() / 1000);
    sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,context,code_hash,security_stamp,session_token,issued_at,expires_at,ready) VALUES('email-runtime',?,?,?,?,'',?,'owner-stamp',?,?,?,1)", USER, USER, purpose, recipient, digest, session, now, now + 600);
  };

  await check("account deletion, factor disable, and mailbox confirmation enforce session/OTP guards and post-commit logout", async () => {
    const f = fixture(), bearer = await accessToken();
    await readyEmailCode(f, "owner@example.test", "protected-action");
    const reached = f.db.beforeNextBatch(
      s => s.some(st => st.sql.startsWith("DELETE FROM users WHERE id = ")),
      () => sql.exec("UPDATE devices SET session_token='next' WHERE user_id=? AND device_id='device'", USER),
    );
    await expectStatus(await json(f, "/api/accounts/delete", { otp: "123456" }, bearer), 409);
    ok(reached());
    equal(sql.exec("SELECT consumed_at FROM verification_codes WHERE id='email-runtime'").one().consumed_at, null);

    const fDel = fixture(), effects = [];
    fDel.env.notifydo = new DurableObjectNamespace(async req => {
      equal(sql.exec("SELECT COUNT(*) AS n FROM users WHERE id=?", USER).one().n, 0);
      effects.push((await req.json()).logout);
      return new Response('{"sent":1}');
    });
    await expectStatus(await json(fDel, "/api/accounts/delete", { masterPasswordHash: "hash" }, await accessToken()), 200);
    equal(effects.join(","), "true");

    const fMail = fixture();
    await readyEmailCode(fMail, "owner@example.test", "verify-email", "");
    await expectStatus(await json(fMail, "/api/accounts/verify-email-token", { userId: USER, token: "123456" }), 200);
    equal(sql.exec("SELECT is_email_verified FROM users WHERE id=?", USER).one().is_email_verified, 1);
    await expectStatus(await json(fMail, "/api/accounts/verify-email-token", { userId: USER, token: "123456" }), 400);
  });

  await check("V2 registration persists complete material and returns it through token, profile and sync", async () => {
    const f = fixture({ empty: true });
    const email = "registered@example.test";
    f.env.ALLOWED_EMAILS = email;
    f.env.OWNER_SETUP_TOKEN = "account-runtime-owner-setup-authorization";
    const response = await json(f, "/api/accounts/register", {
      email, accountKeys: keys(),
      masterPasswordAuthentication: { kdf: { ...kdf }, salt: email, hash: "client-authentication-hash" },
      masterPasswordUnlock: { kdf: { ...kdf }, salt: email, key: "7.wrapped-user", containedKeyId: id },
    }, undefined, "POST", { "X-Raywarden-Setup-Token": f.env.OWNER_SETUP_TOKEN });
    await expectStatus(response, 200);
    const row = sql.exec("SELECT id,user_key_id,security_version,signed_public_key,signature_key_pair FROM users WHERE email=?", email).one();
    equal(row.user_key_id, id); equal(row.security_version, 2); equal(row.signed_public_key, "signed-public");
    equal(JSON.parse(row.signature_key_pair).verifyingKey, "verifying-key");
    const tokenResponse = await expectStatus(await login(f, email, "client-authentication-hash", "2026.10.1"), 200);
    const tokens = await tokenResponse.json();
    equal(tokens.AccountKeys.securityState.securityVersion, 2);
    equal(tokens.AccountKeys.Object, "privateKeys");
    equal(tokens.AccountKeys.publicKeyEncryptionKeyPair.Object, "publicKeyEncryptionKeyPair");
    equal(tokens.AccountKeys.publicKeyEncryptionKeyPair.signedPublicKey, "signed-public");
    equal(tokens.UserDecryptionOptions.MasterPasswordUnlock.ContainedKeyId, id);
    const auth = { headers: { Authorization: `Bearer ${tokens.access_token}` } };
    const profile = await expectJson(await f.fetch("/api/accounts/profile", auth), 200);
    equal(profile.accountKeys.securityState.securityVersion, 2);
    const publicKeys = await expectJson(await f.fetch(`/api/users/${row.id}/keys`, auth), 200);
    equal(publicKeys.verifyingKey, "verifying-key"); equal(publicKeys.signedPublicKey, "signed-public");
    const sync = await expectJson(await f.fetch("/api/sync?excludeDomains=true", auth), 200);
    equal(sync.profile.accountKeys.signatureKeyPair.verifyingKey, "verifying-key");
    equal(sync.userDecryption.userKeyId, id);
    equal(sync.userDecryption.masterPasswordUnlock.containedKeyId, id);
  });

  await check("client-version rejection follows successful credentials and uses the desktop boundary", async () => {
    const f = fixture();
    sql.exec("UPDATE users SET private_key='7.private',signed_public_key='signed',security_state='state',security_version=2,signature_key_pair=?,user_key_id=? WHERE id=?", JSON.stringify(signature), id, USER);
    await expectStatus(await login(f, "owner@example.test", "wrong-password", undefined), 401);
    const missing = await expectJson(await login(f, "owner@example.test", "hash", undefined), 400);
    equal(missing.error, "version_header_missing");
    const desktop = await expectJson(await login(f, "owner@example.test", "hash", "2026.10.1", "6"), 400);
    equal(desktop.error, "invalid_client_version");
    await expectStatus(await login(f, "owner@example.test", "hash", "2026.10.1", "14"), 200);
    await expectStatus(await login(f, "owner@example.test", "hash", "2026.10.2", "6"), 200);
  });

  await check("V1 upgrade preserves the exact session stamp, replaces a legacy UUID id and returns its bridge", async () => {
    const f = fixture(); removeVault();
    sql.exec("UPDATE users SET user_key_id=? WHERE id=?", oldId, USER);
    const bearer = await accessToken();
    await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", upgrade(oldId), bearer), 200);
    const row = sql.exec("SELECT security_stamp,user_key_id,security_version,key FROM users WHERE id=?", USER).one();
    equal(row.security_stamp, "owner-stamp"); equal(row.user_key_id, id); equal(row.security_version, 2); equal(row.key, "7.new-wrapped-user");
    const sync = await expectJson(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${bearer}` } }), 200);
    equal(sync.userDecryption.v2UpgradeToken.wrappedUserKey1, "7.bridge-one");
    equal(sync.profile.accountKeys.securityState.securityVersion, 2);
    await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", upgrade(oldId), bearer), 409);
  });

  await check("password plus V2 key rotation commits together and invalidates the previous session", async () => {
    const f = fixture(); removeVault();
    const bearer = await accessToken();
    const body = {
      oldMasterKeyAuthenticationHash: "hash", oldUserKeyId: null, newUserKeyId: id,
      accountKeys: keys(), accountData: { ciphers: [], folders: [], sends: [] },
      accountUnlockData: { masterPasswordUnlockData: {
        kdfType: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null,
        email: "owner@example.test", masterKeyAuthenticationHash: "replacement-client-auth",
        masterKeyEncryptedUserKey: "7.replacement-user", masterPasswordHint: "new hint", containedKeyId: id,
      }, passkeyUnlockData: [] },
    };
    await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-account-keys", body, bearer), 200);
    const row = sql.exec("SELECT key,security_stamp,v2_upgrade_token,security_version FROM users WHERE id=?", USER).one();
    equal(row.key, "7.replacement-user"); equal(row.security_version, 2); equal(row.v2_upgrade_token, null);
    if (row.security_stamp === "owner-stamp") throw new Error("Password rotation retained the old stamp");
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 401);
    await expectStatus(await login(f, "owner@example.test", "hash", "2026.10.1"), 401);
    const tokens = await expectJson(await login(f, "owner@example.test", "replacement-client-auth", "2026.10.1"), 200);
    equal(tokens.AccountKeys.securityState.securityVersion, 2);
  });

  await check("an intervening encrypted edit makes rotation reject without partial account or cipher writes", async () => {
    const f = fixture();
    sql.exec("DELETE FROM attachments_pending; DELETE FROM attachments; DELETE FROM sends;");
    const original = sql.exec("SELECT key,security_stamp FROM users WHERE id=?", USER).one();
    const body = upgrade(null, [{ id: CIPHER, type: 1, name: "7.rotated-name", login: { password: "7.rotated-password" }, key: "7.rotated-item" }]);
    const changed = f.db.beforeNextBatch(
      statements => statements[0]?.sql.startsWith("UPDATE users SET key="),
      () => sql.exec("UPDATE ciphers SET data=? WHERE id=?", '{"name":"concurrent-edit","login":{}}', CIPHER),
    );
    await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", body, await accessToken()), 409);
    ok(changed(), "race fixture missed the transaction boundary");
    const user = sql.exec("SELECT key,security_stamp,security_version FROM users WHERE id=?", USER).one();
    equal(user.key, original.key); equal(user.security_stamp, original.security_stamp); equal(user.security_version, null);
    equal(JSON.parse(sql.exec("SELECT data FROM ciphers WHERE id=?", CIPHER).one().data).name, "concurrent-edit");
  });

  await check("rotation rejects a foreign attachment among complete owned material without writing any rows", async () => {
    const f = fixture();
    sql.exec("DELETE FROM attachments_pending; DELETE FROM sends;");
    const foreignCipher = "00000000-0000-4000-8000-000000000101";
    const foreignFile = "00000000-0000-4000-8000-000000000102";
    const date = "2026-01-01T00:00:00.000Z";
    sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,'other-owner',1,?,?,?)", foreignCipher, '{"name":"foreign-encrypted"}', date, date);
    sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at) VALUES(?,?,?,6,?,?,?)", foreignFile, foreignCipher, "foreign-file", "foreign-key", date, date);
    const owned = sql.exec("SELECT id FROM attachments WHERE cipher_id=?", CIPHER).one();
    const attachments2 = {
      [owned.id]: { fileName: "7.rotated-own-file", key: "7.rotated-own-key" },
      [foreignFile]: { fileName: "7.invalid-foreign-file", key: "7.invalid-foreign-key" },
    };
    const body = upgrade(null, [{
      id: CIPHER, type: 1, name: "7.rotated-name", key: "7.rotated-item",
      login: { password: "7.rotated-password" }, encryptedFor: USER, encryptedByKeyId: id, attachments2,
    }]);
    const snapshot = () => snapshotTables(sql, ["users", "ciphers", "attachments", "devices"]);
    const bearer = await accessToken();
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 200);
    const before = snapshot();
    const response = await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", body, bearer), 400);
    const error = await response.json();
    if (!error.message.includes("Rotated attachment does not belong to the cipher")) throw new Error(`Wrong rotation rejection: ${JSON.stringify(error)}`);
    equal(snapshot(), before, "rejected foreign material changed account, vault or session rows");

    // A successful control proves the rejected request included every owned
    // cipher/attachment and had valid credentials and account key material.
    delete attachments2[foreignFile];
    await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", body, bearer), 200);
    equal(sql.exec("SELECT encrypted_key FROM attachments WHERE id=?", owned.id).one().encrypted_key, "7.rotated-own-key");
    equal(sql.exec("SELECT encrypted_key FROM attachments WHERE id=?", foreignFile).one().encrypted_key, "foreign-key");
  });

  await check("email credential commit rejects a same-stamp V2 upgrade and preserves remember state", async () => {
    const f = fixture(); const recipient = "new-owner@example.test";
    f.env.ALLOWED_EMAILS = `owner@example.test,${recipient}`;
    await readyEmailCode(f, recipient);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,data) VALUES('email-remember',?,5,'{}')", USER);
    const changed = f.db.beforeNextBatch(
      statements => statements.some(statement => statement.sql.startsWith("UPDATE users SET email=")),
      () => sql.exec("UPDATE users SET key='7.concurrent-upgrade',private_key='7.new-private',signed_public_key='signed',security_state='new-state',security_version=2,signature_key_pair=?,user_key_id=? WHERE id=?", JSON.stringify(signature), id, USER),
    );
    await expectStatus(await json(f, "/api/accounts/email", { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth", newEmail: recipient, key: "2.stale-wrapper", token: "123456" }, await accessToken()), 409);
    ok(changed(), "email fixture missed guarded publication");
    const user = sql.exec("SELECT email,key,security_stamp FROM users WHERE id=?", USER).one();
    equal(user.email, "owner@example.test"); equal(user.key, "7.concurrent-upgrade"); equal(user.security_stamp, "owner-stamp");
    equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=? AND provider_type=5", USER).one().n, 1);
    equal(sql.exec("SELECT consumed_at FROM verification_codes WHERE id='email-runtime'").one().consumed_at, null);
  });

  await check("an email claimed by another account during commit returns a conflict and preserves account state", async () => {
    const f = fixture(), recipient = "contended@example.test";
    f.env.ALLOWED_EMAILS = `owner@example.test,${recipient}`;
    await readyEmailCode(f, recipient);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,data) VALUES('contended-remember',?,5,'{}')", USER);
    const claimed = f.db.beforeNextBatch(
      statements => statements.some(statement => statement.sql.startsWith("UPDATE users SET email=")),
      () => sql.exec("UPDATE users SET email=? WHERE id='other-owner'", recipient),
    );
    const bearer = await accessToken();
    const body = { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth",
      newEmail: recipient, key: "2.rewrapped", token: "123456" };
    await expectStatus(await json(f, "/api/accounts/email", { ...body, token: "654321" }, bearer), 400);
    await expectStatus(await json(f, "/api/accounts/email", body, bearer), 409);
    equal(claimed(), true);
    const user = sql.exec("SELECT email,key,security_stamp FROM users WHERE id=?", USER).one();
    equal(user.email, "owner@example.test"); equal(user.key, "2.wrapped"); equal(user.security_stamp, "owner-stamp");
    equal(sql.exec("SELECT email FROM users WHERE id='other-owner'").one().email, recipient);
    equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE id='contended-remember'").one().n, 1);
    const proof = sql.exec("SELECT attempts, consumed_at FROM verification_codes WHERE id='email-runtime'").one();
    equal(proof.attempts, 1);
    equal(proof.consumed_at, null);

    sql.exec("UPDATE users SET email='other@example.test' WHERE id='other-owner'");
    await expectStatus(await json(f, "/api/accounts/email", body, bearer), 200);
    equal(sql.exec("SELECT email FROM users WHERE id=?", USER).one().email, recipient);
    equal(sql.exec("SELECT count(*) AS n FROM verification_codes WHERE id='email-runtime'").one().n, 0);
  });

  await check("password and email changes retag only a current PRF wrapper without replacing its ciphertext", async () => {
    for (const kind of ["password", "email"]) {
      const f = fixture(); seedPrf();
      const bearer = await accessToken(); const wrapper = `2.${kind}-rewrapped-user`;
      let path, body;
      if (kind === "email") {
        const recipient = "changed-owner@example.test"; f.env.ALLOWED_EMAILS = `owner@example.test,${recipient}`; await readyEmailCode(f, recipient);
        path = "/api/accounts/email";
        body = { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth", newEmail: recipient, key: wrapper, token: "123456" };
      } else {
        path = "/api/accounts/password";
        body = { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth", key: wrapper };
      }
      const captured = [];
      f.env.notifydo = new DurableObjectNamespace(async req => {
        const update = await req.json();
        const key = sql.exec("SELECT key FROM users WHERE id=?", USER).one().key;
        captured.push({ update, key });
        return new Response(null, { status: 204 });
      });
      await expectStatus(await json(f, path, body, bearer), 200);
      equal(captured.length, 1, `${kind} notification count`);
      const { update, key } = captured[0];
      equal(key, wrapper, `${kind} published before commit`);
      equal(update.selector.kind, "user"); equal(update.selector.user_id, USER); equal(update.logout, true);
      const frame = atob(update.message);
      equal(frame.includes("\xa4Type\x0b"), true, "LogOut type");
      equal(frame.includes("\xa9ContextId\xa6device"), true, "authenticated device context");
      const current = sql.exec("SELECT account_snapshot,encrypted_user_key,encrypted_private_key FROM webauthn_credentials WHERE id='account-passkey-1'").one();
      equal(JSON.parse(current.account_snapshot).key, wrapper); equal(current.encrypted_user_key, "prf-user"); equal(current.encrypted_private_key, "prf-private");
      equal(JSON.parse(sql.exec("SELECT account_snapshot FROM webauthn_credentials WHERE id='account-passkey-2'").one().account_snapshot).key, "older-generation");
      await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 401);
    }
  });

  await check("key rotation returns PRF rotation data and publishes rewrapped passkey envelopes in the new generation", async () => {
    const f = fixture(); removeVault(); seedPrf();
    // A stale PRF envelope is deliberately excluded from this valid rotation.
    sql.exec("DELETE FROM webauthn_credentials WHERE id='account-passkey-2'");
    const bearer = await accessToken();
    const data = await expectJson(await f.fetch("/api/accounts/key-management/key-rotation-data", { headers: { Authorization: `Bearer ${bearer}` } }), 200);
    equal(data.passkeyKeyData.length, 1); equal(data.passkeyKeyData[0].id, "1");
    const body = upgrade();
    body.unlockData.passkeyUnlockData = [{ id: "1", encryptedPublicKey: "new-prf-public", encryptedUserKey: "new-prf-user" }];
    await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", body, bearer), 200);
    const row = sql.exec("SELECT encrypted_public_key,encrypted_user_key,encrypted_private_key,account_snapshot FROM webauthn_credentials WHERE id='account-passkey-1'").one();
    equal(row.encrypted_public_key, "new-prf-public"); equal(row.encrypted_user_key, "new-prf-user"); equal(row.encrypted_private_key, "prf-private");
    equal(JSON.parse(row.account_snapshot).key, "7.new-wrapped-user"); equal(JSON.parse(row.account_snapshot).user_key_id, id);
  });


  await check("rotation of five 450KB blobs passes the old 2MiB boundary in one transaction", async () => {
    const f = fixture(); removeVault();
    const blob = JSON.stringify({ format_version: 1, encrypted_data: "x".repeat(450000) });
    const ciphers = [];
    for (let number = 0; number < 5; number++) {
      const cipher = `large-rotation-${number}`;
      sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,?,1,?,?,?)", cipher, USER, JSON.stringify({ name: "", data: blob }), "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z");
      ciphers.push({ id: cipher, type: 1, data: blob, key: "7.rewrapped-item", encryptedFor: USER, encryptedByKeyId: id });
    }
    const body = upgrade(null, ciphers);
    if (JSON.stringify(body).length <= 2 * 1024 * 1024) throw new Error("large-rotation fixture did not exceed 2MiB");
    await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", body, await accessToken()), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers WHERE user_id=?", USER).one().n, 5);
    for (const row of sql.exec("SELECT data FROM ciphers WHERE user_id=?", USER).toArray()) equal(JSON.parse(row.data).data, blob);
  });

  await check("both rotation endpoints reject a streamed JSON body above the explicit 16MiB limit", async () => {
    for (const path of ["/api/accounts/key-management/rotate-user-keys", "/api/accounts/key-management/rotate-user-account-keys"]) {
      const f = fixture(); let sent = 0;
      const chunk = new Uint8Array(65536).fill(32);
      const body = new ReadableStream({ pull(controller) {
        if (sent >= 17 * 1024 * 1024) { controller.close(); return; }
        controller.enqueue(chunk); sent += chunk.length;
      } });
      await expectStatus(await f.fetch(path, { method: "POST", headers: { Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" }, body }), 413);
    }
  });


  await check("sync includes SSH entries only for supported stable client versions", async () => {
    const f = fixture();
    sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES('account-ssh',?,5,?,?,?)", USER,
      JSON.stringify({ name: "2.encrypted-ssh", sshKey: { privateKey: "2.private", publicKey: "2.public", keyFingerprint: "2.fingerprint" } }), "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z");
    const bearer = await accessToken();
    for (const [version, included] of [[undefined, false], ["invalid", false], ["2024.11.9", false], ["2024.12.0", true], ["2026.11.0", true], ["2026.11.0-beta.1", false]]) {
      const response = await expectJson(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${bearer}`, ...(version ? { "Bitwarden-Client-Version": version } : {}) } }), 200);
      equal(response.ciphers.some(cipher => cipher.id === "account-ssh"), included, `SSH filter for ${version ?? "missing header"}`);
      if (!response.ciphers.some(cipher => cipher.id === CIPHER)) throw new Error("SSH version filter removed an ordinary cipher");
    }
  });

}

/** API-key, domain-setting and logical storage contracts in real Worker WASM. */
async function runAccountSettingsChecks({ fixture, check, sql, accessToken, USER, CIPHER, SEND }) {
  const owner = async () => bearerJsonHeaders(await accessToken());
  const api = async (f, rotate = false, hash = "hash") => requestJson(f, `/api/accounts/${rotate ? "rotate-api-key" : "api-key"}`,
    { masterPasswordHash: hash }, { headers: await owner() });
  const apiJson = async f => expectJson(await api(f), 200);
  const state = () => snapshotTables(sql, ["users", "devices", "user_api_keys", "user_api_key_sessions"]);
  const unchanged = before => equal(state() === before, true, "rejected operation changed account or session state");
  const isApi = statements => statements.some(value => value.sql.startsWith("UPDATE users SET account_write_token="));
  await check("API-key reads, concurrent issuance, rotation, and active session preservation", async () => {
    const f = fixture(), responses = await f.db.beforeBothBatches(isApi, () => api(f));
    const values = await Promise.all(responses.map(async value => (await expectStatus(value, 200)).json()));
    equal(values[0].apiKey, values[1].apiKey);
    const before = state();
    equal((await apiJson(f)).apiKey, values[0].apiKey);
    unchanged(before);
    await expectStatus(await api(f, false, "wrong-password"), 401);
    unchanged(before);

    const authenticated = await expectJson(await oauthToken(f, {
      grant_type: "client_credentials", client_id: `user.${USER}`, client_secret: values[0].apiKey,
      scope: "api offline_access", deviceIdentifier: "misc-api-client", deviceName: "API Runtime", deviceType: "14",
    }, { "Bitwarden-Client-Version": "2026.10.2", "device-type": "14" }), 200);
    const apiHeaders = bearerJsonHeaders(authenticated.access_token);
    const rotated = await expectJson(await requestJson(f, "/api/accounts/rotate-api-key",
      { masterPasswordHash: "hash" }, { headers: apiHeaders }), 200);
    ok(rotated.apiKey !== values[0].apiKey);
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: apiHeaders }), 401);
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: await owner() }), 200);
    equal((await apiJson(f)).apiKey, rotated.apiKey);
  });

  const domains = async (f, body, method, authorized = true) => requestJson(f, "/api/settings/domains", body, {
    method, headers: authorized ? await owner() : undefined,
  });
  const payload = { equivalentDomains: [["one.example", "two.example"]], excludedGlobalEquivalentDomains: [1, 2] };
  function notificationType(value) {
    const bytes = Uint8Array.from(atob(value.message), char => char.charCodeAt(0));
    const key = [0xa4, 0x54, 0x79, 0x70, 0x65];
    for (let i = 0; i < bytes.length - key.length; i++) if (key.every((byte, at) => bytes[i + at] === byte)) return bytes[i + key.length];
    throw new Error("Notification frame has no Type entry");
  }

  await check("domain POST, PUT, settings, and sync handle exclusions and invalid stored JSON", async () => {
    const f = fixture(), captured = captureNotifications(f);
    sql.exec("INSERT INTO global_domains_cache VALUES(1, 4000000000)");
    for (const [order, type, domain] of [[0, 20, "first.test"], [1, 1, "second.test"], [2, 10, "third.test"]]) {
      sql.exec("INSERT INTO global_equivalent_domains(type,sort_order,domains_json) VALUES(?,?,?)", type, order, JSON.stringify([domain]));
    }
    for (const method of ["POST", "PUT"]) {
      await expectStatus(await domains(f, payload, method), 200);
      await expectStatus(await domains(f, {}, method, false), 401);
    }
    equal(captured.length, 2);
    for (const event of captured) equal(notificationType(event), 10);
    const headers = await owner();
    sql.exec("UPDATE users SET excluded_globals='[1,1]', equivalent_domains='[' WHERE id=?", USER);
    const readSettings = await expectJson(await f.fetch("/api/settings/domains", { headers }), 200);
    const sync = await expectJson(await f.fetch("/api/sync", { headers }), 200);
    equal(JSON.stringify(readSettings.equivalentDomains), "[]");
    equal(JSON.stringify(sync.domains.globalEquivalentDomains.map(g => g.type)), "[20,10]");
  });
}

/** Actual compatibility aliases, bounded icons and atomic WebAuthn clearing. */
async function runRouteParityChecks({ fixture, check, sql, accessToken, USER, SEND }) {
  const headers = async () => bearerJsonHeaders(await accessToken());
  const request = async (f, path, body, method, authorized = true) => requestJson(f, path, body, {
    method, headers: authorized ? await headers() : undefined,
  });

  const expectNotification = (update, type, logout) => {
    equal(update.selector.kind, "user"); equal(update.selector.user_id, USER);
    equal(update.logout, logout);
    const frame = atob(update.message);
    ok(frame.includes(`\xa4Type${String.fromCharCode(type)}`), `missing notification type ${type}`);
    ok(frame.includes("\xa9ContextId\xa6device"), "missing authenticated device context");
  };

  await check("password verification and folder rename aliases enforce authentication", async () => {
    const f = fixture();
    equal((await expectJsonOrEmpty(await request(f, "/accounts/verify-password", { masterPasswordHash: "hash" }), 200)).Object, "masterPasswordPolicy");
    await expectJsonOrEmpty(await request(f, "/accounts/verify-password", { masterPasswordHash: "wrong" }), 401);
    const folder = await expectJsonOrEmpty(await request(f, "/api/folders", { name: "2.original" }), 200);
    const renamed = await expectJsonOrEmpty(await request(f, `/api/folders/${folder.id}`, { name: "2.renamed" }), 200);
    equal(renamed.name, "2.renamed");
    for (const [path, body] of [[`/api/folders/${folder.id}`, { name: "2.unauthorized" }], ["/accounts/verify-password", { masterPasswordHash: "hash" }]]) {
      await expectJsonOrEmpty(await request(f, path, body, "POST", false), 401);
    }
    equal(sql.exec("SELECT name FROM folders WHERE id=?", folder.id).one().name, "2.renamed");
  });

  await check("profile and avatar aliases require a live session and notify once after each write", async () => {
    const f = fixture();
    const account = () => sql.exec("SELECT name,avatar_color FROM users WHERE id=?", USER).one();
    const captured = captureNotifications(f, update => ({ update, account: account() }));
    for (const [path, field, column, values, invalid] of [
      ["/api/accounts/profile", "name", "name", ["First profile", "Second profile"], "x".repeat(51)],
      ["/api/accounts/avatar", "avatarColor", "avatar_color", ["#123abc", "#345def"], "x"],
    ]) {
      for (const [method, value] of [["POST", values[0]], ["PUT", values[1]]]) {
        const result = await expectJsonOrEmpty(await request(f, path, { [field]: value }, method), 200);
        equal(result[field], value);
        equal(captured.length, 1);
        const notification = captured.shift();
        expectNotification(notification.update, 5, false);
        equal(notification.account[column], value);
      }
      await expectJsonOrEmpty(await request(f, path, { [field]: invalid }), 400);
      await expectJsonOrEmpty(await request(f, path, { [field]: values[0] }, "PUT", false), 401);
      equal(account()[column], values[1]);
      equal(captured.length, 0);
    }
    const avatarColor = account().avatar_color;
    sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
    await expectJsonOrEmpty(await request(f, "/api/accounts/avatar", { avatarColor: "#ffffff" }), 401);
    equal(account().avatar_color, avatarColor);
    equal(captured.length, 0);
  });

  await check("device token aliases retain current-device authorization and clear stored tokens", async () => {
    for (const method of ["POST", "PUT"]) {
      const f = fixture();
      const changeToken = async (id, action, body) => f.fetch(`/api/devices/identifier/${id}/${action}`, {
        method, headers: await headers(), ...(body ? { body: JSON.stringify(body) } : {}),
      });
      await expectJsonOrEmpty(await changeToken("device", "token", { pushToken: " test-push-token " }), 200);
      await expectJsonOrEmpty(await changeToken("other-device", "token", { pushToken: "foreign" }), 400);
      equal(sql.exec("SELECT push_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().push_token, "test-push-token");
      await expectJsonOrEmpty(await changeToken("other-device", "clear-token"), 400);
      await expectJsonOrEmpty(await changeToken("device", "clear-token"), 200);
      equal(sql.exec("SELECT push_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().push_token, null);
    }
  });

  await check("an optional bearer on anonymous Send metadata never produces an account update", async () => {
    const f = fixture();
    const captured = captureNotifications(f, update => ({ update, account: null }));
    sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) SELECT 'other-owner',device_id,name,device_type,session_token,created_at,updated_at FROM devices WHERE user_id=?", USER);
    const send = await expectJsonOrEmpty(await f.fetch(`/api/sends/${SEND}`, { headers: await headers() }), 200);
    const result = await expectJsonOrEmpty(await f.fetch(`/api/sends/access/${send.accessId}`, {
      method: "POST", body: "{}",
      headers: { Authorization: `Bearer ${await accessToken({ sub: "other-owner", sstamp: "other" })}`, "Content-Type": "application/json" },
    }), 200);
    equal(result.object, "send-access");
    equal(captured.length, 0);
  });

  await check("KDF changes notify once with LogOut after revoking the old session and never after rollback", async () => {
    const f = fixture();
    const captured = captureNotifications(f, update => ({ update, account: sql.exec("SELECT key,kdf_iterations,security_stamp FROM users WHERE id=?", USER).one() }));
    const body = { masterPasswordHash: "hash", newMasterPasswordHash: "changed-auth", key: "2.kdf-change", kdf: 0, kdfIterations: 650000 };
    f.db.failBatch = true;
    await expectJsonOrEmpty(await request(f, "/api/accounts/kdf", body), 500);
    equal(captured.length, 0);

    f.db.failBatch = false;
    await expectJsonOrEmpty(await request(f, "/api/accounts/kdf", body), 200);
    equal(captured.length, 1);
    expectNotification(captured[0].update, 11, true);
    equal(captured[0].account.key, body.key);
    equal(captured[0].account.kdf_iterations, body.kdfIterations);
    ok(captured[0].account.security_stamp !== "owner-stamp", "LogOut preceded session invalidation");
    await expectJsonOrEmpty(await f.fetch("/api/accounts/profile", { headers: await headers() }), 401);
  });

  await check("admin-request is the same public known-device approval request protocol", async () => {
    const f = fixture();
    const post = body => requestJson(f, "/api/auth-requests/admin-request", body, { headers: { "device-type": "0" } });
    const body = { email: "owner@example.test", deviceIdentifier: "device", accessCode: "request-code", publicKey: "request-public-key" };
    const created = await expectJsonOrEmpty(await post(body), 200);
    equal(created.object, "auth-request");
    equal(sql.exec("SELECT request_device_id FROM auth_requests WHERE id=?", created.id).one().request_device_id, "device");
    equal(sql.exec("SELECT COUNT(*) AS n FROM auth_requests WHERE user_id=?", USER).one().n, 1);
    await expectJsonOrEmpty(await post({ ...body, deviceIdentifier: "unknown-device" }), 400);
    equal(sql.exec("SELECT COUNT(*) AS n FROM auth_requests WHERE user_id=?", USER).one().n, 1);
  });

  await check("client version rejection leaves an approved authentication request usable", async () => {
    const f = fixture(), device = "requesting-device", ip = "192.0.2.11";
    sql.exec(
      "INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?,?,?,0,?,?,?)",
      USER, device, "Requesting device", "previous-session", "before", "before",
    );
    const approvalRequest = { email: "owner@example.test", deviceIdentifier: device, accessCode: "request-code", publicKey: "request-public-key" };
    const created = await expectJsonOrEmpty(await f.fetch("/api/auth-requests", {
      method: "POST", headers: { "Content-Type": "application/json", "device-type": "0", "cf-connecting-ip": ip },
      body: JSON.stringify(approvalRequest),
    }), 200);
    const approved = await expectJsonOrEmpty(await request(f, `/api/auth-requests/${created.id}`, {
      deviceIdentifier: "device", key: "2.approved-key", requestApproved: true,
    }, "PUT"), 200);
    equal(approved.requestApproved, true);

    const exchange = version => f.fetch("/identity/connect/token", {
      method: "POST", headers: {
        "Content-Type": "application/x-www-form-urlencoded", "device-type": "0", "cf-connecting-ip": ip,
        ...(version ? { "Bitwarden-Client-Version": version } : {}),
      },
      body: new URLSearchParams({
        grant_type: "password", username: approvalRequest.email, authRequest: created.id,
        accessCode: approvalRequest.accessCode, deviceIdentifier: device, deviceType: "0",
      }),
    });
    const consumed = () => sql.exec("SELECT authenticated_at FROM auth_requests WHERE id=?", created.id).one().authenticated_at;
    const session = () => sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id=?", USER, device).one().session_token;
    equal((await expectJsonOrEmpty(await exchange(), 400)).error, "version_header_missing");
    equal(consumed(), null);
    equal(session(), "previous-session");

    const login = await expectJsonOrEmpty(await exchange("2026.10.2"), 200);
    equal(typeof consumed(), "string");
    ok(session() !== "previous-session", "successful login did not rotate the device session");
    await expectJsonOrEmpty(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${login.access_token}` } }), 200);
    await expectJsonOrEmpty(await exchange("2026.10.2"), 401);
  });

  await check("email login reuses only a delivered code with attempts remaining", async () => {
    const f = fixture(), address = "owner@example.test";
    f.env.MAIL_WEBHOOK_URL = "https://mail.runtime.test/send";
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data) VALUES('email-login-factor',?,1,1,?)", USER, JSON.stringify({ email: address }));
    const started = Promise.withResolvers(), release = Promise.withResolvers();
    let calls = 0, deliveryStatus = 503;
    const send = () => request(f, "/two-factor/send-email-login", { email: address, masterPasswordHash: "hash" }, "POST", false);
    const code = () => sql.exec("SELECT ready, attempts FROM verification_codes WHERE user_id=? AND purpose='email-login'", USER).one();
    const mockMail = async input => {
      equal(new URL(input.url).hostname, "mail.runtime.test");
      if (++calls === 1) {
        started.resolve();
        await release.promise;
      }
      return new Response("fixture provider", { status: deliveryStatus });
    };
    await withFetchMock(mockMail, async () => {
      const first = send();
      try {
        await Promise.race([started.promise, first.then(() => { throw new Error("verification delivery did not start"); })]);
        equal(code().ready, 0);
        await expectJsonOrEmpty(await send(), 429);
        release.resolve();
        await expectJsonOrEmpty(await first, 503);
        equal(calls, 1);
        equal(sql.exec("SELECT count(*) AS n FROM verification_codes").one().n, 0);

        deliveryStatus = 200;
        await expectJsonOrEmpty(await send(), 200);
        equal(code().ready, 1);
        await expectJsonOrEmpty(await send(), 200);
        equal(calls, 2);
        sql.exec("UPDATE verification_codes SET attempts=5 WHERE user_id=? AND purpose='email-login'", USER);
        await expectJsonOrEmpty(await send(), 429);
        equal(calls, 2);
        equal(code().attempts, 5);
      } finally {
        release.resolve();
        await first;
      }
    });
  });

  await check("client event aliases return an empty successful body without weakening session checks", async () => {
    const f = fixture();
    for (const path of ["/events/collect", "/api/events/collect"]) {
      const response = await request(f, path, [{ type: 1000, date: "2026-11-18T00:00:00Z" }]);
      equal(response.status, 200); equal(await response.text(), "");
      await expectJsonOrEmpty(await request(f, path, [], "POST", false), 401);
    }
  });

  await check("security-stamp publishes one logout only after its database commit and none after failure", async () => {
    for (const fail of [true, false]) {
      const f = fixture(), messages = [];
      f.env.notifydo = new DurableObjectNamespace(async req => {
        equal(new URL(req.url).pathname, "/internal/fanout");
        const message = await req.json(); equal(message.logout, true); messages.push(message);
        equal(sql.exec("SELECT COUNT(*) AS n FROM devices WHERE user_id=?", USER).one().n, 0, "logout preceded its database commit");
        return new Response('{"sent":1}', { headers: { "Content-Type": "application/json" } });
      });
      f.db.failBatch = fail;
      await expectJsonOrEmpty(await request(f, "/api/accounts/security-stamp", { masterPasswordHash: "hash" }), fail ? 500 : 200);
      equal(messages.length, fail ? 0 : 1, "logout notification count");
      equal(sql.exec("SELECT security_stamp FROM users WHERE id=?", USER).one().security_stamp === "owner-stamp", fail);
    }
  });

  await check("trailing slash normalization preserves JSON, query strings and streamed request bodies without heavydo", async () => {
    const f = fixture(); f.env.HEAVY_DO_ENABLED = "false";
    await expectJsonOrEmpty(await f.fetch("/api/config///"), 200);
    const sync = await expectJsonOrEmpty(await f.fetch("/api/sync///?excludeDomains=true", { headers: await headers() }), 200);
    equal(sync.policies.length, 0); equal(sync.policiesNew.length, 0); equal(sync.domains, null, "normalized path lost its query");
    const folder = await expectJsonOrEmpty(await request(f, "/api/folders///?keep=a%2Fb", { name: "2.streamed" }), 200);
    const bytes = new TextEncoder().encode(JSON.stringify({ name: "2.after-stream" })); let offset = 0;
    const body = new ReadableStream({ pull(controller) { if (offset === bytes.length) { controller.close(); return; } controller.enqueue(bytes.slice(offset, ++offset)); } });
    await expectJsonOrEmpty(await f.fetch(`/api/folders/${folder.id}///?keep=a%2Fb`, { method: "POST", headers: await headers(), body }), 200);
    equal(sql.exec("SELECT name FROM folders WHERE id=?", folder.id).one().name, "2.after-stream");
    // An absent auth-request response is a harmless query-bearing lookup.
    const lookup = await f.fetch("/api/auth-requests/not-present/response///?code=a%2Fb");
    equal(lookup.status, 400);
  });

  const withIcon = async (upstream, run) => {
    const captured = [];
    await withFetchMock(async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init); captured.push(req.url);
      equal(req.url, "https://vault.bitwarden.com/icons/example.test/icon.png", "fixed icon upstream");
      return upstream();
    }, () => run(captured));
  };
  const miss = async response => { equal(response.status, 404); equal(response.headers.get("cache-control"), "public, max-age=300"); equal(await response.text(), ""); };

  await check("icon wildcard aliases serve only fixed-upstream raster content and preserve cache policy", async () => {
    const f = fixture();
    await withIcon(() => new Response(new Uint8Array([137, 80, 78, 71]), { headers: { "Content-Type": "IMAGE/PNG; charset=binary" } }), async captured => {
      for (const path of ["/icons/example.test", "/icons/example.test/icon.png", "/icons/example.test/icon.png///"]) {
        const response = await f.fetch(path); equal(response.status, 200); equal(response.headers.get("cache-control"), "public, max-age=604800, immutable");
        equal([...new Uint8Array(await response.arrayBuffer())].join(","), "137,80,78,71");
      }
      equal(captured.length, 3);
      for (const path of ["/icons/bad%40example.test/icon.png", "/icons/example.test/unexpected", "/icons/-bad.test"]) await miss(await f.fetch(path));
      f.env.DISABLE_ICON_DOWNLOAD = "true"; await miss(await f.fetch("/icons/example.test")); equal(captured.length, 3);
    });
  });

  await check("icon misses, redirects and active or unknown formats never become long-lived successful content", async () => {
    const f = fixture();
    for (const [status, kind] of [[404, "text/html"], [500, "image/png"], [302, "image/png"], [200, "image/svg+xml"], [200, "text/html"], [200, "image/unknown"], [200, ""]]) {
      await withIcon(() => new Response("untrusted upstream", { status, headers: kind ? { "Content-Type": kind } : {} }), async () => miss(await f.fetch("/icons/example.test/icon.png")));
    }
    await withIcon(() => new Response(new Uint8Array([1]), { headers: { "Content-Type": "image/png", "Content-Length": String(5 * 1024 * 1024 + 1) } }), async () => miss(await f.fetch("/icons/example.test")));
  });

  await check("icons without Content-Length stop reading when their streamed body exceeds five MiB", async () => {
    const f = fixture(); let pulled = 0;
    await withIcon(() => new Response(new ReadableStream({ pull(controller) {
      if (++pulled > 32) { controller.close(); return; } controller.enqueue(new Uint8Array(1024 * 1024));
    } }), { headers: { "Content-Type": "image/png" } }), async () => {
      await miss(await f.fetch("/icons/example.test")); ok(pulled < 12, `Oversized icon consumed ${pulled} chunks`);
    });
  });

  const seedCredential = (id, user, usage, slot) => sql.exec("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,created_at,updated_at) VALUES(?,?,?,?,?,'public',?,'old','old')", id, user, slot, id, `wire-${id}`, usage);
  const seed2fa = () => {
    const f = fixture(); seedCredential("route-2fa-one", USER, "2fa", 1); seedCredential("route-2fa-two", USER, "2fa", 2);
    seedCredential("route-passkey", USER, "login", 3); seedCredential("route-other", "other-owner", "2fa", 1);
    sql.exec("UPDATE users SET two_factor_recovery_code='existing-recovery' WHERE id=?", USER);
    for (const type of [5, 7]) sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,?,1,'{}',0)", `route-factor-${type}`, USER, type);
    for (const purpose of ["register.2fa", "assert.2fa", "assert.login"]) sql.exec("INSERT INTO webauthn_challenges(id,challenge,purpose,user_id,rp_id,origin,expires_at) VALUES(?,?,?,?, 'vault.test','https://vault.test','2099-01-01T00:00:00Z')", purpose, purpose, purpose, USER);
    return f;
  };
  const proof = async f => (await expectJsonOrEmpty(await request(f, "/api/two-factor/get-webauthn", { masterPasswordHash: "hash" }), 200)).userVerificationToken;
  const clear = (f, token) => request(f, "/api/two-factor/webauthn/all", { userVerificationToken: token }, "DELETE");
  const state = () => snapshotTables(sql, ["users", "devices", "webauthn_credentials", "webauthn_challenges", "two_factors"]);
  const isClear = statements => statements.some(s => s.sql.includes("DELETE FROM webauthn_credentials") && s.sql.includes("credential_use='2fa'"));

  await check("dedicated WebAuthn clear requires the matching purpose proof and preserves login passkeys", async () => {
    const f = seed2fa(), token = await proof(f), before = state();
    await expectJsonOrEmpty(await request(f, "/api/two-factor/get-webauthn", { userVerificationToken: token }), 400); equal(state(), before);
    await expectJsonOrEmpty(await request(f, "/api/two-factor/webauthn/all", { masterPasswordHash: "hash" }, "DELETE"), 400); equal(state(), before);
    const totp = await expectJsonOrEmpty(await request(f, "/api/two-factor/get-authenticator", { masterPasswordHash: "hash" }), 200);
    await expectJsonOrEmpty(await clear(f, totp.userVerificationToken), 401); equal(state(), before);
    const result = await expectJsonOrEmpty(await clear(f, token), 200); equal(result.enabled, false); equal(result.keys.length, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id=? AND credential_use='2fa'", USER).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE credential_use='login'").one().n, 1);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id='other-owner'").one().n, 1);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_challenges").one().n, 1);
    equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=?", USER).one().n, 0);
    equal(sql.exec("SELECT two_factor_recovery_code FROM users WHERE id=?", USER).one().two_factor_recovery_code, null);
    const cleared = state(); await expectJsonOrEmpty(await clear(f, token), 400); equal(state(), cleared);
  });

  await check("WebAuthn bulk clear rejects concurrent changes to credentials, account or session", async () => {
    for (const mode of ["counter", "key", "addition", "session", "account"]) {
      const f = seed2fa(), token = await proof(f);
      let expected;
      const reached = f.db.beforeNextBatch(isClear, () => {
        if (mode === "addition") seedCredential("concurrent", USER, "2fa", 4);
        else if (mode === "session") sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
        else if (mode === "account") sql.exec("UPDATE users SET key='concurrent-wrapper' WHERE id=?", USER);
        else sql.exec(`UPDATE webauthn_credentials SET ${mode === "counter" ? "sign_count=sign_count+1" : "public_key='concurrent'"} WHERE id='route-2fa-one'`);
        expected = state();
      });
      await expectJsonOrEmpty(await clear(f, token), 409);
      ok(reached(), "fixture missed the WebAuthn clear");
      equal(state(), expected);
    }
  });

  await check("WebAuthn bulk clear rolls back late recovery failures and retains independent factors", async () => {
    let f = seed2fa(), token = await proof(f);
    sql.exec("CREATE TRIGGER route_clear_failure BEFORE UPDATE OF two_factor_recovery_code ON users BEGIN SELECT RAISE(ABORT,'injected clear failure'); END");
    const before = state(); await expectJsonOrEmpty(await clear(f, token), 500); equal(state(), before);
    f = seed2fa(); token = await proof(f);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('route-email',?,1,1,'{}',0)", USER);
    await expectJsonOrEmpty(await clear(f, token), 200); equal(sql.exec("SELECT two_factor_recovery_code FROM users WHERE id=?", USER).one().two_factor_recovery_code, "existing-recovery");
  });

  await check("WebAuthn collection PUT updates only the passkey identified by a valid RSA assertion", async () => {
    const f = fixture(), encoder = new TextEncoder();
    const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey), n = fromBase64Url(jwk.n), e = fromBase64Url(jwk.e);
    const cborBytes = bytes => bytes.length < 24 ? [0x40 + bytes.length, ...bytes] : bytes.length < 256 ? [0x58, bytes.length, ...bytes] : [0x59, bytes.length >> 8, bytes.length & 255, ...bytes];
    const cose = new Uint8Array([0xa4, 1, 3, 3, 0x39, 1, 0, 0x20, ...cborBytes(n), 0x21, ...cborBytes(e)]);
    const id = toBase64Url(encoder.encode("route-assertion-key"));
    const otherId = toBase64Url(encoder.encode("other-route-assertion-key"));
    seedCredential("route-rsa", USER, "login", 1);
    seedCredential("route-other-rsa", "other-owner", "login", 1);
    sql.exec("UPDATE webauthn_credentials SET credential_id=?,public_key=? WHERE id='route-rsa'", id, toBase64Url(cose));
    sql.exec("UPDATE webauthn_credentials SET credential_id=?,public_key=? WHERE id='route-other-rsa'", otherId, toBase64Url(cose));
    const issued = await expectJsonOrEmpty(await request(f, "/api/webauthn/assertion-options", { masterPasswordHash: "hash" }), 200);
    const client = encoder.encode(JSON.stringify({ type: "webauthn.get", challenge: issued.options.challenge, origin: "https://vault.test", crossOrigin: false }));
    const auth = new Uint8Array(37); auth.set(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode("vault.test")))); auth[32] = 5; new DataView(auth.buffer).setUint32(33, 1, false);
    const signed = new Uint8Array(auth.length + 32); signed.set(auth); signed.set(new Uint8Array(await crypto.subtle.digest("SHA-256", client)), auth.length);
    const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, signed));
    const assertion = { clientDataJSON: toBase64Url(client), authenticatorData: toBase64Url(auth), signature: toBase64Url(signature) };
    const body = { token: issued.token, name: "Updated passkey", encryptedPublicKey: "2.updated-public", encryptedUserKey: "2.updated-user", encryptedPrivateKey: "2.updated-private",
      deviceResponse: { rawId: id, response: assertion } };
    const put = (payload, authorized) => request(f, "/api/webauthn", payload, "PUT", authorized);
    const before = state();
    await expectJsonOrEmpty(await put(body, false), 401);
    await expectJsonOrEmpty(await put({ ...body, deviceResponse: { response: assertion } }), 400);
    await expectJsonOrEmpty(await put({ ...body, deviceResponse: { rawId: otherId, response: assertion } }), 404);
    equal(state(), before);
    const result = await expectJsonOrEmpty(await put(body), 200);
    equal(result.data.length, 1); equal(result.data[0].name, "Updated passkey"); equal(result.data[0].prfStatus, 0);
    const stored = sql.exec("SELECT * FROM webauthn_credentials WHERE id='route-rsa'").one();
    equal(stored.sign_count, 1); equal(stored.encrypted_public_key, body.encryptedPublicKey); equal(stored.encrypted_user_key, body.encryptedUserKey); equal(stored.encrypted_private_key, body.encryptedPrivateKey);
    const updated = state(); await expectJsonOrEmpty(await put(body), 400); equal(state(), updated);
  });
}
