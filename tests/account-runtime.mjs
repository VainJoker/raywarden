import { DurableObjectNamespace } from "./runtime-fixture.mjs";
import { equal, expectStatus } from "./runtime-assertions.mjs";
import { emailCodeHash, fixtureAccessSecret, oauthToken } from "./runtime-auth.mjs";

/** Account HTTP regressions against the compiled Worker and workerd SQLite. */
export async function runAccountCompatibility({ fixture, check, accessToken, USER, CIPHER, sql }) {
  const id = "0123456789abcdef0123456789abcdef";
  const oldId = "00000000-0000-4000-8000-000000000099";
  const kdf = { kdfType: 0, iterations: 600000, memory: null, parallelism: null };
  const signature = { signatureAlgorithm: "ed25519", wrappedSigningKey: "7.wrapped-signing", verifyingKey: "verifying-key" };
  const keys = () => ({
    userKeyEncryptedAccountPrivateKey: "7.wrapped-private", accountPublicKey: "public",
    publicKeyEncryptionKeyPair: { publicKey: "public", wrappedPrivateKey: "7.wrapped-private", signedPublicKey: "signed-public" },
    signatureKeyPair: { ...signature }, securityState: { securityState: "encrypted-security-state", securityVersion: 2 },
  });
  const json = async (f, path, body, bearer, method = "POST", extraHeaders = {}) => f.fetch(path, {
    method, headers: { "Content-Type": "application/json", ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}), ...extraHeaders },
    body: JSON.stringify(body),
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

  await check("protected account deletion rejects stale sessions and keeps the OTP reusable on failed writes", async () => {
    for (const change of ["nonce", "stamp", "verifier", "delete failure"]) {
      const f = fixture(), bearer = await accessToken();
      await readyEmailCode(f, "owner@example.test", "protected-action");
      const previous = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
      const batch = f.db.batch.bind(f.db);
      let reached = false;
      f.db.batch = async statements => {
        if (!reached && statements.some(statement => statement.sql.startsWith("DELETE FROM users WHERE id = "))) {
          reached = true;
          if (change === "nonce") sql.exec("UPDATE devices SET session_token='next' WHERE user_id=? AND device_id='device'", USER);
          else if (change === "stamp") sql.exec("UPDATE users SET security_stamp='next' WHERE id=?", USER);
          else if (change === "verifier") sql.exec("UPDATE users SET master_password_hash='fresh' WHERE id=?", USER);
          else sql.exec("CREATE TRIGGER protect_delete_failure BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT, 'fixture deletion denied'); END;");
        }
        return batch(statements);
      };
      const body = { otp: "123456" };
      await expectStatus(await json(f, "/api/accounts/delete", body, bearer), change === "delete failure" ? 500 : 409);
      equal(reached, true);
      equal(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at, previous, change);
      const proof = sql.exec("SELECT attempts,consumed_at FROM verification_codes WHERE id='email-runtime'").one();
      equal(proof.attempts, 0, change); equal(proof.consumed_at, null, change);
      if (change === "delete failure") {
        sql.exec("DROP TRIGGER protect_delete_failure");
        await expectStatus(await json(f, "/api/accounts/delete", body, bearer), 200);
      }
    }
  });

  await check("factor disable does not remove a newly replaced provider or consume its authorization", async () => {
    const f = fixture();
    await readyEmailCode(f, "owner@example.test", "protected-action");
    sql.exec("INSERT INTO two_factors VALUES('email-factor',?,1,1,?,0)", USER, JSON.stringify({ email: "owner@example.test" }));
    const batch = f.db.batch.bind(f.db);
    let reached = false;
    f.db.batch = async statements => {
      if (!reached && statements.some(statement => statement.sql.startsWith("DELETE FROM two_factors WHERE user_id="))) {
        reached = true;
        sql.exec("UPDATE two_factors SET id='replacement' WHERE id='email-factor'");
      }
      return batch(statements);
    };
    await expectStatus(await json(f, "/api/two-factor/disable", { type: 1, otp: "123456" }, await accessToken()), 409);
    equal(reached, true);
    equal(sql.exec("SELECT id FROM two_factors WHERE user_id=? AND provider_type=1", USER).one().id, "replacement");
    const proof = sql.exec("SELECT attempts,consumed_at FROM verification_codes WHERE id='email-runtime'").one();
    equal(proof.attempts, 0); equal(proof.consumed_at, null);
  });

  await check("both account deletion routes send logout and unregister captured push devices only after commit", async () => {
    for (const recovery of [false, true]) {
      for (const fail of [true, false]) {
        const f = fixture(), effects = [];
        const owners = () => sql.exec("SELECT COUNT(*) AS n FROM users WHERE id=?", USER).one().n;
        sql.exec("UPDATE devices SET push_id='fixture-push',push_token='fixture-mobile-token' WHERE user_id=?", USER);
        Object.assign(f.env, {
          MAIL_WEBHOOK_URL: "https://deletion-mail.runtime.test/verify",
          PUSH_ENABLED: "true",
          PUSH_INSTALLATION_ID: "fixture-installation",
          PUSH_INSTALLATION_KEY: "fixture-installation-key",
          PUSH_IDENTITY_URI: "https://deletion-push.runtime.test",
          PUSH_RELAY_URI: "https://deletion-push.runtime.test",
        });
        f.env.notifydo = new DurableObjectNamespace(async request => {
          const update = await request.json();
          equal(owners(), 0, "WebSocket logout precedes deletion");
          equal(update.selector.user_id, USER);
          equal(update.logout, true);
          effects.push("logout");
          return new Response('{"sent":1}');
        });

        let code;
        const fetch = globalThis.fetch;
        globalThis.fetch = async input => {
          const request = input instanceof Request ? input : new Request(input);
          const url = new URL(request.url);
          equal(request.redirect, "manual", "credential-bearing notification redirect policy");
          if (url.hostname === "deletion-mail.runtime.test") {
            const message = await request.json();
            equal(message.purpose, "delete-recover");
            code = message.text.split("\n\n")[1];
            return Response.json({});
          }
          equal(url.hostname, "deletion-push.runtime.test");
          equal(owners(), 0, "push relay called before deletion");
          if (url.pathname === "/connect/token") {
            return Response.json({ access_token: "fixture-push-access", expires_in: 300 });
          }
          effects.push(url.pathname);
          if (url.pathname === "/push/send") {
            const update = await request.json();
            equal(update.type, 11);
            equal(update.userId, USER);
            equal(update.deviceId, recovery ? null : "fixture-push");
          }
          return Response.json({});
        };
        try {
          if (recovery) {
            await expectStatus(await json(f, "/api/accounts/delete-recover", { email: "owner@example.test" }), 200);
            equal(typeof code, "string", "recovery mail delivered");
          }
          if (fail) {
            sql.exec("CREATE TRIGGER reject_account_deletion BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT, 'fixture deletion failure'); END");
          }
          const response = recovery
            ? await json(f, "/api/accounts/delete-recover-token", { userId: USER, token: code })
            : await json(f, "/api/accounts/delete", { masterPasswordHash: "hash" }, await accessToken());
          await expectStatus(response, fail ? 500 : 200);
          equal(owners(), fail ? 1 : 0);
          equal(effects.join(","), fail ? "" : "logout,/push/send,/push/delete/fixture-push");
          if (recovery && fail) {
            const proof = sql.exec("SELECT attempts, consumed_at FROM verification_codes WHERE user_id=? AND purpose='delete-recover'", USER).one();
            equal(proof.attempts, 0);
            equal(proof.consumed_at, null);
            sql.exec("DROP TRIGGER reject_account_deletion");
            await expectStatus(await json(f, "/api/accounts/delete-recover-token", { userId: USER, token: code }), 200);
            equal(owners(), 0);
            equal(effects.join(","), "logout,/push/send,/push/delete/fixture-push");
            await expectStatus(await json(f, "/api/accounts/delete-recover-token", { userId: USER, token: code }), 404);
          }
        } finally {
          globalThis.fetch = fetch;
        }
      }
    }
  });

  await check("email confirmation and two-factor enrollment preserve valid proofs on failed writes", async () => {
    for (const purpose of ["verify-email", "email-setup"]) {
      const f = fixture(), enrollment = purpose === "email-setup";
      await readyEmailCode(f, "owner@example.test", purpose, enrollment ? "session" : "");
      const path = enrollment ? "/api/two-factor/email" : "/api/accounts/verify-email-token";
      const body = enrollment ? { masterPasswordHash: "hash", token: "123456" } : { userId: USER, token: "123456" };
      const bearer = enrollment ? await accessToken() : undefined;
      const write = enrollment ? "INSERT ON two_factors" : "UPDATE OF is_email_verified ON users";
      sql.exec(`CREATE TRIGGER reject_mailbox_mutation BEFORE ${write} BEGIN SELECT RAISE(ABORT, 'fixture mailbox failure'); END`);
      await expectStatus(await json(f, path, body, bearer), 500);
      const proof = sql.exec("SELECT attempts, consumed_at FROM verification_codes WHERE id='email-runtime'").one();
      equal(proof.attempts, 0);
      equal(proof.consumed_at, null);
      sql.exec("DROP TRIGGER reject_mailbox_mutation");
      await expectStatus(await json(f, path, body, bearer), 200);
      if (enrollment) {
        equal(sql.exec("SELECT is_enabled FROM two_factors WHERE user_id=? AND provider_type=1", USER).one().is_enabled, 1);
      } else {
        equal(sql.exec("SELECT is_email_verified FROM users WHERE id=?", USER).one().is_email_verified, 1);
      }
      await expectStatus(await json(f, path, body, bearer), 400);
    }
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
    const profile = await (await expectStatus(await f.fetch("/api/accounts/profile", auth), 200)).json();
    equal(profile.accountKeys.securityState.securityVersion, 2);
    const publicKeys = await (await expectStatus(await f.fetch(`/api/users/${row.id}/keys`, auth), 200)).json();
    equal(publicKeys.verifyingKey, "verifying-key"); equal(publicKeys.signedPublicKey, "signed-public");
    const sync = await (await expectStatus(await f.fetch("/api/sync?excludeDomains=true", auth), 200)).json();
    equal(sync.profile.accountKeys.signatureKeyPair.verifyingKey, "verifying-key");
    equal(sync.userDecryption.userKeyId, id);
    equal(sync.userDecryption.masterPasswordUnlock.containedKeyId, id);
  });

  await check("V2 initial key material is conditional and cannot overwrite an established pair", async () => {
    const f = fixture();
    sql.exec("UPDATE users SET private_key='',public_key='' WHERE id=?", USER);
    const body = { encryptedPrivateKey: "7.wrapped-private", publicKey: "public", userKeyId: id, accountKeys: keys() };
    const bearer = await accessToken();
    const response = await (await expectStatus(await json(f, "/api/accounts/keys", body, bearer), 200)).json();
    equal(response.accountKeys.securityState.securityVersion, 2);
    await expectStatus(await json(f, "/api/accounts/keys", body, bearer), 400);
    equal(sql.exec("SELECT user_key_id FROM users WHERE id=?", USER).one().user_key_id, id);
  });

  await check("client-version rejection follows successful credentials and uses the desktop boundary", async () => {
    const f = fixture();
    sql.exec("UPDATE users SET private_key='7.private',signed_public_key='signed',security_state='state',security_version=2,signature_key_pair=?,user_key_id=? WHERE id=?", JSON.stringify(signature), id, USER);
    await expectStatus(await login(f, "owner@example.test", "wrong-password", undefined), 401);
    const missing = await (await expectStatus(await login(f, "owner@example.test", "hash", undefined), 400)).json();
    equal(missing.error, "version_header_missing");
    const desktop = await (await expectStatus(await login(f, "owner@example.test", "hash", "2026.10.1", "6"), 400)).json();
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
    const sync = await (await expectStatus(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${bearer}` } }), 200)).json();
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
    const tokens = await (await expectStatus(await login(f, "owner@example.test", "replacement-client-auth", "2026.10.1"), 200)).json();
    equal(tokens.AccountKeys.securityState.securityVersion, 2);
  });

  await check("an intervening encrypted edit makes rotation reject without partial account or cipher writes", async () => {
    const f = fixture();
    sql.exec("DELETE FROM attachments_pending; DELETE FROM attachments; DELETE FROM sends;");
    const original = sql.exec("SELECT key,security_stamp FROM users WHERE id=?", USER).one();
    const body = upgrade(null, [{ id: CIPHER, type: 1, name: "7.rotated-name", login: { password: "7.rotated-password" }, key: "7.rotated-item" }]);
    const batch = f.db.batch.bind(f.db);
    let changed = false;
    f.db.batch = async (statements) => {
      if (!changed && statements[0]?.sql.startsWith("UPDATE users SET key=")) {
        changed = true;
        sql.exec("UPDATE ciphers SET data=? WHERE id=?", '{"name":"concurrent-edit","login":{}}', CIPHER);
      }
      return batch(statements);
    };
    await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", body, await accessToken()), 409);
    equal(changed, true, "race fixture reached the transaction boundary");
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
    const snapshot = () => JSON.stringify({
      accounts: sql.exec("SELECT * FROM users ORDER BY id").toArray(),
      ciphers: sql.exec("SELECT * FROM ciphers ORDER BY id").toArray(),
      attachments: sql.exec("SELECT * FROM attachments ORDER BY id").toArray(),
      sessions: sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray(),
    });
    const bearer = await accessToken();
    await expectStatus(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 200);
    const before = snapshot(), batches = f.db.batches;
    const response = await expectStatus(await json(f, "/api/accounts/key-management/rotate-user-keys", body, bearer), 400);
    const error = await response.json();
    if (!error.message.includes("Rotated attachment does not belong to the cipher")) throw new Error(`Wrong rotation rejection: ${JSON.stringify(error)}`);
    equal(snapshot(), before, "rejected foreign material changed account, vault or session rows");
    equal(f.db.batches, batches, "foreign material reached the write transaction");

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
    const batch = f.db.batch.bind(f.db); let changed = false;
    f.db.batch = async (statements) => {
      if (!changed && statements.some(statement => statement.sql.startsWith("UPDATE users SET email="))) {
        changed = true;
        sql.exec("UPDATE users SET key='7.concurrent-upgrade',private_key='7.new-private',signed_public_key='signed',security_state='new-state',security_version=2,signature_key_pair=?,user_key_id=? WHERE id=?", JSON.stringify(signature), id, USER);
      }
      return batch(statements);
    };
    await expectStatus(await json(f, "/api/accounts/email", { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth", newEmail: recipient, key: "2.stale-wrapper", token: "123456" }, await accessToken()), 409);
    equal(changed, true, "email fixture reached guarded publication");
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
    const batch = f.db.batch.bind(f.db); let claimed = false;
    f.db.batch = async statements => {
      if (!claimed && statements.some(statement => statement.sql.startsWith("UPDATE users SET email="))) {
        claimed = true;
        sql.exec("UPDATE users SET email=? WHERE id='other-owner'", recipient);
      }
      return batch(statements);
    };
    const bearer = await accessToken();
    const body = { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth",
      newEmail: recipient, key: "2.rewrapped", token: "123456" };
    await expectStatus(await json(f, "/api/accounts/email", { ...body, token: "654321" }, bearer), 400);
    await expectStatus(await json(f, "/api/accounts/email", body, bearer), 409);
    equal(claimed, true);
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
    const data = await (await expectStatus(await f.fetch("/api/accounts/key-management/key-rotation-data", { headers: { Authorization: `Bearer ${bearer}` } }), 200)).json();
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
      const response = await (await expectStatus(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${bearer}`, ...(version ? { "Bitwarden-Client-Version": version } : {}) } }), 200)).json();
      equal(response.ciphers.some(cipher => cipher.id === "account-ssh"), included, `SSH filter for ${version ?? "missing header"}`);
      if (!response.ciphers.some(cipher => cipher.id === CIPHER)) throw new Error("SSH version filter removed an ordinary cipher");
    }
  });

}
