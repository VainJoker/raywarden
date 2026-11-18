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
  const equal = (actual, expected, label = "value") => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const expectStatus = async (response, expected) => {
    if (response.status !== expected) throw new Error(`Expected HTTP ${expected}, received ${response.status}: ${await response.text()}`);
    return response;
  };
  const json = async (f, path, body, bearer, method = "POST", extraHeaders = {}) => f.fetch(path, {
    method, headers: { "Content-Type": "application/json", ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}), ...extraHeaders },
    body: JSON.stringify(body),
  });
  const login = (f, email, password, version, deviceType = "14") => f.fetch("/identity/connect/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "device-type": deviceType,
      ...(version ? { "Bitwarden-Client-Version": version } : {}) },
    body: new URLSearchParams({ grant_type: "password", username: email, password,
      deviceIdentifier: "account-runtime-login", deviceName: "Runtime Browser", deviceType: "14" }),
  });
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
  const readyEmailCode = async (recipient) => {
    const parts = [USER, "change-email", recipient, "", "123456"];
    const encode = new TextEncoder();
    const chunks = [];
    for (const part of parts) {
      const bytes = encode.encode(part), prefix = new Uint8Array(8);
      new DataView(prefix.buffer).setBigUint64(0, BigInt(bytes.length), false);
      chunks.push(prefix, bytes);
    }
    const bytes = new Uint8Array(chunks.reduce((n, part) => n + part.length, 0));
    let offset = 0; for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
    const secret = sql.exec("SELECT access_secret FROM jwt_keys WHERE id='global'").one().access_secret;
    const key = await crypto.subtle.importKey("raw", encode.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const digest = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes)), byte => byte.toString(16).padStart(2, "0")).join("");
    const now = Math.floor(Date.now() / 1000);
    sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,context,code_hash,security_stamp,session_token,issued_at,expires_at,ready) VALUES('email-runtime',?,?,'change-email',?,'',?,'owner-stamp','session',?,?,1)", USER, USER, recipient, digest, now, now + 600);
  };

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
    sql.exec("INSERT INTO ciphers(id,user_id,type,data,created_at,updated_at) VALUES(?,'other-owner',1,?,?,?)", foreignCipher, '{"name":"foreign-encrypted"}', date, date);
    sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size,akey,created_at,updated_at) VALUES(?,?,?,6,?,?,?)", foreignFile, foreignCipher, "foreign-file", "foreign-key", date, date);
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
      sessions: sql.exec("SELECT * FROM devices ORDER BY user_id,identifier").toArray(),
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
    equal(sql.exec("SELECT akey FROM attachments WHERE id=?", owned.id).one().akey, "7.rotated-own-key");
    equal(sql.exec("SELECT akey FROM attachments WHERE id=?", foreignFile).one().akey, "foreign-key");
  });

  await check("email credential commit rejects a same-stamp V2 upgrade and preserves remember state", async () => {
    const f = fixture(); const recipient = "new-owner@example.test";
    await readyEmailCode(recipient);
    sql.exec("INSERT INTO twofactor(uuid,user_uuid,atype,data) VALUES('email-remember',?,5,'{}')", USER);
    const batch = f.db.batch.bind(f.db); let changed = false;
    f.db.batch = async (statements) => {
      if (!changed && statements[0]?.sql.startsWith("UPDATE users SET email=")) {
        changed = true;
        sql.exec("UPDATE users SET key='7.concurrent-upgrade',private_key='7.new-private',signed_public_key='signed',security_state='new-state',security_version=2,signature_key_pair=?,user_key_id=? WHERE id=?", JSON.stringify(signature), id, USER);
      }
      return batch(statements);
    };
    await expectStatus(await json(f, "/api/accounts/email", { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth", newEmail: recipient, key: "2.stale-wrapper", token: "123456" }, await accessToken()), 409);
    equal(changed, true, "email fixture reached guarded publication");
    const user = sql.exec("SELECT email,key,security_stamp FROM users WHERE id=?", USER).one();
    equal(user.email, "owner@example.test"); equal(user.key, "7.concurrent-upgrade"); equal(user.security_stamp, "owner-stamp");
    equal(sql.exec("SELECT COUNT(*) AS n FROM twofactor WHERE user_uuid=? AND atype=5", USER).one().n, 1);
  });

  await check("password and email changes retag only a current PRF wrapper without replacing its ciphertext", async () => {
    for (const kind of ["password", "email"]) {
      const f = fixture(); seedPrf();
      const bearer = await accessToken(); const wrapper = `2.${kind}-rewrapped-user`;
      let path, body;
      if (kind === "email") {
        const recipient = "changed-owner@example.test"; await readyEmailCode(recipient);
        path = "/api/accounts/email";
        body = { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth", newEmail: recipient, key: wrapper, token: "123456" };
      } else {
        path = "/api/accounts/password";
        body = { masterPasswordHash: "hash", newMasterPasswordHash: "new-auth", key: wrapper };
      }
      await expectStatus(await json(f, path, body, bearer), 200);
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
      sql.exec("INSERT INTO ciphers(id,user_id,type,data,created_at,updated_at) VALUES(?,?,1,?,?,?)", cipher, USER, JSON.stringify({ name: "", data: blob }), "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z");
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
    sql.exec("INSERT INTO ciphers(id,user_id,type,data,created_at,updated_at) VALUES('account-ssh',?,5,?,?,?)", USER,
      JSON.stringify({ name: "2.encrypted-ssh", sshKey: { privateKey: "2.private", publicKey: "2.public", keyFingerprint: "2.fingerprint" } }), "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z");
    const bearer = await accessToken();
    for (const [version, included] of [[undefined, false], ["invalid", false], ["2024.11.9", false], ["2024.12.0", true], ["2026.11.0", true], ["2026.11.0-beta.1", false]]) {
      const response = await (await expectStatus(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${bearer}`, ...(version ? { "Bitwarden-Client-Version": version } : {}) } }), 200)).json();
      equal(response.ciphers.some(cipher => cipher.id === "account-ssh"), included, `SSH filter for ${version ?? "missing header"}`);
      if (!response.ciphers.some(cipher => cipher.id === CIPHER)) throw new Error("SSH version filter removed an ordinary cipher");
    }
  });

}
