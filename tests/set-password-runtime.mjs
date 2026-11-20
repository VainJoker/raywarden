/** First-password compatibility for existing authenticated empty accounts. */
export async function runSetPasswordCompatibility({ fixture, check, sql, accessToken, USER }) {
  const HASH = "set-password-client-authentication-hash", EMAIL = "owner@example.test";
  const equal = (actual, expected, label = "value") => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const expect = async (response, status) => {
    if (response.status !== status) throw new Error(`Expected HTTP ${status}, received ${response.status}: ${await response.text()}`);
    return response;
  };
  const owner = async () => ({ Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" });
  const post = async (f, body, headers) => f.fetch("/api/accounts/set-password", {
    method: "POST", headers: headers ?? await owner(), body: JSON.stringify(body),
  });
  const legacy = () => ({ masterPasswordHash: HASH, key: "2.new-wrapped-user", masterPasswordHint: "test hint" });
  const current = () => ({ masterPasswordAuthentication: { hash: HASH, salt: EMAIL,
    kdf: { kdfType: 0, iterations: 700000, memory: null, parallelism: null } },
    masterPasswordUnlock: { key: "2.current-wrapper", salt: EMAIL,
      kdf: { kdfType: 0, iterations: 700000, memory: null, parallelism: null } },
    userAsymmetricKeys: { publicKey: "public", encryptedPrivateKey: "2.initial-private" } });
  const state = () => JSON.stringify(Object.fromEntries(["users", "devices", "two_factors", "auth_requests", "webauthn_credentials", "ciphers"]
    .map(table => [table, sql.exec(`SELECT * FROM ${table} ORDER BY rowid`).toArray()])));
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
    await expect(await post(f, legacy(), { "Content-Type": "application/json" }), 401);
    await expect(await post(f, legacy()), 401); equal(state(), initial);
    f = fixture(); const existing = state();
    const rejected = await expect(await post(f, { accountKeys: {} }), 400);
    equal((await rejected.json()).message, "Invalid request: Account already initialized, cannot set password");
    equal(state(), existing);
    equal(sql.exec("SELECT COUNT(*) AS n FROM users").one().n, 2);
  });

  await check("an empty account cannot authenticate with an empty master password but a trusted session can initialize it", async () => {
    const f = emptyOwner(), before = state();
    for (const password of ["", " "]) {
      await expect(await login(f, password), 401);
      await expect(await f.fetch("/api/accounts/verify-password", { method: "POST", headers: await owner(), body: JSON.stringify({ masterPasswordHash: password }) }), 401);
      equal(state(), before);
    }
    const cipher = JSON.stringify(sql.exec("SELECT * FROM ciphers ORDER BY id").toArray()), unrelated = other();
    const prelogin = await (await expect(await f.fetch("/api/accounts/prelogin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: EMAIL }) }), 200)).json();
    await expect(await post(f, legacy()), 200); await assertVerifier();
    const user = sql.exec("SELECT * FROM users WHERE id=?", USER).one();
    equal(user.key, "2.new-wrapped-user"); equal(user.kdf_type, prelogin.kdf); equal(user.kdf_iterations, prelogin.kdfIterations);
    equal(user.password_iterations, 600000); equal(user.security_stamp, "owner-stamp"); equal(user.master_password_hint, "test hint");
    equal(JSON.stringify(sql.exec("SELECT * FROM ciphers ORDER BY id").toArray()), cipher);
    equal(other(), unrelated); equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=? AND provider_type=5", USER).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM auth_requests WHERE user_id=?", USER).one().n, 0);
    const prf = sql.exec("SELECT * FROM webauthn_credentials WHERE user_id=?", USER).one();
    equal(prf.prf_status, 1); equal(prf.encrypted_user_key, null); equal(prf.encrypted_private_key, null);
    await expect(await f.fetch("/api/accounts/profile", { headers: await owner() }), 200);
    // This reference flow deliberately retains the session for late key setup.
    await expect(await f.fetch("/api/accounts/keys", { method: "POST", headers: await owner(), body: JSON.stringify({ publicKey: "public", encryptedPrivateKey: "2.late-private" }) }), 200);
    await expect(await login(f, HASH), 200);
    const completed = state(); await expect(await post(f, legacy()), 400); equal(state(), completed);
  });

  await check("modern V1 initialization and explicit legacy Argon settings preserve stronger server costs", async () => {
    for (const format of ["legacy", "modern", "modern-keys-alias", "modern-v1-contained-id"]) {
      const modern = format !== "legacy";
      const f = emptyOwner(); sql.exec("UPDATE users SET password_iterations=1200000 WHERE id=?", USER);
      const body = modern ? current() : { ...legacy(), kdf: 1, kdfIterations: 3, keys: { publicKey: "public", encryptedPrivateKey: "2.initial-private" } };
      if (format === "modern-keys-alias") { body.keys = body.userAsymmetricKeys; delete body.userAsymmetricKeys; }
      if (format === "modern-v1-contained-id") body.masterPasswordUnlock.containedKeyId = "0123456789abcdef0123456789abcdef";
      await expect(await post(f, body), 200); await assertVerifier();
      const user = sql.exec("SELECT * FROM users WHERE id=?", USER).one();
      equal(user.public_key, "public"); equal(user.private_key, "2.initial-private"); equal(user.password_iterations, 1200000);
      equal(user.user_key_id, null, "optional V1 containedKeyId must not establish V2 identity");
      equal(user.kdf_type, modern ? 0 : 1); equal(user.kdf_iterations, modern ? 700000 : 3);
      equal(user.kdf_memory, modern ? null : 64); equal(user.kdf_parallelism, modern ? null : 4);
      await expect(await login(f, HASH), 200);
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
      const before = state(); await expect(await post(f, make()), 400); equal(state(), before);
    }
    const f = emptyOwner(); sql.exec("UPDATE users SET public_key='existing-public' WHERE id=?", USER);
    await expect(await post(f, legacy()), 200);
    equal(sql.exec("SELECT public_key FROM users WHERE id=?", USER).one().public_key, "existing-public");
  });

  await check("partial initialization, V2 state and revoked sessions cannot authorize first-password writes", async () => {
    for (const [column, value] of [["master_password_hash", "existing-hash"], ["private_key", "2.existing"], ["security_version", 2], ["signed_public_key", "signed"]]) {
      const f = emptyOwner(); sql.exec(`UPDATE users SET ${column}=? WHERE id=?`, value, USER);
      const before = state(); await expect(await post(f, legacy()), 400); equal(state(), before);
    }
    for (const [table, column, value] of [["devices", "session_token", "revoked"], ["users", "security_stamp", "revoked"]]) {
      const f = emptyOwner(); sql.exec(`UPDATE ${table} SET ${column}=? WHERE ${table === "users" ? "id" : "user_id"}=?`, value, USER);
      const before = state(); await expect(await post(f, legacy()), 401); equal(state(), before);
    }
  });

  await check("initialization fences concurrent credentials, KDF, envelope and device-session changes before any cleanup", async () => {
    const changes = [["users", "master_password_hash", "concurrent-hash"], ["users", "private_key", "2.concurrent-private"],
      ["users", "public_key", "concurrent-public"], ["users", "key", "concurrent-wrapper"],
      ["users", "password_salt", "concurrent-salt"], ["users", "password_iterations", 1200000],
      ["users", "security_stamp", "concurrent-stamp"], ["users", "security_version", 2],
      ["users", "kdf_type", 1], ["users", "kdf_iterations", 700000], ["users", "kdf_memory", 64],
      ["users", "kdf_parallelism", 4], ["devices", "session_token", "concurrent-nonce"]];
    for (const [table, column, value] of changes) {
      const f = emptyOwner(), batch = f.db.batch.bind(f.db); let reached = false, expected;
      f.db.batch = async writes => {
        if (!reached && isInitialization(writes)) {
          reached = true; sql.exec(`UPDATE ${table} SET ${column}=? WHERE ${table === "users" ? "id" : "user_id"}=?`, value, USER); expected = state();
        }
        return batch(writes);
      };
      await expect(await post(f, legacy()), 409); equal(reached, true); equal(state(), expected);
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
          await expect(await f.fetch("/api/accounts/keys", { method: "POST", headers: await owner(), body: JSON.stringify({ publicKey: "concurrent-identity", encryptedPrivateKey: "2.concurrent-private" }) }), 200);
          expected = state();
        }
        return batch(writes);
      };
      await expect(await post(f, current()), 409); equal(reached, true); equal(state(), expected);
    }
  });

  await check("late initialization cleanup failure rolls back password, wrapper, private keys and Remember", async () => {
    const f = emptyOwner(), before = state();
    sql.exec("CREATE TRIGGER initialization_failure BEFORE UPDATE ON webauthn_credentials BEGIN SELECT RAISE(ABORT,'injected initialization failure'); END;");
    await expect(await post(f, current()), 500); equal(state(), before);
  });
}
