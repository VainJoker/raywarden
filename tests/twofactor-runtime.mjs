// Actual authenticator HTTP handlers and native SQLite transactions. The test
// client computes its TOTP independently with WebCrypto HMAC-SHA1.
function equal(actual, expected, label = "value") {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
}
function ok(value, label) { if (!value) throw new Error(label); }

async function totp(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let accumulator = 0, bits = 0; const bytes = [];
  for (const char of secret.toUpperCase().replace(/=+$/, "")) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("Server returned an invalid base32 key");
    accumulator = (accumulator << 5) | value; bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 30000)), false);
  const key = await crypto.subtle.importKey("raw", new Uint8Array(bytes), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[digest.length - 1] & 15;
  const value = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(value % 1000000).padStart(6, "0");
}

export async function runTwoFactorCompatibility({ fixture, check, accessToken, USER, sql }) {
  async function request(f, path, body, bearer, method = "POST") {
    return f.fetch(path, { method, headers: { Authorization: `Bearer ${bearer ?? await accessToken()}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  }
  async function responseJson(response, status) {
    const text = await response.text();
    equal(response.status, status, text);
    try { return JSON.parse(text); } catch { throw new Error(`Non-JSON HTTP ${status}: ${text}`); }
  }
  const get = (f, bearer) => request(f, "/api/two-factor/get-authenticator", { masterPasswordHash: "hash" }, bearer).then(response => responseJson(response, 200));
  const activate = async (f, setup, bearer) => request(f, "/api/two-factor/authenticator", {
    key: setup.key, token: await totp(setup.key), userVerificationToken: setup.userVerificationToken,
  }, bearer);
  const disable = (f, setup, bearer) => request(f, "/api/two-factor/authenticator", {
    key: setup.key, type: 0, userVerificationToken: setup.userVerificationToken,
  }, bearer, "DELETE");
  const remember = () => sql.exec("INSERT INTO twofactor(uuid,user_uuid,atype,enabled,data,last_used) VALUES('totp-runtime-remember',?,5,1,'{}',0)", USER);
  const count = type => sql.exec("SELECT COUNT(*) AS n FROM twofactor WHERE user_uuid=? AND atype=?", USER, type).one().n;
  function shape(body, enabled) {
    equal(body.enabled, enabled); equal(body.authenticator.enabled, enabled);
    equal(body.authenticator.key, body.key); ok(typeof body.key === "string" && body.key.length > 0, "missing TOTP key");
  }

  await check("profile and sync agree on enabled login factors without counting Remember or internal records", async () => {
    for (const [type, enabled, expected] of [[0, 1, true], [1, 1, true], [7, 1, true], [5, 1, false], [0, 0, false], [1, 0, false], [7, 0, false], [1000, 1, false], [2, 1, true]]) {
      const f = fixture();
      const data = type === 1 ? JSON.stringify({ email: "factor@example.test" }) : type === 0 ? "JBSWY3DPEHPK3PXP" : "{}";
      sql.exec("INSERT INTO twofactor(uuid,user_uuid,atype,enabled,data,last_used) VALUES('status-factor',?,?,?,?,0)", USER, type, enabled, data);
      const headers = { Authorization: `Bearer ${await accessToken()}` };
      const profile = await responseJson(await f.fetch("/api/accounts/profile", { headers }), 200);
      const sync = await responseJson(await f.fetch("/api/sync?excludeDomains=true", { headers }), 200);
      equal(profile.twoFactorEnabled, expected, `profile factor ${type}/${enabled}`);
      equal(sync.profile.twoFactorEnabled, expected, `sync factor ${type}/${enabled}`);
    }
  });

  const emailFactor = address => sql.exec("INSERT INTO twofactor(uuid,user_uuid,atype,enabled,data,last_used) VALUES('email-runtime-factor',?,1,1,?,0)", USER, JSON.stringify({ email: address }));
  const emailProof = async (f, bearer) => responseJson(await request(f, "/api/two-factor/get-email", { masterPasswordHash: "hash" }, bearer), 200);

  await check("email action proofs keep their own purpose and provider-state binding across both handlers", async () => {
    const f = fixture(); emailFactor("first-factor@example.test"); remember();
    const proof = await emailProof(f); const setup = await get(f);
    await responseJson(await request(f, "/api/two-factor/email", { userVerificationToken: setup.userVerificationToken }, undefined, "DELETE"), 401);
    await responseJson(await request(f, "/api/two-factor/get-authenticator", { userVerificationToken: proof.userVerificationToken }), 400);
    equal(count(1), 1); equal(count(5), 1);
    sql.exec("UPDATE twofactor SET data=? WHERE user_uuid=? AND atype=1", JSON.stringify({ email: "new-factor@example.test" }), USER);
    await responseJson(await request(f, "/api/two-factor/disable", { type: 1, userVerificationToken: proof.userVerificationToken }), 401);
    equal(count(1), 1); equal(count(5), 1);
    const current = await emailProof(f);
    await responseJson(await request(f, "/api/two-factor/disable", { type: 1, userVerificationToken: current.userVerificationToken }), 200);
    equal(count(1), 0); equal(count(5), 0);
  });

  await check("a valid new session cannot reuse an email action proof but can mint its own", async () => {
    const f = fixture(); emailFactor("factor@example.test"); remember();
    const proof = await emailProof(f);
    sql.exec("UPDATE devices SET session_token='email-new-session' WHERE user_id=? AND identifier='device'", USER);
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
    const first = sql.exec("SELECT * FROM twofactor WHERE user_uuid=? AND atype=0", USER).one();
    ok(first.last_used > 0, "setup did not consume the accepted TOTP step");
    await responseJson(await activate(f, setup), 400);
    const current = await get(f); shape(current, true); equal(current.key, setup.key);
    const disabled = await responseJson(await disable(f, current), 200);
    equal(disabled.enabled, false); equal(disabled.type, 0); equal(count(0), 0);
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
    equal(sql.exec("SELECT data FROM twofactor WHERE user_uuid=? AND atype=0", USER).one().data, setup.key);
  });

  await check("a valid new session cannot reuse the previous session's TOTP proof", async () => {
    const f = fixture(); const setup = await get(f); remember();
    sql.exec("UPDATE devices SET session_token='new-session' WHERE user_id=? AND identifier='device'", USER);
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
      if (!changed && statements.some(statement => /^DELETE FROM twofactor WHERE uuid=/.test(statement.sql.trim()))) {
        changed = true;
        sql.exec("UPDATE twofactor SET last_used=last_used+1 WHERE user_uuid=? AND atype=0", USER);
      }
      return batch(statements);
    };
    await responseJson(await disable(f, current), 409);
    equal(changed, true, "delete did not reach the actual snapshot transaction");
    equal(count(0), 1); equal(count(5), 1, "failed configuration snapshot cleared Remember tokens");
  });
}
