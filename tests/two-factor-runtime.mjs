import { bearerJsonHeaders, equal, expectStatus, ok } from "./runtime-assertions.mjs";
import { oauthToken, totp } from "./runtime-auth.mjs";

// Actual authenticator HTTP handlers and native SQLite transactions. The test
// client computes its TOTP independently with WebCrypto HMAC-SHA1.
export async function runTwoFactorCompatibility({ fixture, check, accessToken, USER, sql }) {
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
