import { bearerJsonHeaders, equal, expectJsonOrEmpty as expect } from "./runtime-assertions.mjs";
import { emailCodeHash, fixtureAccessSecret } from "./runtime-auth.mjs";

/** Export authorization consumes scoped OTPs in the compiled Worker and SQLite. */
export async function runProtectedActionCompatibility({ fixture, check, sql, accessToken, USER }) {
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
        const failure = await expect(await request(), 503);
        equal(failure.code, 12);
        equal(failure.message, "Internal server error");
        equal(sql.exec("SELECT count(*) AS n FROM verification_codes").one().n, 0);
      }
      delivery = 200;
      await expect(await request(), 200);
      equal(calls, 3);
      equal(sql.exec("SELECT ready FROM verification_codes WHERE purpose='protected-action'").one().ready, 1);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  await check("export OTP verification consumes its proof through both aliases and prevents later reuse", async () => {
    for (const path of ["/api/accounts/verify-otp", "/accounts/verify-otp"]) {
      const f = fixture(); await seed(f);
      await expect(await post(f, path, { OTP: CODE }), 200);
      equal(row().consumed_at !== null, true, "successful export authorization left a reusable OTP");
      equal(row().attempts, 1);
      const consumed = JSON.stringify(row());
      await expect(await post(f), 400);
      await expect(await post(f, "/api/two-factor/get-authenticator"), 400);
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
      await expect(await post(f), 400); equal(JSON.stringify(row()), before, JSON.stringify(scope));
    }
    const f = fixture(); await seed(f);
    sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?, 'export-other-device','Browser',14,'other-session','old','old')", USER);
    const other = await accessToken({ device: "export-other-device", session_token: "other-session" });
    const before = JSON.stringify(row()); await expect(await post(f, undefined, undefined, other), 400);
    equal(JSON.stringify(row()), before, "another active session changed the proof");
    await expect(await f.fetch("/api/accounts/verify-otp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ otp: CODE }) }), 401);
    sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=? AND device_id='device'", USER);
    await expect(await post(f), 401); equal(JSON.stringify(row()), before, "revoked session changed the proof");
  });

  await check("wrong export OTP attempts remain bounded and expiry never consumes a valid-looking code", async () => {
    let f = fixture(); await seed(f);
    await expect(await post(f, undefined, { otp: "654321" }), 400);
    equal(row().attempts, 1); equal(row().consumed_at, null);
    await expect(await post(f), 200); equal(row().attempts, 2); equal(row().consumed_at !== null, true);
    f = fixture(); await seed(f);
    for (let attempt = 0; attempt < 5; attempt++) await expect(await post(f, undefined, { otp: "654321" }), 400);
    await expect(await post(f), 400); equal(row().attempts, 5); equal(row().consumed_at, null);
    f = fixture(); await seed(f, { expires: Math.floor(Date.now() / 1000) - 1 });
    await expect(await post(f), 400); equal(row().attempts, 0); equal(row().consumed_at, null);
  });

  await check("failed export proof consumption rolls back without returning authorization", async () => {
    const f = fixture(); await seed(f);
    sql.exec("CREATE TRIGGER export_consume_failure BEFORE UPDATE OF consumed_at ON verification_codes BEGIN SELECT RAISE(ABORT,'injected OTP consumption failure'); END");
    const before = JSON.stringify(row()); await expect(await post(f), 500); equal(JSON.stringify(row()), before);
    sql.exec("DROP TRIGGER export_consume_failure");
    await expect(await post(f), 200); equal(row().consumed_at !== null, true);
  });

  await check("other protected actions still consume independently issued OTPs before issuing management proofs", async () => {
    const f = fixture(); await seed(f);
    const result = await expect(await post(f, "/api/two-factor/get-authenticator"), 200);
    equal(typeof result.userVerificationToken, "string"); equal(row().consumed_at !== null, true);
    await expect(await post(f), 400);
  });
}
