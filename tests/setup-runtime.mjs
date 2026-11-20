import { openFixtureJwtKeys } from "./jwt-runtime.mjs";

/** Private account enrollment through compiled Rust, real migrations and SQLite. */
export async function runSetupCompatibility({ fixture, check, accessToken, sql }) {
  const EMAIL = "owner@example.test", TOKEN = "owner-setup-runtime-token-32-characters";
  const COOKIE = "raywarden_owner_setup";
  const aliases = ["/api/accounts/register", "/identity/accounts/register", "/identity/accounts/register/finish"];
  const equal = (actual, expected, label = "value") => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const ok = (value, label) => { if (!value) throw new Error(label); };
  const status = async (response, expected) => {
    if (response.status !== expected) throw new Error(`Expected HTTP ${expected}, received ${response.status}: ${await response.text()}`);
    return response;
  };
  const post = (f, path, body, headers = {}) => f.fetch(path, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
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
    const response = await status(await f.fetch("/api/config", { headers: cookie ? { Cookie: cookie } : {} }), 200);
    equal(response.headers.get("cache-control"), "no-store");
    return response.json();
  };
  const authorize = async (f, headers) => {
    const response = await status(await post(f, "/api/accounts/setup", { token: TOKEN }, headers), 200);
    equal(response.headers.get("cache-control"), "no-store");
    const set = response.headers.get("set-cookie");
    for (const part of [COOKIE + "=", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=600", "Secure"]) ok(set?.includes(part), `Missing cookie ${part}`);
    const body = await response.text();
    ok(!body.includes(TOKEN) && !body.includes(set.split(";")[0].split("=")[1]), "setup credentials leaked into JSON");
    return set.split(";")[0];
  };
  const sign = async (f, claims) => {
    const encode = value => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(value)))).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    const input = encode({ alg: "HS256", typ: "JWT" }) + "." + encode(claims);
    const { access_secret: secret } = await openFixtureJwtKeys(
      sql.exec("SELECT access_secret,refresh_secret FROM jwt_keys WHERE id='global'").one(), f.env.KEY_ENCRYPTION_KEY);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input)));
    return input + "." + btoa(String.fromCharCode(...mac)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  };

  await check("public registration stays closed on every alias until independent owner authorization", async () => {
    const f = empty();
    equal((await configuration(f)).settings.disableUserRegistration, true);
    for (const path of aliases) await status(await post(f, path, payload()), 401);
    await status(await post(f, "/identity/accounts/register/send-verification-email", { email: EMAIL }), 401);
    equal(count(), 0);
    await status(await post(f, "/api/accounts/setup", { token: TOKEN + "wrong" }), 401);
    equal((await configuration(f)).settings.disableUserRegistration, true);
    await status(await post(f, "/api/accounts/setup", { token: TOKEN }, { Origin: "https://unrelated.test" }), 401);
    equal(count(), 0);
  });

  await check("setup configuration rejects missing and glob account identities and malformed tokens", async () => {
    const f = empty();
    for (const invalid of ["", "*", "owner*@example.test", "owner@@example.test"]) {
      f.env.ALLOWED_EMAILS = invalid;
      await status(await post(f, "/api/accounts/setup", { token: TOKEN }), 400);
    }
    delete f.env.ALLOWED_EMAILS;
    await status(await post(f, "/api/accounts/setup", { token: TOKEN }), 400);
    f.env.ALLOWED_EMAILS = EMAIL;
    for (const invalid of ["short", "x".repeat(513), " " + TOKEN, TOKEN + "\n"]) {
      f.env.OWNER_SETUP_TOKEN = invalid;
      await status(await post(f, "/api/accounts/setup", { token: invalid }), 400);
    }
    equal(count(), 0);
  });

  await check("setup page is private, cookie scope is strict and ordinary token classes cannot authorize signup", async () => {
    const f = empty();
    const page = await status(await f.fetch("/setup"), 200);
    equal(page.headers.get("cache-control"), "no-store");
    ok(page.headers.get("content-security-policy")?.includes("frame-ancestors 'none'"), "setup page has no frame protection");
    const html = await page.text();
    ok(html.includes('type="password"') && html.includes('/#/signup'), "setup page does not use the real signup route");
    ok(!html.includes(TOKEN), "setup page contained the secret");
    const head = await status(await f.fetch("/setup", { method: "HEAD" }), 200); equal(await head.text(), "");
    const cookie = await authorize(f);
    equal((await configuration(f, cookie)).settings.disableUserRegistration, false);
    equal((await configuration(f)).settings.disableUserRegistration, true);
    const verification = await status(await post(f, "/identity/accounts/register/send-verification-email", { email: EMAIL }, { Cookie: cookie }), 200);
    equal(await verification.json(), "email-verification-not-required");
    await status(await post(f, aliases[0], payload("other@example.test"), { Cookie: cookie }), 401);
    const now = Math.floor(Date.now() / 1000);
    const proof = { sub: EMAIL, aud: "https://vault.test", purpose: "owner-setup", iat: now, nbf: now, exp: now + 600 };
    const invalid = [
      await accessToken(),
      await sign(f, { ...proof, purpose: "email-factor" }),
      await sign(f, { ...proof, aud: "https://other.test" }),
      await sign(f, { ...proof, sub: "other@example.test" }),
      await sign(f, { ...proof, iat: now - 600, nbf: now - 600, exp: now }),
    ];
    for (const token of invalid) {
      const badCookie = `${COOKIE}=${token}`;
      equal((await configuration(f, badCookie)).settings.disableUserRegistration, true);
      await status(await post(f, aliases[0], payload(), { Cookie: badCookie }), 401);
    }
    equal(count(), 0);
  });

  await check("each registration alias accepts only client-owned material and then clears bootstrap authorization", async () => {
    for (const path of aliases) {
      const f = empty(); f.env.ALLOWED_EMAILS = " Owner@Example.TEST ";
      const cookie = await authorize(f);
      const request = payload();
      const response = await status(await post(f, path, request, { Cookie: cookie }), 200);
      ok(response.headers.get("set-cookie")?.includes("Max-Age=0"), "successful signup kept setup cookie");
      const user = sql.exec("SELECT email,key,private_key,public_key FROM users").one();
      equal(user.email, EMAIL); equal(user.key, request.key);
      equal(user.private_key, request.userAsymmetricKeys.encryptedPrivateKey); equal(user.public_key, request.userAsymmetricKeys.publicKey);
      equal(count(), 1);
      equal((await configuration(f, cookie)).settings.disableUserRegistration, true);
      await status(await post(f, path, payload(), { Cookie: cookie }), 409);
      await status(await post(f, "/api/accounts/setup", { token: TOKEN }), 409);
      await status(await post(f, "/identity/accounts/register/send-verification-email", { email: EMAIL }, { Cookie: cookie }), 409);
      await status(await f.fetch("/setup"), 200);
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
    await status(await post(f, aliases[0], payload(), { Cookie: cookie }), 200);
    equal(count(), 1);
    f.env.ALLOWED_EMAILS = `second@example.test,${EMAIL},${EMAIL}`;
    equal((await configuration(f, cookie)).settings.disableUserRegistration, false);
    await status(await post(f, aliases[0], payload("outsider@example.test"), { Cookie: cookie }), 401);
    await status(await post(f, aliases[0], payload("second@example.test")), 401);
    await status(await post(f, aliases[0], payload("second@example.test"), { Cookie: cookie }), 200);
    equal(count(), 2);
    equal((await configuration(f, cookie)).settings.disableUserRegistration, true);
    await status(await post(f, "/api/accounts/setup", { token: TOKEN }), 409);
    // Expanding or restricting the list invalidates old cookie scope immediately.
    f.env.ALLOWED_EMAILS += ",third@example.test";
    equal((await configuration(f, cookie)).settings.disableUserRegistration, true);
    await status(await post(f, aliases[0], payload("third@example.test"), { Cookie: cookie }), 401);
    const updated = await authorize(f);
    await status(await post(f, aliases[0], payload("third@example.test"), { Cookie: updated }), 200);
    equal(count(), 3);
    f.env.ALLOWED_EMAILS = "third@example.test";
    const login = await status(await f.fetch("/identity/connect/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Bitwarden-Client-Version": "2026.11.0" },
      body: new URLSearchParams({ grant_type: "password", username: EMAIL, password: payload().masterPasswordHash,
        deviceIdentifier: "private-enrollment-login", deviceName: "Test Browser", deviceType: "14" }),
    }), 200);
    const bearer = (await login.json()).access_token;
    const profile = await status(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${bearer}` } }), 200);
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
    for (const response of responses) await status(response, 200);
    equal(count(), 2);
  });

  await check("unauthorized signup cannot consume a valid registration email code", async () => {
    const f = empty(); f.env.REQUIRE_EMAIL_VERIFICATION = "true";
    const encoder = new TextEncoder(), chunks = [];
    for (const part of [EMAIL, "registration", EMAIL, "", "123456"]) {
      const bytes = encoder.encode(part), length = new Uint8Array(8);
      new DataView(length.buffer).setBigUint64(0, BigInt(bytes.length), false); chunks.push(length, bytes);
    }
    const input = new Uint8Array(chunks.reduce((length, bytes) => length + bytes.length, 0));
    let offset = 0; for (const bytes of chunks) { input.set(bytes, offset); offset += bytes.length; }
    const { access_secret: secret } = await openFixtureJwtKeys(
      sql.exec("SELECT access_secret,refresh_secret FROM jwt_keys WHERE id='global'").one(), f.env.KEY_ENCRYPTION_KEY);
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const digest = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, input)), byte => byte.toString(16).padStart(2, "0")).join("");
    const now = Math.floor(Date.now() / 1000);
    sql.exec("INSERT INTO verification_codes(id,owner_key,purpose,recipient,context,code_hash,issued_at,expires_at,ready) VALUES('setup-email',?,'registration',?,'',?,?,?,1)", EMAIL, EMAIL, digest, now, now + 600);
    const request = { ...payload(), emailVerificationToken: "123456" };
    await status(await post(f, aliases[0], request), 401);
    const before = sql.exec("SELECT attempts,consumed_at FROM verification_codes WHERE id='setup-email'").one();
    equal(before.attempts, 0); equal(before.consumed_at, null);
    const cookie = await authorize(f);
    await status(await post(f, aliases[0], request, { Cookie: cookie }), 200);
    equal(count(), 1);
    ok(sql.exec("SELECT consumed_at FROM verification_codes WHERE id='setup-email'").one().consumed_at !== null, "authorized signup did not consume the email code");
  });

  await check("bootstrap checks database errors and permits insecure cookies only on local loopback", async () => {
    const f = empty(); f.env.DOMAIN = "http://127.0.0.2:8787";
    const local = await status(await post(f, "/api/accounts/setup", { token: TOKEN }), 200);
    ok(!local.headers.get("set-cookie").includes("; Secure"), "loopback bootstrap required HTTPS cookie");
    f.env.DOMAIN = "HTTPS://VAULT.TEST:443/";
    const cookie = await authorize(f, { Origin: "https://vault.test" });
    equal((await configuration(f, cookie)).settings.disableUserRegistration, false);
    f.env.DOMAIN = "https://other.test";
    equal((await configuration(f, cookie)).settings.disableUserRegistration, true);
    f.env.DOMAIN = "https://vault.test";
    sql.exec("DROP TABLE users");
    await status(await post(f, "/api/accounts/setup", { token: TOKEN }), 500);
  });
}
