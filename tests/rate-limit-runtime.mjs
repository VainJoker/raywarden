/** Required binding selection and failure behavior through the actual SDK/WASM. */
export async function runRateLimitChecks({ fixture, check, sql, accessToken, notificationFetch, USER, SEND, FILE }) {
  const equal = (actual, expected, label = "value") => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const expect = async (response, code) => {
    const body = await response.text();
    equal(response.status, code, body);
    for (const secret of ["sensitive-provider-error", `verify-password:${USER}`, `send:${SEND}:`]) {
      equal(body.includes(secret), false, "response exposed rate-limit context");
    }
    return body ? JSON.parse(body) : null;
  };
  // worker::EnvBinding checks the constructor name before calling limit().
  class Ratelimit {
    constructor(mode) { this.mode = mode; this.keys = []; }
    async limit({ key }) {
      this.keys.push(key);
      if (this.mode === "throw") throw new Error(`sensitive-provider-error:${key}`);
      if (this.mode === "malformed") return { success: "not-a-boolean" };
      return { success: this.mode !== "deny" };
    }
  }
  const ip = "203.0.113.17";
  const owner = async () => ({ Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json", "cf-connecting-ip": ip });
  const verify = async (f, password = "hash") => f.fetch("/api/accounts/verify-password", {
    method: "POST", headers: await owner(), body: JSON.stringify({ masterPasswordHash: password }),
  });
  const sendAccessId = async f => (await expect(await f.fetch(`/api/sends/${SEND}`, { headers: await owner() }), 200)).accessId;
  const accessSend = (f, accessId, password) => f.fetch(`/api/sends/access/${accessId}`, {
    method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(password === undefined ? {} : { password }),
  });
  const credentials = () => JSON.stringify(Object.fromEntries(["users", "devices"]
    .map(table => [table, sql.exec(`SELECT * FROM ${table} ORDER BY rowid`).toArray()])));

  await check("real SDK login and Send bindings independently enforce provider denials as HTTP 429", async () => {
    for (const [loginMode, sendMode, loginCode, sendCode] of [["allow", "deny", 200, 429], ["deny", "allow", 429, 200]]) {
      const f = fixture(), login = new Ratelimit(loginMode), send = new Ratelimit(sendMode);
      f.env.LOGIN_RATE_LIMITER = login; f.env.SEND_ACCESS_RATE_LIMITER = send;
      const accessId = await sendAccessId(f), before = credentials();
      await expect(await verify(f), loginCode);
      await expect(await accessSend(f, accessId), sendCode);
      equal(login.keys.join(","), `verify-password:${USER}`, "protected action selected the wrong binding");
      equal(send.keys.join(","), `send:${SEND}:${ip}`, "anonymous Send selected the wrong binding");
      equal(credentials(), before, "limiter checks changed credentials or sessions");
      equal(sql.exec("SELECT access_count FROM sends WHERE id=?", SEND).one().access_count, 0, "file metadata consumed a download");
    }
  });

  await check("missing or wrong-type rate-limit bindings reject protected attempts while reads remain available", async () => {
    for (const mode of ["missing", "wrong-type"]) {
      const f = fixture();
      if (mode === "wrong-type") { f.env.LOGIN_RATE_LIMITER = {}; f.env.SEND_ACCESS_RATE_LIMITER = {}; }
      else { delete f.env.LOGIN_RATE_LIMITER; delete f.env.SEND_ACCESS_RATE_LIMITER; }
      const accessId = await sendAccessId(f), before = credentials();
      await expect(await verify(f, "wrong-password"), 503);
      await expect(await verify(f), 503);
      await expect(await accessSend(f, accessId), 503);
      await expect(await f.fetch("/api/alive"), 200);
      await expect(await f.fetch("/api/sync", { headers: await owner() }), 200);
      equal(credentials(), before, "missing limiter changed credentials or sessions");
    }
  });

  await check("rate-limit provider exceptions and malformed responses reject before protected work", async () => {
    for (const mode of ["throw", "malformed"]) {
      const f = fixture(), login = new Ratelimit(mode), send = new Ratelimit(mode);
      f.env.LOGIN_RATE_LIMITER = login; f.env.SEND_ACCESS_RATE_LIMITER = send;
      const accessId = await sendAccessId(f), before = credentials();
      await expect(await verify(f, "wrong-password"), 503);
      await expect(await verify(f), 503);
      await expect(await accessSend(f, accessId), 503);
      equal(login.keys.length, 2, "SDK did not call the failing login provider");
      equal(send.keys.length, 1, "SDK did not call the failing Send provider");
      equal(credentials(), before, "provider failure changed credentials or sessions");
    }
  });

  await check("password grants stop before authentication on limiter failures and recover when protection returns", async () => {
    const login = (f, password) => f.fetch("/identity/connect/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "device-type": "14", "Bitwarden-Client-Version": "2026.10.1", "cf-connecting-ip": ip },
      body: new URLSearchParams({ grant_type: "password", username: "owner@example.test", password, deviceIdentifier: "rate-password-client", deviceName: "Rate fixture", deviceType: "14" }) });
    for (const mode of ["missing", "wrong-type", "throw", "malformed", "deny"]) {
      const f = fixture(), before = credentials();
      if (mode === "missing") delete f.env.LOGIN_RATE_LIMITER;
      else f.env.LOGIN_RATE_LIMITER = mode === "wrong-type" ? {} : new Ratelimit(mode);
      for (const password of ["hash", "wrong-password"]) await expect(await login(f, password), mode === "deny" ? 429 : 503);
      equal(credentials(), before, "unprotected login changed account or sessions");
      f.env.LOGIN_RATE_LIMITER = new Ratelimit("allow");
      await expect(await login(f, "wrong-password"), 401);
      const tokens = await expect(await login(f, "hash"), 200);
      equal(typeof tokens.access_token, "string", "login did not recover with a working limiter");
    }
  });

  await check("password-protected Send guesses stop on dependency failures without consuming access", async () => {
    const encoder = new TextEncoder(), password = "client-send-password", salt = Uint8Array.from({ length: 16 }, (_, i) => i);
    const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const hash = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, material, 256))));
    for (const mode of ["missing", "throw", "malformed", "deny"]) {
      const f = fixture(), accessId = await sendAccessId(f);
      sql.exec("UPDATE sends SET password_hash=?,password_salt=?,password_iterations=100000 WHERE id=?", hash, btoa(String.fromCharCode(...salt)), SEND);
      if (mode === "missing") delete f.env.SEND_ACCESS_RATE_LIMITER;
      else f.env.SEND_ACCESS_RATE_LIMITER = new Ratelimit(mode);
      for (const supplied of [password, "wrong-password"]) await expect(await accessSend(f, accessId, supplied), mode === "deny" ? 429 : 503);
      equal(sql.exec("SELECT access_count FROM sends WHERE id=?", SEND).one().access_count, 0);
      f.env.SEND_ACCESS_RATE_LIMITER = new Ratelimit("allow");
      await expect(await accessSend(f, accessId, "wrong-password"), 400);
      await expect(await accessSend(f, accessId, password), 200);
    }
  });

  await check("Legacy Send routes and both token grants use the same limiter before password verification", async () => {
    const f = fixture(), login = new Ratelimit("allow"), send = new Ratelimit("deny");
    f.env.LOGIN_RATE_LIMITER = login; f.env.SEND_ACCESS_RATE_LIMITER = send;
    const accessId = await sendAccessId(f);
    sql.exec("UPDATE sends SET password_hash='protected',password_salt='salt',password_iterations=100000 WHERE id=?", SEND);
    const post = (path, type, body) => f.fetch(path, {
      method: "POST", headers: { "Content-Type": type, "cf-connecting-ip": ip }, body,
    });
    const json = "application/json", form = "application/x-www-form-urlencoded";
    const password = JSON.stringify({ password: "wrong-password" });
    const before = credentials();
    await expect(await post(`/api/sends/access/${accessId}`, json, password), 429);
    await expect(await post(`/api/sends/${SEND}/access/file/${FILE}`, json, password), 429);
    for (const grant_type of ["send_access", "access_token"]) {
      await expect(await post("/identity/connect/token", form,
        new URLSearchParams({ grant_type, send_id: accessId, password_hash_b64: "wrong-password" })), 429);
    }
    equal(send.keys.join(","), Array(4).fill(`send:${SEND}:${ip}`).join(","));
    equal(login.keys.length, 0);
    equal(sql.exec("SELECT access_count FROM sends WHERE id=?", SEND).one().access_count, 0);
    equal(credentials(), before, "denial advanced the owner revision");

    sql.exec("UPDATE sends SET password_hash=NULL,password_salt=NULL,password_iterations=NULL WHERE id=?", SEND);
    send.mode = "allow";
    const issued = await expect(await post("/identity/connect/token", form, new URLSearchParams({ grant_type: "send_access", send_id: accessId })), 200);
    send.mode = "deny";
    for (const path of ["/api/sends/access", `/api/sends/access/file/${FILE}`]) {
      await expect(await f.fetch(path, { method: "POST", headers: { Authorization: `Bearer ${issued.access_token}`, "cf-connecting-ip": ip } }), 200);
    }
    equal(send.keys.length, 5, "signed access was sent back through anonymous authorization");
    equal(login.keys.length, 0);
    equal(sql.exec("SELECT access_count FROM sends WHERE id=?", SEND).one().access_count, 1);
  });

  await check("NotifyDo distinguishes unavailable protection from a real connection limit", async () => {
    for (const mode of ["missing", "wrong-type", "throw", "malformed", "deny"]) {
      const f = fixture();
      if (mode === "missing") delete f.env.LOGIN_RATE_LIMITER;
      else f.env.LOGIN_RATE_LIMITER = mode === "wrong-type" ? {} : new Ratelimit(mode);
      const request = new Request(`https://vault.test/notifications/hub?access_token=${await accessToken()}`, { headers: { Upgrade: "websocket", "cf-connecting-ip": ip } });
      const response = await notificationFetch(f, request), body = await response.text();
      equal(response.status, mode === "deny" ? 429 : 503, body);
      equal(body.includes("sensitive-provider-error"), false, "notification error exposed provider context");
    }
  });
}
