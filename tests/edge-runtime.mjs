import { heavydo, notifydo } from "./index.js";
import { equal, ok, sameBytes } from "./runtime-assertions.mjs";
import { CIPHER, FILE, NOW, ORIGIN, USER, DurableObjectNamespace, accessToken, base64url, encoder, token } from "./runtime-fixture.mjs";

async function fanoutProof(body, claims = {}, secret) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(body)));
  const body_hash = Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
  const exp = Math.floor(Date.now() / 1000) + 30;
  return token({ scope: "notifications.internal", body_hash, exp, ...claims }, secret);
}
function fanoutRequest(signature, body) {
  return new Request("https://notify.test/internal/fanout", {
    method: "POST", body,
    headers: signature ? { "x-raywarden-notify-token": signature } : {},
  });
}
export async function runEdgeChecks({ fixture, check, state, setNotifyDo }) {
  await check("Rust entry, metadata and CORS", async () => {
    const f = fixture();
    let databaseLookups = 0, corsLookups = 0;
    Object.defineProperty(f.env, "DB", { get() { databaseLookups++; return f.db; } });
    Object.defineProperty(f.env, "CORS_ALLOWED_ORIGINS", { get() { corsLookups++; return ORIGIN; } });
    const response = await f.fetch("/api/alive", { headers: { Origin: ORIGIN } });
    equal(response.status, 200);
    JSON.parse(await response.text());
    equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    equal(databaseLookups, 1, "database binding lookups");
    equal(corsLookups, 1, "CORS configuration lookups");
  });
  await check("local requests skip the heavydo binding and leave unused bodies unread", async () => {
    const f = fixture(); f.env.HEAVY_DO_ENABLED = "true";
    let bindings = 0, pulls = 0;
    Object.defineProperty(f.env, "heavydo", { get() { bindings++; throw new Error("local request consulted heavydo"); } });
    const alive = await f.fetch("/api/alive///?keep=a%2Fb");
    equal(alive.status, 200); await alive.arrayBuffer();
    const body = new ReadableStream({ pull() { pulls++; throw new Error("unused request body was read"); } }, { highWaterMark: 0 });
    const missing = await f.fetch("/api/not-a-route///?keep=a%2Fb", { method: "POST", body });
    equal(missing.status, 404); await missing.arrayBuffer();
    equal(bindings, 0, "local requests must not resolve the heavydo binding");
    equal(pulls, 0, "routing an unused body must not consume it");
  });
  await check("heavydo selects token and registration shards without changing forwarded requests or CORS", async () => {
    const maximumPrefix = "grant_type=password&username=OWNER%40EXAMPLE.TEST&padding=";
    const cases = [
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=password&username=%20OWNER%40EXAMPLE.TEST%20&password=opaque", "heavy:9"],
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=client_credentials&client_id=%20USER.ALICE%20&client_secret=opaque", "heavy:0"],
      ...["/api/accounts/register", "/identity/accounts/register", "/identity/accounts/register/finish"].map(path =>
        [path, "application/json", '{"email":" OWNER@EXAMPLE.TEST ","preserve":"a b"}', "heavy:9"]),
      ["/identity/connect/token", "application/x-www-form-urlencoded", maximumPrefix + "x".repeat(65536 - maximumPrefix.length), "heavy:9"],
    ];
    for (const [path, contentType, text, shard] of cases) {
      const f = fixture(); f.env.HEAVY_DO_ENABLED = "true"; f.env.HEAVY_DO_SHARDS = "16";
      f.db.prepare = () => { throw new Error("offloaded request touched D1 before forwarding"); };
      let forwarded = 0;
      f.env.heavydo = new DurableObjectNamespace(async (request, name) => {
        forwarded++;
        equal(name, shard, "normalized identity selects the expected shard");
        equal(request.method, "POST"); equal(request.bodyUsed, false);
        const url = new URL(request.url);
        equal(url.pathname, path); equal(url.search, "?keep=a%2Fb&flag=two+words");
        equal(request.headers.get("Content-Type"), contentType);
        equal(await request.text(), text, "shard selection must preserve the complete original body");
        return new Response("offloaded", { status: 202, headers: { "Access-Control-Allow-Origin": ORIGIN, Vary: "X-Heavy-Fixture" } });
      });
      const bytes = encoder.encode(text); let offset = 0;
      const body = new ReadableStream({ pull(controller) {
        if (offset === bytes.length) { controller.close(); return; }
        const end = Math.min(offset + 4096, bytes.length);
        controller.enqueue(bytes.subarray(offset, end)); offset = end;
      } }, { highWaterMark: 0 });
      const response = await f.fetch(`${path}///?keep=a%2Fb&flag=two+words`, { method: "POST", body,
        headers: { "Content-Type": contentType, Origin: ORIGIN, "CF-Connecting-IP": "198.51.100.7" } });
      equal(response.status, 202); equal(await response.text(), "offloaded");
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
      equal(response.headers.get("Vary"), "X-Heavy-Fixture", "successful DO responses retain their own CORS headers");
      equal(response.headers.get("X-Content-Type-Options"), "nosniff", "forwarded responses receive public defaults");
      equal(forwarded, 1);
    }
  });
  await check("the real heavydo uses the same CORS and response policy as local Axum", async () => {
    const f = fixture();
    const register = () => f.fetch("/api/accounts/register", {
      method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN },
      body: JSON.stringify({ email: "owner@example.test" }),
    });
    const local = await register();
    f.env.HEAVY_DO_ENABLED = "true";
    let forwarded = 0;
    f.env.heavydo = new DurableObjectNamespace(request => {
      forwarded++;
      return new heavydo(state, f.env).fetch(request);
    });
    const offloaded = await register();
    equal(forwarded, 1);
    equal(offloaded.status, local.status);
    equal(await offloaded.text(), await local.text());
    for (const name of ["access-control-allow-origin", "cache-control", "content-security-policy", "x-content-type-options"]) {
      equal(offloaded.headers.get(name), local.headers.get(name), name);
    }
  });
  await check("heavydo returns the same startup errors as local Axum", async () => {
    for (const [binding, value, status] of [
      ["ALLOWED_EMAILS", "owner*@example.test", 400],
      ["DOMAIN", "ftp://vault.test", 500],
      ["DB", undefined, 500],
    ]) {
      const f = fixture();
      if (value === undefined) delete f.env[binding];
      else f.env[binding] = value;
      const register = () => f.fetch("/api/accounts/register", {
        method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN },
        body: JSON.stringify({ email: "owner@example.test" }),
      });
      const local = await register();
      f.env.HEAVY_DO_ENABLED = "true";
      let forwarded = 0;
      f.env.heavydo = new DurableObjectNamespace(request => {
        forwarded++;
        return new heavydo(state, f.env).fetch(request);
      });
      const offloaded = await register();
      equal(forwarded, 1, binding);
      equal(local.status, status, binding);
      equal(offloaded.status, status, binding);
      equal(await offloaded.text(), await local.text(), binding);
      equal(offloaded.headers.get("Access-Control-Allow-Origin"), ORIGIN, binding);
      equal(offloaded.headers.get("Vary"), "Origin", binding);
      equal(offloaded.headers.get("X-Content-Type-Options"), "nosniff", binding);
      for (const name of ["cache-control", "content-security-policy", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"]) {
        equal(offloaded.headers.get(name), local.headers.get(name), `${binding}: ${name}`);
      }
    }
  });
  await check("lightweight grants and invalid or oversized shard input fall back to the same Axum response", async () => {
    const prefix = "grant_type=password&padding=";
    const cases = [
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=refresh_token"],
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=send_access"],
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=password&auth_request=pending&username=owner%40example.test&password=opaque"],
      ["/api/accounts/register", "application/json", "{"],
      ["/identity/connect/token", "application/x-www-form-urlencoded", prefix + "x".repeat(65537 - prefix.length)],
      ["/identity/accounts/register/finish", "application/json", JSON.stringify({ email: "owner@example.test", padding: "x".repeat(65537) })],
    ];
    for (const [path, contentType, text] of cases) {
      const baseline = fixture();
      const expected = await baseline.fetch(path, { method: "POST", headers: { "Content-Type": contentType, Origin: ORIGIN }, body: text });
      const expectedBody = await expected.text();
      const f = fixture(); f.env.HEAVY_DO_ENABLED = "true";
      let forwarded = 0;
      f.env.heavydo = new DurableObjectNamespace(() => { forwarded++; return new Response("unexpected offload", { status: 202 }); });
      const bytes = encoder.encode(text); let offset = 0;
      const body = new ReadableStream({ pull(controller) {
        if (offset === bytes.length) { controller.close(); return; }
        const end = Math.min(offset + 16384, bytes.length);
        controller.enqueue(bytes.subarray(offset, end)); offset = end;
      } }, { highWaterMark: 0 });
      const response = await f.fetch(`${path}///?keep=a%2Fb`, { method: "POST", headers: { "Content-Type": contentType, Origin: ORIGIN }, body });
      equal(forwarded, 0, `${path} should remain local`);
      equal(response.status, expected.status); equal(await response.text(), expectedBody, "fallback must preserve application validation");
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    }
  });
  await check("interrupted form and JSON requests return sanitized errors with or without heavydo", async () => {
    for (const [path, contentType, oauth] of [
      ["/identity/connect/token", "application/x-www-form-urlencoded", true],
      ["/api/accounts/register", "application/json", false],
      ["/identity/accounts/register", "application/json", false],
      ["/identity/accounts/register/finish", "application/json", false],
      ["/api/two-factor/get-authenticator", "application/json", false],
    ]) {
      let baseline;
      const authenticator = path === "/api/two-factor/get-authenticator";
      for (const enabled of [false, true]) {
        const f = fixture(); f.env.HEAVY_DO_ENABLED = String(enabled);
        let forwarded = 0;
        f.env.heavydo = new DurableObjectNamespace(async request => {
          forwarded++;
          return new heavydo(state, f.env).fetch(request);
        });
        const body = new ReadableStream({ start(controller) { controller.error(new Error("fixture private stream failure")); } });
        const headers = { "Content-Type": contentType, Origin: ORIGIN };
        if (authenticator) headers.Authorization = `Bearer ${await accessToken()}`;
        const response = await f.fetch(path, { method: "POST", headers, body });
        equal(forwarded, enabled && authenticator ? 1 : 0, path);
        equal(response.status, 400, path);
        equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN, path);
        equal(response.headers.get("Content-Type"), "application/json", path);
        const raw = await response.text();
        equal(raw.includes("fixture private stream failure"), false, path);
        const error = JSON.parse(raw);
        if (oauth) equal(error.error, "invalid_request");
        else equal(error.message, "Invalid request: Cannot read JSON request body");
        if (enabled) equal(raw, baseline, path);
        else baseline = raw;
      }
    }

    const f = fixture();
    const oversized = await f.fetch("/api/accounts/register", { method: "POST",
      headers: { "Content-Type": "application/json" }, body: "x".repeat(2 * 1024 * 1024 + 1) });
    equal(oversized.status, 413);
    equal((await oversized.json()).message, "Invalid request: Cannot read JSON request body");

    const badType = await f.fetch("/api/accounts/register", { method: "POST",
      headers: { "Content-Type": "text/plain" }, body: "{}" });
    equal(badType.status, 415);

    const badSchema = await f.fetch("/api/accounts/register", { method: "POST",
      headers: { "Content-Type": "application/json" }, body: "{}" });
    equal(badSchema.status, 422);
  });
  await check("heavydo forwards file uploads before reading their stream", async () => {
    const f = fixture(); f.env.HEAVY_DO_ENABLED = "true"; f.env.HEAVY_DO_SHARDS = "16";
    f.db.prepare = () => { throw new Error("offloaded upload touched D1 before forwarding"); };
    let pulls = 0, forwarded = 0;
    const bytes = encoder.encode("streamed-upload");
    const body = new ReadableStream({ pull(controller) { pulls++; controller.enqueue(bytes); controller.close(); } }, { highWaterMark: 0 });
    f.env.heavydo = new DurableObjectNamespace(async (request, name) => {
      forwarded++; equal(pulls, 0, "upload must reach the DO before any source bytes are pulled");
      equal(name, "heavy:8", "bearer subject selects the upload shard"); equal(request.method, "PUT");
      equal(new URL(request.url).pathname, `/api/ciphers/${CIPHER}/attachment/${FILE}/azure-upload`);
      equal(new URL(request.url).search, "?token=capability&keep=a%2Fb");
      sameBytes(new Uint8Array(await request.arrayBuffer()), bytes);
      return new Response(null, { status: 201 });
    });
    const bearer = `e30.${base64url(encoder.encode('{"sub":"alice"}'))}.unverified`;
    const response = await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}/azure-upload///?token=capability&keep=a%2Fb`,
      { method: "PUT", headers: { Authorization: `bEaReR   ${bearer}` }, body });
    equal(response.status, 201); equal(forwarded, 1); equal(pulls, 1);
  });
  await check("missing and malformed D1 bindings return a sanitized error with CORS", async () => {
    for (const binding of [undefined, {}]) {
      const f = fixture();
      f.env.DB = binding;
      const response = await f.fetch("/api/alive", { headers: { Origin: ORIGIN } });
      equal(response.status, 500);
      equal((await response.json()).message, "Internal server error");
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    }
    equal((await fixture().fetch("/api/alive")).status, 200);
  });
  await check("notification internal routes never reach a DO or database", async () => {
    const f = fixture();
    f.db.prepare = () => { throw new Error("notification dispatch touched D1"); };
    for (const path of ["/notifications/internal/fanout", "/notifications/unknown"]) equal((await f.fetch(path, { method: "POST" })).status, 404);
    equal((await f.fetch("/notifications/hub/negotiate", { method: "OPTIONS", headers: { Origin: ORIGIN } })).status, 204);
    equal((await f.fetch("/notifications/hub")).status, 503);
  });
  await check("notification forwarding errors preserve the protocol response and CORS", async () => {
    for (const failure of ["id", "stub", "fetch"]) {
      const f = fixture();
      const reject = () => { throw new Error("fixture private notification outage"); };
      const namespace = new DurableObjectNamespace(async () => reject());
      if (failure === "id") namespace.idFromName = reject;
      if (failure === "stub") namespace.get = reject;
      f.env.notifydo = namespace;
      const response = await f.fetch("/notifications/hub/negotiate", { method: "POST", headers: { Origin: ORIGIN } });
      equal(response.status, 503, failure);
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
      equal(response.headers.get("Access-Control-Allow-Methods"), "GET,POST,OPTIONS");
      equal(await response.text(), "Service temporarily unavailable");
    }
  });
  await check("notification method and upgrade errors include their protocol headers", async () => {
    const f = fixture(); const headers = { Origin: ORIGIN };
    f.db.prepare = () => { throw new Error("notification rejection touched D1"); };
    f.env.notifydo = new DurableObjectNamespace(() => { throw new Error("unsupported method reached notifydo"); });
    for (const prefix of ["/notifications/hub", "/notifications/anonymous-hub"]) {
      for (const [path, method, allow] of [
        [prefix, "POST", "GET, OPTIONS"],
        [prefix + "/negotiate", "GET", "POST, OPTIONS"],
      ]) {
        const response = await f.fetch(path, { method, headers });
        equal(response.status, 405);
        equal(response.headers.get("Allow"), allow);
        equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
        equal(response.headers.get("Access-Control-Allow-Methods"), "GET,POST,OPTIONS");
        equal(await response.text(), "Method not allowed");
      }
    }
    f.env.notifydo = new DurableObjectNamespace(request => new notifydo(state, f.env).fetch(request));
    const response = await f.fetch("/notifications/hub", { headers });
    equal(response.status, 426);
    equal(response.headers.get("Upgrade"), "websocket");
    equal(response.headers.get("Connection"), "upgrade");
    equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    equal(await response.text(), "WebSocket upgrade required");
  });
  await check("notifydo installs no socket on a failed alarm or a full connection cap", async () => {
    for (const failure of ["alarm", "full", "became full"]) {
      const f = fixture();
      let alarmCalls = 0;
      const tag = `u:${USER}`;
      const rejectingState = {
        storage: {
          async getAlarm() { return null; },
          async setAlarm() {
            alarmCalls++;
            if (failure === "alarm") throw new Error("fixture private alarm failure");
          },
        },
        getWebSockets(value) {
          equal(value, tag);
          if (failure === "full" || (failure === "became full" && alarmCalls)) {
            return Array(40).fill(null);
          }
          return state.getWebSockets(value);
        },
        acceptWebSocket(socket, tags) { state.acceptWebSocket(socket, tags); },
      };
      f.env.notifydo = new DurableObjectNamespace(request => new notifydo(rejectingState, f.env).fetch(request));
      const response = await f.fetch("/notifications/hub", {
        headers: { Authorization: `Bearer ${await accessToken()}`, Upgrade: "websocket", Origin: ORIGIN },
      });
      equal(response.status, failure === "alarm" ? 503 : 429, failure);
      equal(await response.text(), failure === "alarm" ? "Service temporarily unavailable" : "Too many connections");
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
      equal(alarmCalls, failure === "full" ? 0 : 1);
      equal(state.getWebSockets(tag).length, 0, "a rejected upgrade registered a socket");
    }
  });
  await check("notifydo separates rejected credentials from identity lookup failures", async () => {
    const f = fixture();
    f.env.notifydo = new DurableObjectNamespace(request => new notifydo(state, f.env).fetch(request));
    const ip = "192.0.2.10", id = "notification-auth-request";
    f.db.execute(
      "INSERT INTO auth_requests(id,user_id,request_device_id,device_type,request_ip,access_code,public_key,security_stamp,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
      [id, USER, "device", 0, ip, "code", "public", "owner-stamp", NOW, "2099-01-01T00:00:00Z"],
    );
    const user = { hub: "/notifications/hub", headers: { Authorization: `bEaReR   ${await accessToken()}` } };
    const anonymous = { hub: "/notifications/anonymous-hub", query: `?token=${id}`, headers: { "cf-connecting-ip": ip } };
    const stale = { ...user, headers: { Authorization: `Bearer ${await accessToken({ session_token: "revoked" })}` } };
    const send = ({ hub, query = "", headers }, upgrade = false) =>
      f.fetch(hub + (upgrade ? "" : "/negotiate") + query, {
        method: upgrade ? "GET" : "POST",
        headers: { Origin: ORIGIN, ...headers, ...(upgrade ? { Upgrade: "websocket" } : {}) },
      });
    async function expectError(endpoint, upgrade, status, challenge = null) {
      const response = await send(endpoint, upgrade);
      equal(response.status, status);
      equal(response.headers.get("WWW-Authenticate"), challenge);
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
      equal(await response.text(), status === 401 ? "Unauthorized" : "Service temporarily unavailable");
    }

    equal((await send(user)).status, 200);
    equal((await send(anonymous)).status, 200);
    for (const upgrade of [false, true]) {
      await expectError({ ...user, headers: {} }, upgrade, 401, "Bearer");
      await expectError({ ...user, headers: { Authorization: "Bearer\ttoken" } }, upgrade, 401, "Bearer");
      await expectError({ ...user, headers: { Authorization: "Bearer invalid" } }, upgrade, 401, 'Bearer error="invalid_token"');
      await expectError(stale, upgrade, 401, 'Bearer error="invalid_token"');
      await expectError({ ...anonymous, query: "?token=missing" }, upgrade, 401);

      const execute = f.db.execute;
      for (const [endpoint, query] of [
        [user, "FROM jwt_keys"], [user, "FROM devices"],
        [anonymous, "FROM auth_requests"], [anonymous, "FROM users"],
      ]) {
        f.db.execute = function (sql, params) {
          if (sql.includes(query)) throw new Error("fixture private identity lookup failure");
          return execute.call(this, sql, params);
        };
        await expectError(endpoint, upgrade, 503);
      }
      f.db.execute = execute;
    }
    delete f.env.KEY_ENCRYPTION_KEY;
    await expectError(user, false, 503);
    delete f.env.DB;
    await expectError(anonymous, false, 503);
  });
  await check("notifydo fanout separates invalid proofs from verification outages", async () => {
    const f = fixture();
    const body = JSON.stringify({ selector: { kind: "user", user_id: USER }, message: "AQ==", logout: false });
    const now = Math.floor(Date.now() / 1000);
    const sign = (claims, secret) => fanoutProof(body, claims, secret);
    const proof = await sign();
    const send = (signature, payload = body) => new notifydo(state, f.env).fetch(fanoutRequest(signature, payload));
    async function expectError(signature, status, payload) {
      const response = await send(signature, payload);
      equal(response.status, status);
      equal(await response.text(), status === 403 ? "Forbidden" : "Service temporarily unavailable");
    }

    const accepted = await send(proof);
    equal(accepted.status, 200);
    equal((await accepted.json()).sent, 0);
    for (const invalid of [null, await sign({}, "different-key"), await sign({ scope: "access" }), await sign({ exp: now - 1 })]) {
      await expectError(invalid, 403);
    }
    await expectError(proof, 403, body + " ");

    const execute = f.db.execute;
    f.db.execute = function (sql, params) {
      if (sql.includes("FROM jwt_keys")) throw new Error("fixture private fanout lookup failure");
      return execute.call(this, sql, params);
    };
    await expectError(proof, 503);
    await expectError(proof, 403, " ".repeat(65_537));
    f.db.execute = execute;
    delete f.env.KEY_ENCRYPTION_KEY;
    await expectError(proof, 503);
    delete f.env.DB;
    await expectError(proof, 503);
  });
  await check("established notifydo sockets distinguish unavailable identity from revocation", async () => {
    const handshake = '{"protocol":"messagepack","version":1}\u001e';
    for (const [action, revokedReason] of [
      ["receive", "Session expired"],
      ["alarm", "Session expired or inactive"],
      ["fanout", "Session expired"],
      ["logout", "Notification channel complete"],
    ]) {
      for (const unavailable of [false, true]) {
        const f = fixture();
        const notify = new notifydo(state, f.env);
        setNotifyDo(notify);
        const response = await notify.fetch(new Request("https://vault.test/notifications/hub", {
          headers: { Upgrade: "websocket", Authorization: `Bearer ${await accessToken()}` },
        }));
        equal(response.status, 101);
        const client = response.webSocket;
        const server = state.getWebSockets(`u:${USER}`).find(socket => socket.readyState === WebSocket.OPEN);
        ok(client && server, "missing upgraded connection");
        client.accept();
        const logout = action === "logout";
        if (action === "fanout" || logout) await notify.webSocketMessage(server, handshake);
        if (unavailable) {
          const execute = f.db.execute;
          f.db.execute = function (sql, params) {
            if (sql.includes("FROM devices")) throw new Error("fixture session lookup failure");
            return execute.call(this, sql, params);
          };
        } else {
          f.db.sessionValid = false;
        }

        let timeout;
        const closed = new Promise((resolve, reject) => {
          timeout = setTimeout(() => reject(new Error(`socket did not close after ${action}`)), 3000);
          client.addEventListener("close", resolve, { once: true });
        });
        try {
          if (action === "receive") await notify.webSocketMessage(server, handshake);
          else if (action === "alarm") await notify.alarm();
          else {
            const body = JSON.stringify({ selector: { kind: "user", user_id: USER }, message: "AQ==", logout });
            const fanout = await notify.fetch(fanoutRequest(await fanoutProof(body), body));
            equal(fanout.status, 200);
            equal((await fanout.json()).sent, logout ? 1 : 0);
          }
          const event = await closed;
          client.close(event.code, event.reason);
          equal(event.code, logout ? 1000 : unavailable ? 1011 : 1008, action);
          equal(event.reason, unavailable && !logout ? "Service temporarily unavailable" : revokedReason, action);
        } finally {
          clearTimeout(timeout);
          await state.storage.deleteAlarm();
        }
      }
    }
  });
  await check("notifydo preserves an earlier alarm and keeps a new socket scheduled during a running alarm", async () => {
    const f = fixture();
    const tag = `u:${USER}`;
    const notify = new notifydo(state, f.env);
    setNotifyDo(notify);
    const open = async () => {
      const response = await notify.fetch(new Request("https://vault.test/notifications/hub", {
        headers: { Upgrade: "websocket", Authorization: `Bearer ${await accessToken()}` },
      }));
      equal(response.status, 101);
      response.webSocket.accept();
      return response.webSocket;
    };

    const earlier = Date.now() + 15_000;
    await state.storage.setAlarm(earlier);
    const old = await open();
    equal(await state.storage.getAlarm(), earlier, "upgrade postponed an earlier alarm");
    // A native alarm is consumed before its handler runs.
    await state.storage.deleteAlarm();

    const entered = Promise.withResolvers(), release = Promise.withResolvers();
    const batch = f.db.batch.bind(f.db);
    f.db.batch = async statements => {
      if (!statements.some(stmt => stmt.sql.startsWith("SELECT entry.key AS position"))) return batch(statements);
      f.db.batch = batch;
      entered.resolve();
      await release.promise;
      return statements.map(() => ({ success: true, results: [], meta: {} }));
    };
    const alarm = notify.alarm();
    let fresh;
    try {
      await Promise.race([entered.promise, alarm.then(() => { throw new Error("alarm missed the session lookup"); })]);
      fresh = await open();
      const scheduled = await state.storage.getAlarm();
      ok(scheduled !== null, "upgrade left the new socket without an alarm");
      release.resolve();
      await alarm;
      equal(await state.storage.getAlarm(), scheduled, "running alarm canceled a new socket's alarm");
      equal(state.getWebSockets(tag).filter(ws => ws.readyState === WebSocket.OPEN).length, 1);
    } finally {
      release.resolve();
      await alarm.catch(() => {});
      old.close(1000);
      if (fresh) fresh.close(1000);
      for (const socket of state.getWebSockets(tag)) socket.close(1000);
      await state.storage.deleteAlarm();
    }
  });
  await check("notifydo batches validations and scoped logout keeps post-rotation sockets", async () => {
    for (const kind of ["stamp", "before_revision"]) {
      const f = fixture(), tag = `u:${USER}`;
      const notify = new notifydo(state, f.env);
      setNotifyDo(notify);
      const sockets = [];
      const open = async claims => {
        const existing = new Set(state.getWebSockets(tag));
        const upgrade = await notify.fetch(new Request("https://vault.test/notifications/hub", {
          headers: { Upgrade: "websocket", Authorization: `Bearer ${await accessToken(claims)}` },
        }));
        equal(upgrade.status, 101);
        const client = upgrade.webSocket;
        client.accept();
        sockets.push(client);
        const server = state.getWebSockets(tag).find(ws => !existing.has(ws));
        ok(server, "new server socket");
        await notify.webSocketMessage(server, '{"protocol":"messagepack","version":1}\u001e');
        return client;
      };

      try {
        await open();
        await open();
        const priorBatches = f.db.batches;
        await state.storage.deleteAlarm();
        await notify.alarm();
        equal(f.db.batches - priorBatches, 1, "keepalive should validate multiple sockets in one batch");

        const revision = "2026-11-24T10:00:00.000Z";
        const stamp = kind === "stamp" ? "next-stamp" : "owner-stamp";
        state.storage.sql.exec("UPDATE users SET security_stamp=?,updated_at=? WHERE id=?", stamp, revision, USER);
        const fresh = await open({ sstamp: stamp });
        const scope = kind === "stamp" ? { kind, value: "owner-stamp" } : { kind, value: revision, stamp };
        const body = JSON.stringify({ selector: { kind: "user", user_id: USER, logout_scope: scope }, message: "AQ==", logout: true });
        const reply = await notify.fetch(fanoutRequest(await fanoutProof(body), body));
        equal(reply.status, 200);
        equal((await reply.json()).sent, 2);
        equal(fresh.readyState, WebSocket.OPEN, "a delayed logout must leave the new socket open");
      } finally {
        for (const socket of sockets) socket.close(1000);
        for (const socket of state.getWebSockets(tag)) socket.close(1000);
        await state.storage.deleteAlarm();
      }
    }
  });
  await check("notification WebSocket upgrades retain their native socket", async () => {
    const f = fixture(); const pair = new WebSocketPair(); pair[1].accept();
    f.db.prepare = () => { throw new Error("notification dispatch touched D1"); };
    f.env.notifydo = new DurableObjectNamespace(async (request, name) => {
      equal(name, "global"); equal(new URL(request.url).pathname, "/notifications/hub");
      return new Response(null, { status: 101, webSocket: pair[0] });
    });
    const response = await f.fetch("/notifications/hub///", { headers: { Upgrade: "websocket", Origin: ORIGIN } });
    equal(response.status, 101); equal(response.webSocket, pair[0], "upgraded socket identity");
    response.webSocket.accept(); response.webSocket.close(1000); pair[1].close(1000);
  });
}
