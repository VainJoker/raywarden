import { heavydo, notifydo } from "./index.js";
import {
  bearerJsonHeaders,
  equal,
  expectJson,
  expectStatus,
  oauthToken,
  ok,
  sameBytes,
} from "./runtime-tools.mjs";
import {
  snapshotTables,
  CIPHER,
  DurableObjectNamespace,
  FILE,
  NOW,
  ORIGIN,
  USER,
  accessToken,
  base64url,
  encoder,
  token,
} from "./runtime-fixture.mjs";

export async function runPlatformTests(context) {
  await runEdgeChecks(context);
  await runConfigurationChecks(context);
  await runPresentationChecks(context);
  await runAdminNotificationChecks(context);
  await runSecurityHeadersChecks(context);
  await runRateLimitChecks(context);
}

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
async function runEdgeChecks({ fixture, check, state, setNotifyDo }) {
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

async function runConfigurationChecks({ fixture, check }) {
  const origin = "https://client.test";
  function headers(response, expected) {
    equal(response.headers.get("Access-Control-Allow-Origin"), expected, "allowed origin");
    equal(response.headers.get("Access-Control-Allow-Credentials"), null, "cookie credentials");
  }

  await check("Worker config serves a canonical DOMAIN and redacts rejected configuration", async () => {
    // The Rust parser tests cover the full set of accepted and rejected origins.
    const f = fixture();
    f.env.DOMAIN = " HTTPS://VAULT.TEST:443/ ";
    const config = await expectJson(await f.fetch("/api/config"), 200);
    equal(config.environment.vault, "https://vault.test");

    for (const value of [
      "https://user:private-password@vault.test",
      "https://vault.test?token=private-token",
    ]) {
      f.env.DOMAIN = value;
      const response = await f.fetch("/api/config");
      equal(response.status, 500);
      const body = await response.text();
      ok(!body.includes("private-password") && !body.includes("private-token"), "invalid DOMAIN exposed configuration credentials");
    }
  });

  await check("CORS applies the same policy to routes, preflight and errors", async () => {
    for (const [origins, expected] of [
      [undefined, "*"], ["", "*"], ["  ", "*"], ["*", "*"], [origin, origin],
      ["https://other.test", null], ["not-an-origin", null],
      ["https://user:pass@client.test", null], [",,,", null],
      [null, null], [true, null], [["*"], null], [{ origin }, null],
    ]) {
      const f = fixture();
      if (origins === undefined) delete f.env.CORS_ALLOWED_ORIGINS;
      else f.env.CORS_ALLOWED_ORIGINS = origins;
      const alive = await f.fetch("/api/alive", { headers: { Origin: origin } });
      equal(alive.status, 200); headers(alive, expected);
      const preflight = await f.fetch("/api/sync", { method: "OPTIONS", headers: { Origin: origin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization,device-type" } });
      headers(preflight, expected);
      const outer = await f.fetch("/notifications/internal/fanout", { method: "POST", headers: { Origin: origin } });
      equal(outer.status, 404); headers(outer, expected);
      const notifyPreflight = await f.fetch("/notifications/hub/negotiate", { method: "OPTIONS", headers: { Origin: origin } });
      equal(notifyPreflight.status, 204); headers(notifyPreflight, expected);
      delete f.env.DB;
      const failure = await f.fetch("/api/alive", { headers: { Origin: origin } });
      equal(failure.status, 500); headers(failure, expected);
    }
  });

  await check("readiness reports the verified release while public reads need no signing keys", async () => {
    const f = fixture();
    const releaseId = "a1".repeat(32);
    f.env.RAYWARDEN_RELEASE_ID = releaseId;
    const ready = await f.fetch("/api/alive");
    equal(ready.status, 200);
    equal(ready.headers.get("X-Raywarden-Release-Id"), releaseId);
    equal(ready.headers.get("Cache-Control"), "private, no-store");
    if (typeof await ready.json() !== "string") throw new Error("readiness timestamp changed shape");
    f.env.RAYWARDEN_RELEASE_ID = releaseId.toUpperCase();
    equal((await f.fetch("/api/alive")).headers.get("X-Raywarden-Release-Id"), null);

    delete f.env.DB;
    delete f.env.KEY_ENCRYPTION_KEY;
    for (const path of ["/api/now", "/api/version", "/css/vaultwarden.css", "/js/raywarden.js", "/.well-known/apple-app-site-association"]) {
      equal((await f.fetch(path)).status, 200, path);
    }
    equal((await f.fetch("/api/version", { method: "POST" })).status, 405);
    equal((await f.fetch("/api/alive")).status, 500);
    equal((await f.fetch("/api/sync")).status, 500);
  });

  await check("demo stays disabled by default, is opt-in with no-store and keeps ordinary API authorization", async () => {
    for (const [enabled, status] of [[undefined, 404], ["false", 404], ["true", 200], ["YES", 200], ["1", 200], ["on", 200], ["no", 404]]) {
      const f = fixture();
      if (enabled !== undefined) f.env.DEMO_PAGE_ENABLED = enabled;
      const page = await f.fetch("/demo.html");
      equal(page.status, status);
      equal(page.headers.get("Cache-Control"), "no-store");
      const content = await page.text();
      if (status === 200) {
        if (!content.includes("<!DOCTYPE html>")) throw new Error("demo missing HTML");
        if (!page.headers.get("Content-Security-Policy").includes("connect-src 'self'")) throw new Error("demo missing same-origin policy");
        const head = await f.fetch("/demo.html", { method: "HEAD" });
        equal(head.status, 200); equal(await head.text(), "");
      }
      equal((await f.fetch("/api/sync")).status, 401);
    }
  });
}

/** Presentation preferences through the compiled Rust config/CSS handlers. */

async function runPresentationChecks({ fixture, check }) {
  const css = async (f, init) => {
    const response = await expectStatus(await f.fetch("/css/vaultwarden.css", init), 200);
    return { response, text: await response.text() };
  };
  const config = async (f, headers) => {
    const response = await f.fetch("/api/config", { headers });
    equal(response.status, 200);
    equal(response.headers.get("cache-control"), "no-store");
    return response.json();
  };
  const hidden = (text, selector, expected) => equal(text.includes(selector), expected, selector);
  const names = [
    "SIGNUP_DISABLED", "SENDS_ALLOWED", "PASSWORD_HINTS_ALLOWED", "SSO_ENABLED", "SSO_ONLY",
    "PASSKEY_2FA_SUPPORTED", "PASSKEY_LOGIN_ENABLED", "REMEMBER_2FA_DISABLED",
    "MAIL_2FA_ENABLED", "MAIL_ENABLED", "YUBICO_ENABLED", "DUO_ENABLED",
    "EMERGENCY_ACCESS_ALLOWED", "LOAD_USER_CSS",
  ];
  const custom = ".presentation-runtime-custom { color: rgb(1, 2, 3); }";

  await check("all CSS preferences accept the four boolean spellings and remove fixed feature hiding", async () => {
    const f = fixture();
    f.env.VW_CSS_USER = custom;
    for (const [yes, no] of [["true", "false"], ["1", "0"], [" YES ", " NO "], ["On", "Off"]]) {
      for (const [value, enabled] of [[yes, true], [no, false]]) {
        for (const name of names) f.env[`VW_CSS_${name}`] = value;
        const { text } = await css(f);
        hidden(text, 'a[routerlink="/signup"]', enabled);
        hidden(text, 'bit-nav-item[route="sends"]', !enabled);
        hidden(text, ".vw-password-hint", !enabled);
        hidden(text, ".vw-sso-login", !enabled);
        hidden(text, ".vw-email-continue", enabled);
        hidden(text, ".providers-2fa-7", !enabled);
        hidden(text, ".vw-passkey-login", !enabled);
        hidden(text, "app-two-factor-auth > form > bit-form-control", enabled);
        hidden(text, ".providers-2fa-1", !enabled);
        hidden(text, ".providers-2fa-3", !enabled);
        hidden(text, ".providers-2fa-2", !enabled);
        hidden(text, "settings/emergency-access", !enabled);
        hidden(text, custom, enabled);
      }
    }
    // SSO-only and the two mail preferences also work independently.
    f.env.VW_CSS_SSO_ENABLED = "true";
    f.env.VW_CSS_SSO_ONLY = "false";
    f.env.VW_CSS_MAIL_ENABLED = "true";
    f.env.VW_CSS_MAIL_2FA_ENABLED = "false";
    let result = await css(f);
    hidden(result.text, ".vw-other-login", false);
    hidden(result.text, ".providers-2fa-1", true);
    f.env.VW_CSS_SSO_ONLY = "true";
    f.env.VW_CSS_MAIL_ENABLED = "false";
    f.env.VW_CSS_MAIL_2FA_ENABLED = "true";
    result = await css(f);
    hidden(result.text, ".vw-other-login", true);
    hidden(result.text, ".providers-2fa-1", true);
  });

  await check("CSS defaults and the legacy Passkey alias preserve current presentation", async () => {
    const f = fixture();
    let result = await css(f);
    for (const selector of [".vw-sso-login", ".providers-2fa-1", ".providers-2fa-2", ".providers-2fa-3", "settings/emergency-access", 'a[routerlink="/signup"]']) {
      hidden(result.text, selector, true);
    }
    hidden(result.text, ".providers-2fa-7", false);
    hidden(result.text, ".vw-passkey-login", false);
    f.env.PASSKEY_LOGIN_ENABLED = "false";
    result = await css(f);
    hidden(result.text, ".vw-passkey-login", true);
    f.env.VW_CSS_PASSKEY_LOGIN_ENABLED = "true";
    f.env.VW_CSS_SIGNUP_DISABLED = "false";
    result = await css(f);
    hidden(result.text, ".vw-passkey-login", false);
    hidden(result.text, 'a[routerlink="/signup"]', false);
    equal((await config(f)).settings.disableUserRegistration, true, "CSS does not change the client registration setting");
    delete f.env.VW_CSS_PASSKEY_LOGIN_ENABLED;
    f.env.PASSKEY_LOGIN_ENABLED = "invalid";
    f.env.VW_CSS_DUO_ENABLED = "invalid";
    result = await css(f);
    hidden(result.text, ".vw-passkey-login", false);
    hidden(result.text, ".providers-2fa-2", true);
    f.env.MAIL_WEBHOOK_URL = "https://mail.example.test/fixture-only";
    hidden((await css(f)).text, ".providers-2fa-1", false);
  });

  await check("CSS validators change with effective settings and HEAD keeps GET validators", async () => {
    const f = fixture();
    const first = await css(f);
    const etag = first.response.headers.get("etag");
    ok(/^"[a-f0-9]{64}"$/.test(etag), "CSS has no strong content ETag");
    equal(first.response.headers.get("cache-control"), "public, no-cache");
    let response = await f.fetch("/css/vaultwarden.css", { headers: { "If-None-Match": `"another", W/${etag}` } });
    equal(response.status, 304);
    equal(await response.text(), "");
    equal(response.headers.get("etag"), etag);
    equal(response.headers.get("cache-control"), "public, no-cache");
    equal(response.headers.get("x-content-type-options"), "nosniff");
    response = await f.fetch("/css/vaultwarden.css", { method: "HEAD" });
    equal(response.status, 200); equal(await response.text(), ""); equal(response.headers.get("etag"), etag);
    f.env.VW_CSS_USER = custom;
    const changed = await css(f, { headers: { "If-None-Match": etag } });
    ok(changed.text.endsWith(custom), "custom CSS was not appended last");
    ok(changed.response.headers.get("etag") !== etag, "CSS change retained the old validator");
    f.env.VW_CSS_LOAD_USER_CSS = "false";
    const disabled = await css(f);
    hidden(disabled.text, custom, false);
    equal(disabled.response.headers.get("etag"), etag, "disabled custom CSS did not restore the baseline");
    response = await f.fetch("/css/vaultwarden.css", { method: "HEAD", headers: { "If-None-Match": etag } });
    equal(response.status, 304); equal(await response.text(), "");
  });

  await check("onboarding suppression is a real client setting independent of registration visibility", async () => {
    const f = fixture({ empty: true });
    f.env.ALLOWED_EMAILS = "owner@example.test";
    f.env.OWNER_SETUP_TOKEN = "presentation-runtime-private-owner-authorization";
    f.env.DISABLE_USER_REGISTRATION = "false";
    let settings = (await config(f)).settings;
    equal(settings.disableUserRegistration, true, "a presentation variable cannot open public registration");
    equal(settings.suppressOnboardingInterstitials, false);
    const baseline = await css(f);
    const baselineEtag = baseline.response.headers.get("etag");
    hidden(baseline.text, "app-vault-onboarding", false);
    const authorization = await f.fetch("/api/accounts/setup", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: f.env.OWNER_SETUP_TOKEN }),
    });
    equal(authorization.status, 200);
    const headers = { Cookie: authorization.headers.get("set-cookie").split(";")[0] };
    for (const [yes, no] of [["true", "false"], ["1", "0"], [" YES ", " NO "], ["On", "Off"]]) {
      f.env.CLIENT_SUPPRESS_ONBOARDING = yes;
      settings = (await config(f, headers)).settings;
      equal(settings.suppressOnboardingInterstitials, true);
      equal(settings.disableUserRegistration, false);
      equal((await config(f)).settings.disableUserRegistration, true);
      const suppressed = await css(f, { headers: { "If-None-Match": baselineEtag } });
      hidden(suppressed.text, "app-vault-onboarding { display:none !important; }", true);
      const suppressedEtag = suppressed.response.headers.get("etag");
      ok(suppressedEtag !== baselineEtag, "onboarding suppression retained the visible checklist validator");
      f.env.CLIENT_SUPPRESS_ONBOARDING = no;
      equal((await config(f, headers)).settings.suppressOnboardingInterstitials, false);
      const restored = await css(f, { headers: { "If-None-Match": suppressedEtag } });
      hidden(restored.text, "app-vault-onboarding", false);
      equal(restored.response.headers.get("etag"), baselineEtag, "showing onboarding did not restore the baseline validator");
    }
    f.env.DISABLE_USER_REGISTRATION = "true";
    settings = (await config(f)).settings;
    equal(settings.disableUserRegistration, true);
    equal(settings.suppressOnboardingInterstitials, false);
    equal((await config(f, headers)).settings.disableUserRegistration, false);
  });
}

// Administrative events from the compiled Rust handlers. Only the synthetic
// HTTPS sink is intercepted; no actual webhook or external network is used.

async function runAdminNotificationChecks({ fixture, check, accessToken, USER, sql }) {
  const owner = async () => bearerJsonHeaders(await accessToken());
  const login = (f, password = "hash") => f.fetch("/identity/connect/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Bitwarden-Client-Version": "2026.10.2" },
    body: new URLSearchParams({ grant_type: "password", username: "owner@example.test", password,
      deviceIdentifier: "admin-runtime-login", deviceName: "Runtime Browser", deviceType: "14" }),
  });
  const createSend = async f => f.fetch("/api/sends", { method: "POST", headers: await owner(), body: JSON.stringify({
    type: 0, name: "private-encrypted-name", key: "private-wrapped-key", text: { text: "private-ciphertext" },
    deletionDate: new Date(Date.now() + 86400000).toISOString(),
  }) });
  async function sink(run, deliveryStatus = 200) {
    const captured = [];
    const previous = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (new URL(request.url).origin !== "https://notify.runtime.test") throw new Error("Unexpected outbound URL in administrative-event test");
      equal(request.method, "POST", "webhook method");
      equal(request.redirect, "manual", "webhook redirect policy");
      const body = await request.json();
      equal(body.msgtype, "text", "WeWork payload");
      const text = body.text.content;
      ok(text.startsWith("raywarden: "), "event name in notification");
      for (const secret of ["owner@example.test", "private-ciphertext", "private-wrapped-key", "private-encrypted-name", "wrong-password-secret", "private-admin-recovery-code"]) {
        ok(!text.includes(secret), `notification excludes ${secret}`);
      }
      captured.push(text);
      return new Response("{}", { status: deliveryStatus, headers: { "Content-Type": "application/json" } });
    };
    try { await run(captured); } finally { globalThis.fetch = previous; }
  }
  const configure = (f, events = "all", level = "info") => {
    f.env.WEWORK_WEBHOOK_URL = "https://notify.runtime.test/events";
    f.env.NOTIFY_EVENTS = events;
    f.env.NOTIFY_LEVEL = level;
  };
  const event = text => text.split("\n")[0].slice("raywarden: ".length);

  await check("mail webhooks reject redirects and release the undelivered code", async () => {
    const f = fixture(), previous = globalThis.fetch;
    const webhook = "https://mail.runtime.test/send";
    f.env.MAIL_WEBHOOK_URL = webhook;
    let calls = 0;
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      calls++;
      equal(request.url, webhook);
      equal(request.redirect, "manual");
      return new Response(null, { status: 307, headers: { Location: "https://other.runtime.test/send" } });
    };
    try {
      await expectStatus(await f.fetch("/api/accounts/request-otp", { method: "POST", headers: await owner() }), 503);
      equal(calls, 1);
      equal(sql.exec("SELECT count(*) AS n FROM verification_codes").one().n, 0);
    } finally {
      globalThis.fetch = previous;
    }
  });

  await check("webhook deadlines release stalled login and mail requests", async () => {
    const f = fixture(), previous = globalThis.fetch;
    configure(f, "login");
    f.env.MAIL_WEBHOOK_URL = "https://mail.runtime.test/send";
    const aborted = [];
    globalThis.fetch = async (input, init) => {
      const request = new Request(input, init);
      return new Promise((_, reject) => {
        const onAbort = () => {
          clearTimeout(guard);
          aborted.push(new URL(request.url).hostname);
          reject(request.signal.reason);
        };
        const guard = setTimeout(() => {
          request.signal.removeEventListener("abort", onAbort);
          reject(new Error("notification request lacked a working deadline"));
        }, 8_000);
        if (request.signal.aborted) onAbort();
        else request.signal.addEventListener("abort", onAbort, { once: true });
      });
    };
    try {
      const headers = await owner();
      const [loggedIn, mail] = await Promise.all([
        login(f), f.fetch("/api/accounts/request-otp", { method: "POST", headers }),
      ]);
      const tokens = await expectJson(loggedIn, 200);
      equal((await expectJson(mail, 503)).code, 12);
      equal(aborted.sort().join(","), "mail.runtime.test,notify.runtime.test");
      equal(sql.exec("SELECT count(*) AS n FROM verification_codes").one().n, 0);
      await expectStatus(await f.fetch("/api/accounts/profile", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      }), 200);
    } finally {
      globalThis.fetch = previous;
    }
  });

  await check("administrative Send events follow successful commits and legacy filters do not double-send", async () => {
    const f = fixture(); configure(f, "vault-changed,send_create,send_delete");
    await sink(async captured => {
      f.db.failBatch = true;
      const failed = await createSend(f);
      ok(failed.status >= 400, "injected Send commit failed");
      equal(captured.length, 0, "failed transaction has no successful event");
      f.db.failBatch = false;
      const send = await expectJson(await createSend(f), 200);
      equal(captured.length, 1); equal(event(captured[0]), "send_create");
      await expectStatus(await f.fetch(`/api/sends/${send.id}`, { method: "DELETE", headers: await owner() }), 200);
      equal(captured.length, 2); equal(event(captured[1]), "send_delete");
    });
  });

  await check("administrative warning level reports failed login but not the normal two-factor challenge", async () => {
    const f = fixture(); configure(f, "all", "WARN");
    await sink(async captured => {
      await expectStatus(await login(f, "wrong-password-secret"), 401);
      equal(captured.length, 1); equal(event(captured[0]), "login_failed");
      ok(captured[0].includes("Level: warning"), "failure severity");
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('admin-runtime-totp',?,0,1,'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',0)", USER);
      const challenge = await expectJson(await login(f), 400);
      ok(challenge.TwoFactorProviders || challenge.TwoFactorProviders2, "actual two-factor challenge response");
      equal(captured.length, 1, "challenge is not a failed login");
    });
  });

  await check("administrative login_failed excludes rate limiting and D1 outages", async () => {
    {
      const f = fixture(); configure(f, "login_failed", "warning");
      // workers-rs validates the constructor name before using a binding.
      // A plain Object would silently exercise the missing-binding fallback.
      class Ratelimit {
        calls = 0;
        async limit({ key }) {
          equal(typeof key, "string");
          this.calls++;
          return { success: false };
        }
      }
      const limiter = new Ratelimit();
      f.env.LOGIN_RATE_LIMITER = limiter;
      await sink(async captured => {
        await expectStatus(await login(f, "wrong-password-secret"), 429);
        equal(limiter.calls, 1, "actual SDK limiter binding was called");
        equal(captured.length, 0, "rate limiter does not emit login_failed");
      });
    }
    {
      const f = fixture(); configure(f, "login_failed", "warning");
      const execute = f.db.execute.bind(f.db);
      let injected = false;
      f.db.execute = (query, values) => {
        if (/FROM\s+users\s+WHERE\s+email\s*=/i.test(query)) {
          injected = true;
          throw new Error("injected account lookup failure");
        }
        return execute(query, values);
      };
      await sink(async captured => {
        const response = await expectStatus(await login(f), 500);
        const error = await response.text();
        equal(error.includes("injected account lookup failure"), false);
        equal(error.includes("SELECT"), false);
        ok(injected, "actual login account lookup failed");
        equal(captured.length, 0, "D1 failure does not emit login_failed");
      });
    }
  });

  await check("administrative login, refresh and sync events come from actual successful requests", async () => {
    const f = fixture(); configure(f, "login,token_refresh,sync");
    await sink(async captured => {
      const tokens = await expectJson(await login(f), 200);
      equal(event(captured[0]), "login");
      await expectStatus(await f.fetch("/identity/connect/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Bitwarden-Client-Version": "2026.10.2" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }) }), 200);
      equal(event(captured[1]), "token_refresh");
      await expectStatus(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${await accessToken()}` } }), 200);
      equal(captured.length, 3); equal(event(captured[2]), "sync");
    });
  });

  await check("administrative recovery applies error threshold and failed delivery cannot undo recovery", async () => {
    const f = fixture(); configure(f, "all", "error");
    sql.exec("UPDATE users SET two_factor_recovery_code='private-admin-recovery-code' WHERE id=?", USER);
    await sink(async captured => {
      await expectStatus(await f.fetch("/api/two-factor/get-recover", { method: "POST", headers: await owner(), body: JSON.stringify({ masterPasswordHash: "hash" }) }), 200);
      equal(captured.length, 0, "warning recovery-code view is below threshold");
      await expectStatus(await f.fetch("/api/two-factor/recover", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "owner@example.test", masterPasswordHash: "hash", recoveryCode: "private-admin-recovery-code" }) }), 200);
      equal(captured.length, 1); equal(event(captured[0]), "2fa_recover");
      ok(captured[0].includes("Level: error"), "recovery severity");
      equal(sql.exec("SELECT two_factor_recovery_code FROM users WHERE id=?", USER).one().two_factor_recovery_code, null, "recovery remains committed");
    }, 500);
  });

  await check("administrative 2fa_disable requires an enabled provider while no-op cleanup still returns 200", async () => {
    const f = fixture(); configure(f, "2fa_disable");
    const disable = async type => f.fetch("/api/two-factor/disable", { method: "POST", headers: await owner(),
      body: JSON.stringify({ type, masterPasswordHash: "hash" }) });
    const disableEmail = async () => f.fetch("/api/two-factor/email", { method: "DELETE", headers: await owner(),
      body: JSON.stringify({ masterPasswordHash: "hash" }) });
    const seed = (type, id) => {
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,?,1,?,0)", id, USER, type,
        type === 1 ? JSON.stringify({ email: "factor@example.test" }) : "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,5,1,'{}',0)", `${id}-remember`, USER);
    };
    const noRemember = () => equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=? AND provider_type=5", USER).one().n, 0, "Remember cleanup remains effective");
    await sink(async captured => {
      await expectStatus(await disable(0), 200);
      await expectStatus(await disable(1), 200);
      await expectStatus(await disableEmail(), 200);
      equal(captured.length, 0, "absent providers do not report disable");
      seed(0, "admin-disable-totp");
      await expectStatus(await disable(0), 200); noRemember();
      equal(captured.length, 1); equal(event(captured[0]), "2fa_disable");
      await expectStatus(await disable(0), 200);
      equal(captured.length, 1, "repeated TOTP disable remains a no-op");
      seed(1, "admin-disable-email");
      await expectStatus(await disableEmail(), 200); noRemember();
      equal(captured.length, 2); equal(event(captured[1]), "2fa_disable");
      await expectStatus(await disableEmail(), 200);
      equal(captured.length, 2, "repeated Email disable remains a no-op");
      seed(1, "admin-disable-email-generic");
      await expectStatus(await disable(1), 200); noRemember();
      equal(captured.length, 3); equal(event(captured[2]), "2fa_disable");
    });
  });

  await check("administrative legacy security-stamp event follows successful revoke_all and excludes failed batches", async () => {
    const f = fixture(); configure(f, "account-security-changed");
    const revoke = async () => f.fetch("/api/accounts/security-stamp", { method: "POST", headers: await owner(),
      body: JSON.stringify({ masterPasswordHash: "hash" }) });
    await sink(async captured => {
      f.db.failBatch = true;
      const failed = await revoke();
      ok(failed.status >= 400, "actual revoke transaction failed");
      equal(captured.length, 0, "failed revoke does not report a successful security change");
      f.db.failBatch = false;
      const batch = f.db.batch.bind(f.db);
      let raced = false;
      f.db.batch = async statements => {
        if (statements.some(stmt => stmt.sql.startsWith("UPDATE users SET security_stamp="))) {
          raced = true;
          sql.exec("UPDATE devices SET session_token='new-session' WHERE user_id=?", USER);
          f.db.batch = batch;
        }
        return batch(statements);
      };
      await expectStatus(await revoke(), 409);
      ok(raced, "revocation missed its guarded commit");
      equal(captured.length, 0);
      equal(sql.exec("SELECT security_stamp FROM users WHERE id=?", USER).one().security_stamp, "owner-stamp");
      equal(sql.exec("SELECT session_token FROM devices WHERE user_id=?", USER).one().session_token, "new-session");
      sql.exec("UPDATE devices SET session_token='session' WHERE user_id=?", USER);
      await expectStatus(await revoke(), 200);
      equal(captured.length, 1); equal(event(captured[0]), "account-security-changed");
      equal(sql.exec("SELECT COUNT(*) AS n FROM devices WHERE user_id=?", USER).one().n, 0, "devices actually revoked");
    });
  });
}

/** Real compiled Worker defaults, including failures outside the Axum router. */
async function runSecurityHeadersChecks({ fixture, check }) {
  const defaults = (response) => {
    equal(response.headers.get("x-content-type-options"), "nosniff", "nosniff");
    equal(response.headers.get("referrer-policy"), "no-referrer", "referrer policy");
    equal(response.headers.get("x-robots-tag"), "noindex, nofollow", "robots policy");
    equal(response.headers.get("cache-control"), "private, no-store", "dynamic cache policy");
    ok(response.headers.get("content-security-policy")?.includes("default-src 'none'"), "missing inert API CSP");
  };

  await check("security defaults cover successful APIs and router rejection responses", async () => {
    const f = fixture();
    for (const [path, init, status] of [
      ["/api/alive", {}, 200],
      ["/api/sync", {}, 401],
      ["/api/not-a-route", {}, 404],
      ["/api/accounts/prelogin", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }, 401],
    ]) {
      const response = await f.fetch(path, init);
      equal(response.status, status, path);
      defaults(response);
      await response.arrayBuffer();
    }
  });

  await check("security defaults cover initialization failures before the router", async () => {
    const f = fixture();
    f.env.DOMAIN = "https://example.test/forbidden-subpath";
    const response = await f.fetch("/api/alive");
    if (response.ok) throw new Error("invalid DOMAIN unexpectedly accepted");
    defaults(response);
    await response.arrayBuffer();
  });

  await check("security defaults cover notification dispatch failures without D1", async () => {
    const f = fixture();
    f.db.prepare = () => { throw new Error("notification dispatch must not query D1"); };
    for (const [path, status] of [["/notifications/hub", 503], ["/notifications/not-a-hub", 404]]) {
      const response = await f.fetch(path);
      equal(response.status, status, path);
      defaults(response);
      await response.arrayBuffer();
    }
  });

  await check("setup page CSP survives shared security defaults", async () => {
    const f = fixture({ empty: true });
    const page = await f.fetch("/setup");
    equal(page.status, 200, "setup status");
    ok(page.headers.get("content-security-policy")?.includes("'unsafe-inline'"), "setup inline-script policy was overwritten");
    await page.arrayBuffer();
  });
}

/** Required binding selection and failure behavior through the actual SDK/WASM. */
async function runRateLimitChecks({ fixture, check, sql, accessToken, notificationFetch, USER, SEND, FILE }) {
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
  const setLimiter = (f, binding, mode) => {
    if (mode === "missing") {
      delete f.env[binding];
    } else {
      f.env[binding] = mode === "wrong-type" ? {} : new Ratelimit(mode);
    }
    return f.env[binding];
  };
  const ip = "203.0.113.17";
  const owner = async () => ({ ...bearerJsonHeaders(await accessToken()), "cf-connecting-ip": ip });
  const verify = async (f, password = "hash") => f.fetch("/api/accounts/verify-password", {
    method: "POST", headers: await owner(), body: JSON.stringify({ masterPasswordHash: password }),
  });
  const sendAccessId = async f => (await expect(await f.fetch(`/api/sends/${SEND}`, { headers: await owner() }), 200)).accessId;
  const accessSend = (f, accessId, password) => f.fetch(`/api/sends/access/${accessId}`, {
    method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(password === undefined ? {} : { password }),
  });
  const credentials = () => snapshotTables(sql, ["users", "devices"]);

  await check("real SDK login and Send bindings independently enforce provider denials as HTTP 429", async () => {
    for (const [loginMode, sendMode, loginCode, sendCode] of [["allow", "deny", 200, 429], ["deny", "allow", 429, 200]]) {
      const f = fixture(), login = new Ratelimit(loginMode), send = new Ratelimit(sendMode);
      f.env.LOGIN_RATE_LIMITER = login; f.env.SEND_ACCESS_RATE_LIMITER = send;
      const accessId = await sendAccessId(f), before = credentials();
      const loginResponse = await expect(await verify(f), loginCode);
      const sendResponse = await expect(await accessSend(f, accessId), sendCode);
      equal((loginCode === 429 ? loginResponse : sendResponse).message, "Too many attempts. Please try again later.");
      equal(login.keys.join(","), `verify-password:${USER}`, "protected action selected the wrong binding");
      equal(send.keys.join(","), `send:${SEND}:${ip}`, "anonymous Send selected the wrong binding");
      equal(credentials(), before, "limiter checks changed credentials or sessions");
      equal(sql.exec("SELECT access_count FROM sends WHERE id=?", SEND).one().access_count, 0, "file metadata consumed a download");
    }
  });

  await check("unavailable rate limiting rejects protected attempts and keeps reads available", async () => {
    for (const mode of ["missing", "wrong-type", "throw", "malformed"]) {
      const f = fixture();
      const login = setLimiter(f, "LOGIN_RATE_LIMITER", mode), send = setLimiter(f, "SEND_ACCESS_RATE_LIMITER", mode);
      const accessId = await sendAccessId(f), before = credentials();
      await expect(await verify(f, "wrong-password"), 503);
      await expect(await verify(f), 503);
      await expect(await accessSend(f, accessId), 503);
      if (login instanceof Ratelimit) {
        equal(login.keys.length, 2, `${mode}: SDK did not call the failing login provider`);
        equal(send.keys.length, 1, `${mode}: SDK did not call the failing Send provider`);
      } else {
        await expect(await f.fetch("/api/alive"), 200);
        await expect(await f.fetch("/api/sync", { headers: await owner() }), 200);
      }
      equal(credentials(), before, `${mode}: limiter failure changed credentials or sessions`);
    }
  });

  await check("password grants stop before authentication on limiter failures and recover when protection returns", async () => {
    const login = (f, password) => oauthToken(f, {
      grant_type: "password", username: "owner@example.test", password,
      deviceIdentifier: "rate-password-client", deviceName: "Rate fixture", deviceType: "14",
    }, { "device-type": "14", "Bitwarden-Client-Version": "2026.10.1", "cf-connecting-ip": ip });
    for (const mode of ["missing", "wrong-type", "throw", "malformed", "deny"]) {
      const f = fixture(), before = credentials();
      setLimiter(f, "LOGIN_RATE_LIMITER", mode);
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
      setLimiter(f, "SEND_ACCESS_RATE_LIMITER", mode);
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
    const post = (path, body) => f.fetch(path, {
      method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": ip }, body,
    });
    const password = JSON.stringify({ password: "wrong-password" });
    const before = credentials();
    await expect(await post(`/api/sends/access/${accessId}`, password), 429);
    await expect(await post(`/api/sends/${SEND}/access/file/${FILE}`, password), 429);
    for (const grant_type of ["send_access", "access_token"]) {
      await expect(await oauthToken(f, { grant_type, send_id: accessId, password_hash_b64: "wrong-password" }, { "cf-connecting-ip": ip }), 429);
    }
    equal(send.keys.join(","), Array(4).fill(`send:${SEND}:${ip}`).join(","));
    equal(login.keys.length, 0);
    equal(sql.exec("SELECT access_count FROM sends WHERE id=?", SEND).one().access_count, 0);
    equal(credentials(), before, "denial advanced the owner revision");

    sql.exec("UPDATE sends SET password_hash=NULL,password_salt=NULL,password_iterations=NULL WHERE id=?", SEND);
    send.mode = "allow";
    const issued = await expect(await oauthToken(f, { grant_type: "send_access", send_id: accessId }, { "cf-connecting-ip": ip }), 200);
    send.mode = "deny";
    for (const path of ["/api/sends/access", `/api/sends/access/file/${FILE}`]) {
      await expect(await f.fetch(path, { method: "POST", headers: { Authorization: `Bearer ${issued.access_token}`, "cf-connecting-ip": ip } }), 200);
    }
    equal(send.keys.length, 5, "signed access was sent back through anonymous authorization");
    equal(login.keys.length, 0);
    equal(sql.exec("SELECT access_count FROM sends WHERE id=?", SEND).one().access_count, 1);
  });

  await check("notifydo distinguishes unavailable protection from a real connection limit", async () => {
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
