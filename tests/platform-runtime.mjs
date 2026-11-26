import { heavydo, notifydo } from "./index.js";
import {
  bearerJsonHeaders,
  equal,
  expectJson,
  expectStatus,
  oauthToken,
  ok,
  sameBytes,
  withFetchMock,
} from "./runtime-tools.mjs";
import {
  snapshotTables,
  CIPHER,
  DurableObjectNamespace,
  FILE,
  NOW,
  ORIGIN,
  Ratelimit,
  USER,
  accessToken,
  base64url,
  encoder,
  token,
} from "./runtime-fixture.mjs";

export const platformChecks = [runEdgeChecks, runConfigurationChecks, runPresentationChecks, runAdminNotificationChecks, runSecurityHeadersChecks, runRateLimitChecks];

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
  const handshake = '{"protocol":"messagepack","version":1}\u001e';
  const connectNotify = f => {
    const notify = new notifydo(state, f.env);
    setNotifyDo(notify);
    return notify;
  };
  const openSocket = async (notify, claims) => {
    const response = await notify.fetch(new Request("https://vault.test/notifications/hub", {
      headers: { Upgrade: "websocket", Authorization: `Bearer ${await accessToken(claims)}` },
    }));
    equal(response.status, 101);
    const client = response.webSocket;
    ok(client, "missing upgraded connection");
    client.accept();
    return client;
  };
  function chunkedText(text) {
    const bytes = encoder.encode(text);
    let offset = 0;
    return new ReadableStream({ pull(controller) {
      if (offset === bytes.length) { controller.close(); return; }
      const end = Math.min(offset + 4096, bytes.length);
      controller.enqueue(bytes.subarray(offset, end));
      offset = end;
    } }, { highWaterMark: 0 });
  }

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
  await check("heavydo forwards heavy mutations and file uploads to global DO without touching D1 or reading streams", async () => {
    const f = fixture(); f.env.HEAVY_DO_ENABLED = "true";
    f.db.prepare = () => { throw new Error("offloaded request touched D1 before forwarding"); };
    let forwarded = 0, pulls = 0;
    const bytes = encoder.encode("streamed-upload");
    const uploadBody = new ReadableStream({ pull(controller) { pulls++; controller.enqueue(bytes); controller.close(); } }, { highWaterMark: 0 });
    f.env.heavydo = new DurableObjectNamespace(async (request, name) => {
      forwarded++;
      equal(name, "global");
      if (request.method === "PUT") {
        equal(pulls, 0, "upload must reach the DO before any source bytes are pulled");
        sameBytes(new Uint8Array(await request.arrayBuffer()), bytes);
        return new Response(null, { status: 201 });
      }
      equal(await request.text(), "grant_type=password&username=owner%40example.test&password=hash");
      return new Response("offloaded", { status: 202, headers: { "Access-Control-Allow-Origin": ORIGIN, Vary: "X-Heavy-Fixture" } });
    });
    const loginResp = await f.fetch("/identity/connect/token///?keep=a%2Fb", {
      method: "POST", body: chunkedText("grant_type=password&username=owner%40example.test&password=hash"),
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: ORIGIN },
    });
    equal(loginResp.status, 202);
    equal(loginResp.headers.get("Vary"), "X-Heavy-Fixture");
    equal(loginResp.headers.get("X-Content-Type-Options"), "nosniff");

    const uploadResp = await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}/azure-upload///?token=capability`, { method: "PUT", body: uploadBody });
    equal(uploadResp.status, 201);
    equal(forwarded, 2);
    equal(pulls, 1);

    const local = fixture(); local.env.HEAVY_DO_ENABLED = "true";
    local.env.heavydo = new DurableObjectNamespace(req => new heavydo(state, local.env).fetch(req));
    const badValue = await local.fetch("/api/accounts/register", {
      method: "POST", headers: { "Content-Type": "application/json", "CF-Ray": "a5f72d126a84fd0c-HKG" },
      body: JSON.stringify({ email: "owner@example.test", masterPasswordHash: "hash", key: "2.key", kdf: "fixture-secret-value" }),
    });
    equal(badValue.status, 422);
    const badRaw = await badValue.text();
    equal(badRaw.includes("fixture-secret-value"), false);
    equal(JSON.parse(badRaw).rayId, "a5f72d126a84fd0c");
  });
  await check("missing and malformed D1 bindings return a sanitized error with CORS", async () => {
    for (const binding of [undefined, {}]) {
      const f = fixture();
      f.env.DB = binding;
      const response = await f.fetch("/api/alive", { headers: { Origin: ORIGIN, "CF-Ray": "0123456789abcdef-SIN" } });
      equal(response.status, 500);
      const body = await response.json();
      equal(body.message, "Worker runtime error: D1 database binding DB is missing or invalid");
      equal(body.rayId, "0123456789abcdef");
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

      for (const [endpoint, fragment] of [
        [user, "FROM jwt_keys"], [user, "FROM devices"],
        [anonymous, "FROM auth_requests"], [anonymous, "FROM users"],
      ]) {
        const restore = f.db.failQuery(query => query.includes(fragment), "fixture private identity lookup failure");
        await expectError(endpoint, upgrade, 503);
        restore();
      }
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

    const restore = f.db.failQuery(query => query.includes("FROM jwt_keys"), "fixture private fanout lookup failure");
    await expectError(proof, 503);
    await expectError(proof, 403, " ".repeat(65_537));
    restore();
    delete f.env.KEY_ENCRYPTION_KEY;
    await expectError(proof, 503);
    delete f.env.DB;
    await expectError(proof, 503);
  });
  await check("established notifydo sockets distinguish unavailable identity from revocation", async () => {
    for (const [action, revokedReason] of [
      ["receive", "Session expired"],
      ["alarm", "Session expired or inactive"],
      ["fanout", "Session expired"],
      ["logout", "Notification channel complete"],
    ]) {
      for (const unavailable of [false, true]) {
        const f = fixture();
        const notify = connectNotify(f);
        const client = await openSocket(notify);
        const server = state.getWebSockets(`u:${USER}`).find(socket => socket.readyState === WebSocket.OPEN);
        ok(server, "missing upgraded server connection");
        const logout = action === "logout";
        if (action === "fanout" || logout) await notify.webSocketMessage(server, handshake);
        if (unavailable) {
          f.db.failQuery(query => query.includes("FROM devices"), "fixture session lookup failure");
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
    const notify = connectNotify(f);

    const earlier = Date.now() + 15_000;
    await state.storage.setAlarm(earlier);
    const old = await openSocket(notify);
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
      fresh = await openSocket(notify);
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
      const notify = connectNotify(f);
      const sockets = [];
      const open = async claims => {
        const existing = new Set(state.getWebSockets(tag));
        const client = await openSocket(notify, claims);
        sockets.push(client);
        const server = state.getWebSockets(tag).find(ws => !existing.has(ws));
        ok(server, "new server socket");
        await notify.webSocketMessage(server, handshake);
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
      [undefined, "*"], [origin, origin], ["https://other.test", null],
      ["https://user:pass@client.test", null], [["*"], null],
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

  await check("CSS switches, static enterprise selectors, ETag validators, and onboarding suppression", async () => {
    const f = fixture();
    const first = await css(f);
    for (const selector of [".vw-sso-login", ".providers-2fa-1", ".providers-2fa-2", ".providers-2fa-3", "settings/emergency-access", 'a[routerlink="/signup"]']) {
      hidden(first.text, selector, true);
    }
    f.env.VW_CSS_SIGNUP_DISABLED = "false";
    f.env.VW_CSS_SENDS_ALLOWED = "false";
    f.env.VW_CSS_PASSWORD_HINTS_ALLOWED = "false";
    f.env.VW_CSS_REMEMBER_2FA_DISABLED = "true";
    f.env.MAIL_WEBHOOK_URL = "https://mail.example.test/fixture";
    const toggled = await css(f);
    hidden(toggled.text, 'a[routerlink="/signup"]', false);
    hidden(toggled.text, 'bit-nav-item[route="sends"]', true);
    hidden(toggled.text, ".vw-password-hint", true);
    hidden(toggled.text, "app-two-factor-auth > form > bit-form-control", true);
    hidden(toggled.text, ".providers-2fa-1", false);

    const etag = toggled.response.headers.get("etag");
    ok(/^".+"$/.test(etag));
    equal((await f.fetch("/css/vaultwarden.css", { headers: { "If-None-Match": etag } })).status, 304);
    equal((await f.fetch("/css/vaultwarden.css", { method: "HEAD" })).headers.get("etag"), etag);

    const empty = fixture({ empty: true });
    empty.env.ALLOWED_EMAILS = "owner@example.test";
    empty.env.OWNER_SETUP_TOKEN = "presentation-runtime-private-owner-authorization";
    empty.env.CLIENT_SUPPRESS_ONBOARDING = "true";
    equal((await config(empty)).settings.suppressOnboardingInterstitials, true);
    hidden((await css(empty)).text, "app-vault-onboarding", true);
  });
}

// Administrative events from the compiled Rust handlers. Only the synthetic
// HTTPS sink is intercepted; no actual webhook or external network is used.

async function runAdminNotificationChecks({ fixture, check, accessToken, USER, sql }) {
  const owner = async () => bearerJsonHeaders(await accessToken());
  const login = (f, password = "hash") => oauthToken(f, {
    grant_type: "password", username: "owner@example.test", password,
    deviceIdentifier: "admin-runtime-login", deviceName: "Runtime Browser", deviceType: "14",
  }, { "Bitwarden-Client-Version": "2026.10.2" });
  const createSend = async f => f.fetch("/api/sends", { method: "POST", headers: await owner(), body: JSON.stringify({
    type: 0, name: "private-encrypted-name", key: "private-wrapped-key", text: { text: "private-ciphertext" },
    deletionDate: new Date(Date.now() + 86400000).toISOString(),
  }) });
  async function sink(run, deliveryStatus = 200) {
    const captured = [];
    await withFetchMock(async (input, init) => {
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
    }, () => run(captured));
  }
  const configure = (f, events = "all", level = "info") => {
    f.env.WEWORK_WEBHOOK_URL = "https://notify.runtime.test/events";
    f.env.NOTIFY_EVENTS = events;
    f.env.NOTIFY_LEVEL = level;
  };
  const event = text => text.split("\n")[0].slice("raywarden: ".length);

  await check("mail webhooks reject redirects and release the undelivered code", async () => {
    const f = fixture();
    const webhook = "https://mail.runtime.test/send";
    f.env.MAIL_WEBHOOK_URL = webhook;
    let calls = 0;
    await withFetchMock(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      calls++;
      equal(request.url, webhook);
      equal(request.redirect, "manual");
      return new Response(null, { status: 307, headers: { Location: "https://other.runtime.test/send" } });
    }, async () => {
      await expectStatus(await f.fetch("/api/accounts/request-otp", { method: "POST", headers: await owner() }), 503);
      equal(calls, 1);
      equal(sql.exec("SELECT count(*) AS n FROM verification_codes").one().n, 0);
    });
  });

  await check("webhook deadlines release stalled login and mail requests", async () => {
    const f = fixture();
    configure(f, "login");
    f.env.MAIL_WEBHOOK_URL = "https://mail.runtime.test/send";
    const aborted = [];
    await withFetchMock(async (input, init) => {
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
    }, async () => {
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
    });
  });

  await check("administrative Send events follow successful commits", async () => {
    const f = fixture(); configure(f, "send_create,send_delete");
    await sink(async captured => {
      f.db.failBatch = true;
      const failed = await createSend(f);
      ok(failed.status >= 400);
      equal(captured.length, 0);
      f.db.failBatch = false;
      const send = await expectJson(await createSend(f), 200);
      equal(captured.length, 1); equal(event(captured[0]), "send_create");
      await expectStatus(await f.fetch(`/api/sends/${send.id}`, { method: "DELETE", headers: await owner() }), 200);
      equal(captured.length, 2); equal(event(captured[1]), "send_delete");
    });
  });

  await check("administrative levels and events cover login_failed, login, token_refresh, sync, 2fa_recover, 2fa_disable, and security-stamp", async () => {
    const f = fixture(); configure(f, "all", "WARN");
    await sink(async captured => {
      await expectStatus(await login(f, "wrong-password-secret"), 401);
      equal(captured.length, 1); equal(event(captured[0]), "login_failed");
    });

    const fAll = fixture(); configure(fAll, "login,token_refresh,sync");
    await sink(async captured => {
      const tokens = await expectJson(await login(fAll), 200);
      equal(event(captured[0]), "login");
      await expectStatus(await fAll.fetch("/identity/connect/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Bitwarden-Client-Version": "2026.10.2" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }) }), 200);
      equal(event(captured[1]), "token_refresh");
      await expectStatus(await fAll.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${await accessToken()}` } }), 200);
      equal(event(captured[2]), "sync");
    });

    const fStamp = fixture(); configure(fStamp, "account-security-changed");
    await sink(async captured => {
      await expectStatus(await fStamp.fetch("/api/accounts/security-stamp", { method: "POST", headers: await owner(),
        body: JSON.stringify({ masterPasswordHash: "hash" }) }), 200);
      equal(captured.length, 1); equal(event(captured[0]), "account-security-changed");
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

  await check("security defaults cover routes, startup failures and notification dispatch", async () => {
    const f = fixture();
    for (const [path, status] of [["/api/alive", 200], ["/api/sync", 401], ["/api/not-a-route", 404]]) {
      const response = await expectStatus(await f.fetch(path), status, path);
      defaults(response);
      await response.arrayBuffer();
    }

    const domain = f.env.DOMAIN;
    f.env.DOMAIN = "https://example.test/forbidden-subpath";
    const startup = await expectStatus(await f.fetch("/api/alive"), 500);
    defaults(startup);
    await startup.arrayBuffer();

    f.env.DOMAIN = domain;
    f.db.prepare = () => { throw new Error("notification dispatch must not query D1"); };
    for (const [path, status] of [["/notifications/hub", 503], ["/notifications/not-a-hub", 404]]) {
      const response = await expectStatus(await f.fetch(path), status, path);
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
    const f = fixture(), before = credentials();
    for (const mode of ["missing", "wrong-type", "throw", "malformed", "deny"]) {
      setLimiter(f, "LOGIN_RATE_LIMITER", mode);
      for (const password of ["hash", "wrong-password"]) await expect(await login(f, password), mode === "deny" ? 429 : 503);
      equal(credentials(), before, `${mode}: unprotected login changed account or sessions`);
    }
    setLimiter(f, "LOGIN_RATE_LIMITER", "allow");
    await expect(await login(f, "wrong-password"), 401);
    const tokens = await expect(await login(f, "hash"), 200);
    equal(typeof tokens.access_token, "string", "login did not recover with a working limiter");
  });

  await check("password-protected Send guesses stop on dependency failures without consuming access", async () => {
    const encoder = new TextEncoder(), password = "client-send-password", salt = Uint8Array.from({ length: 16 }, (_, i) => i);
    const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const hash = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, material, 256))));
    const f = fixture(), accessId = await sendAccessId(f);
    sql.exec("UPDATE sends SET password_hash=?,password_salt=?,password_iterations=100000 WHERE id=?", hash, btoa(String.fromCharCode(...salt)), SEND);
    for (const mode of ["missing", "throw", "malformed", "deny"]) {
      setLimiter(f, "SEND_ACCESS_RATE_LIMITER", mode);
      for (const supplied of [password, "wrong-password"]) await expect(await accessSend(f, accessId, supplied), mode === "deny" ? 429 : 503);
      equal(sql.exec("SELECT access_count FROM sends WHERE id=?", SEND).one().access_count, 0);
    }
    setLimiter(f, "SEND_ACCESS_RATE_LIMITER", "allow");
    await expect(await accessSend(f, accessId, "wrong-password"), 400);
    await expect(await accessSend(f, accessId, password), 200);
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
      setLimiter(f, "LOGIN_RATE_LIMITER", mode);
      const request = new Request(`https://vault.test/notifications/hub?access_token=${await accessToken()}`, { headers: { Upgrade: "websocket", "cf-connecting-ip": ip } });
      const response = await notificationFetch(f, request), body = await response.text();
      equal(response.status, mode === "deny" ? 429 : 503, body);
      equal(body.includes("sensitive-provider-error"), false, "notification error exposed provider context");
    }
  });
}
