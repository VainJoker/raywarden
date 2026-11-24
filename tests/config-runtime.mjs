import { equal, expectJson, ok } from "./runtime-assertions.mjs";

export async function runConfigurationCompatibility({ fixture, check }) {
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
