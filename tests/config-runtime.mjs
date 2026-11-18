function equal(actual, expected, label = "value") {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
}

export async function runConfigurationCompatibility({ fixture, check }) {
  const origin = "https://client.test";
  function headers(response, expected) {
    equal(response.headers.get("Access-Control-Allow-Origin"), expected, "allowed origin");
    equal(response.headers.get("Access-Control-Allow-Credentials"), null, "cookie credentials");
  }

  await check("DOMAIN is a canonical origin and rejects credentials, paths and insecure public addresses", async () => {
    for (const value of [
      "https://user:private-password@vault.test", "https://vault.test/api", "https://vault.test?token=private-token",
      "https://vault.test#fragment", "http://vault.test", "https://vault.test\\path", "https://vault. test",
    ]) {
      const f = fixture();
      f.env.DOMAIN = value;
      const response = await f.fetch("/api/config");
      equal(response.status, 500);
      const body = await response.text();
      if (body.includes("private-password") || body.includes("private-token")) throw new Error("invalid DOMAIN exposed configuration credentials");
    }
    for (const [value, expected] of [[" HTTPS://VAULT.TEST:443/ ", "https://vault.test"], ["http://localhost:8787/", "http://localhost:8787"]]) {
      const f = fixture();
      f.env.DOMAIN = value;
      const response = await f.fetch("/api/config");
      equal(response.status, 200);
      equal((await response.json()).environment.vault, expected);
    }
  });

  await check("CORS canonical variable, legacy alias, wildcard and restrictive invalid lists share one policy", async () => {
    for (const [primary, legacy, expected] of [
      [undefined, origin, origin], [undefined, undefined, "*"], ["", "https://other.test", "*"],
      ["*", "https://other.test", "*"], [origin, "https://other.test", origin],
      ["https://other.test", origin, null], ["not-an-origin", origin, null],
      ["https://user:pass@client.test", origin, null], [",,,", origin, null],
    ]) {
      const f = fixture();
      if (primary !== undefined) f.env.CORS_ALLOWED_ORIGINS = primary;
      if (legacy === undefined) delete f.env.ALLOWED_ORIGINS; else f.env.ALLOWED_ORIGINS = legacy;
      const alive = await f.fetch("/api/alive", { headers: { Origin: origin } });
      equal(alive.status, 200); headers(alive, expected);
      const preflight = await f.fetch("/api/sync", { method: "OPTIONS", headers: { Origin: origin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization,device-type" } });
      headers(preflight, expected);
      const outer = await f.fetch("/notifications/internal/fanout", { method: "POST", headers: { Origin: origin } });
      equal(outer.status, 404); headers(outer, expected);
      const notifyPreflight = await f.fetch("/notifications/hub/negotiate", { method: "OPTIONS", headers: { Origin: origin } });
      equal(notifyPreflight.status, 204); headers(notifyPreflight, expected);
      delete f.env["warden-db"];
      const failure = await f.fetch("/api/alive", { headers: { Origin: origin } });
      equal(failure.status, 500); headers(failure, expected);
    }
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
