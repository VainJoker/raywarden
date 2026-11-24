import { equal, ok } from "./runtime-assertions.mjs";

/** Real compiled Worker defaults, including failures outside the Axum router. */
export async function runSecurityHeadersCompatibility({ fixture, check }) {
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
