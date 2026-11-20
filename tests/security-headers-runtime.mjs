export function assertDownloadSecurityHeaders(response, disposition = "attachment") {
  for (const [name, expected] of [
    ["content-type", "application/octet-stream"],
    ["content-disposition", disposition],
    ["content-security-policy", "default-src 'none'; sandbox"],
    ["x-content-type-options", "nosniff"],
    ["cache-control", "private, no-store"],
  ]) {
    const actual = response.headers.get(name);
    if (actual !== expected) throw new Error(`download ${name}: expected ${expected}, received ${actual}`);
  }
}

/** Real compiled Worker defaults, including failures outside the Axum router. */
export async function runSecurityHeadersCompatibility({ fixture, check, accessToken, CIPHER, FILE }) {
  const equal = (actual, expected, label) => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const defaults = (response) => {
    equal(response.headers.get("x-content-type-options"), "nosniff", "nosniff");
    equal(response.headers.get("referrer-policy"), "no-referrer", "referrer policy");
    equal(response.headers.get("x-robots-tag"), "noindex, nofollow", "robots policy");
    equal(response.headers.get("cache-control"), "private, no-store", "dynamic cache policy");
    if (!response.headers.get("content-security-policy")?.includes("default-src 'none'")) throw new Error("missing inert API CSP");
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

  await check("page-specific CSP and CSS cache validators survive shared defaults", async () => {
    const f = fixture({ empty: true });
    const page = await f.fetch("/setup");
    equal(page.status, 200, "setup status");
    if (!page.headers.get("content-security-policy")?.includes("'unsafe-inline'")) throw new Error("setup inline-script policy was overwritten");
    await page.arrayBuffer();
    const css = await f.fetch("/css/vaultwarden.css");
    equal(css.headers.get("cache-control"), "public, no-cache", "CSS revalidation policy");
    const etag = css.headers.get("etag");
    await css.arrayBuffer();
    const cached = await f.fetch("/css/vaultwarden.css", { headers: { "If-None-Match": etag } });
    equal(cached.status, 304, "CSS cache hit");
    equal(cached.headers.get("etag"), etag, "CSS ETag");
    equal(cached.headers.get("cache-control"), "public, no-cache", "304 cache policy");
    equal(cached.headers.get("x-content-type-options"), "nosniff", "304 security headers");
  });

  await check("attachment sandbox policy survives shared defaults and untrusted stored document metadata", async () => {
    const f = fixture();
    const bytes = new TextEncoder().encode("<html>harmless download fixture</html>");
    const storageKey = `${CIPHER}/${FILE}`;
    f.bucket.objects.set(storageKey, bytes);
    f.bucket.httpMetadata.set(storageKey, { contentType: "text/html; charset=utf-8" });
    f.db.attachment.file_name = 'encrypted-name\"; unsafe=\"ignored';
    const metadataResponse = await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { headers: { Authorization: `Bearer ${await accessToken()}` } });
    equal(metadataResponse.status, 200, "attachment metadata");
    const url = new URL((await metadataResponse.json()).url);
    for (const [method, headers, status] of [["GET", {}, 200], ["HEAD", {}, 200], ["GET", { Range: "bytes=0-5" }, 206], ["HEAD", { Range: "bytes=0-5" }, 206]]) {
      const response = await f.fetch(url.pathname + url.search, { method, headers });
      equal(response.status, status, `${method} download status`);
      assertDownloadSecurityHeaders(response);
      defaults(response);
      const actual = new Uint8Array(await response.arrayBuffer());
      const expected = method === "HEAD" ? new Uint8Array() : status === 206 ? bytes.subarray(0, 6) : bytes;
      equal(Array.from(actual).join(","), Array.from(expected).join(","), "download bytes");
    }
  });
}
