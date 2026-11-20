import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { promisify } from "node:util";
import { PLUGINS, Log, LogLevel } from "miniflare";
import { renderAssetHeaders } from "../scripts/patch-ui.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const run = promisify(execFile);

test("Cloudflare assets parser and workerd preserve static header exceptions without a listener", { timeout: 30000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "raywarden-asset-headers-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const [name, body] of Object.entries({
    "_headers": renderAssetHeaders(root),
    "index.html": "<!doctype html><title>fixture</title>",
    "other.html": "<!doctype html><title>other</title>",
    "webauthn-connector.html": "<!doctype html><title>connector</title>",
    "bundle.js": "self.fixture = true;",
    "logo.svg": '<svg xmlns="http://www.w3.org/2000/svg"/>',
    "404.html": "<!doctype html><title>missing</title>",
  })) await writeFile(join(directory, name), body);

  // Use Cloudflare's installed parser and actual assets/KV workers, then run
  // their requests in workerd's test handler. No Miniflare HTTP proxy/listener
  // or external network is needed in restricted CI environments.
  const services = (await PLUGINS.assets.getServices({
    options: { config: { name: "headers-fixture", compatibilityDate: "2026-10-01", assets: { directory, htmlHandling: "auto-trailing-slash", notFoundHandling: "404-page", hasUserWorker: true } }, dev: { rootPath: root } },
    log: new Log(LogLevel.ERROR), tmpPath: directory,
  })).slice(0, 3);
  const policy = JSON.parse(await readFile(join(root, "static/security-headers.json"), "utf8"));
  const extensions = [{ modules: [{ name: "miniflare:shared", esModule: await readFile(join(root, "node_modules/miniflare/dist/src/workers/shared/index.worker.js"), "utf8") }] }];
  const testSource = `const policy = ${JSON.stringify(policy)};
const equal = (actual, expected, label) => { if (actual !== expected) throw new Error(label + ': ' + actual + ' !== ' + expected); };
export default { async test(_controller, env) {
  for (const path of ["/", "/other", "/bundle.js", "/logo.svg", "/webauthn-connector", "/missing"]) {
    const response = await env.ASSETS.fetch('https://assets.example.test' + path);
    equal(response.status, path === '/missing' ? 404 : 200, path);
    equal(response.headers.get('x-content-type-options'), 'nosniff', path);
    equal(response.headers.get('referrer-policy'), 'no-referrer', path);
    equal(response.headers.get('cache-control'), path === '/bundle.js' || path === '/logo.svg' ? policy.assetCache : policy.dynamicCache, path);
    if (path.endsWith('connector')) {
      equal(response.headers.get('content-security-policy'), null, path);
      equal(response.headers.get('x-frame-options'), null, path);
    } else {
      equal(response.headers.get('content-security-policy'), policy[path.endsWith('.svg') ? 'image' : 'document']['Content-Security-Policy'], path);
    }
    await response.arrayBuffer();
  }
  const first = await env.ASSETS.fetch('https://assets.example.test/bundle.js');
  const etag = first.headers.get('etag');
  await first.arrayBuffer();
  const cached = await env.ASSETS.fetch('https://assets.example.test/bundle.js', { headers: { 'If-None-Match': etag } });
  equal(cached.status, 304, 'conditional GET');
  equal(cached.headers.get('cache-control'), policy.assetCache, 'conditional cache policy');
  equal(cached.headers.get('x-content-type-options'), 'nosniff', 'conditional security headers');
  equal((await env.ASSETS.fetch('https://assets.example.test/_headers')).status, 404, 'policy file is private');
}};`;
  services.push({ name: "test", worker: { compatibilityDate: "2026-10-01", modules: [{ name: "test.mjs", esModule: testSource }], bindings: [{ name: "ASSETS", service: { name: services[2].name } }] } });
  let moduleNumber = 0;
  const files = [];
  const capnp = (value, key) => {
    if (key === "esModule") {
      const name = `module-${moduleNumber++}.mjs`;
      files.push(writeFile(join(directory, name), value));
      return `embed ${JSON.stringify(name)}`;
    }
    if (ArrayBuffer.isView(value)) return `0x"${Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("hex")}"`;
    if (value instanceof ArrayBuffer) return `0x"${Buffer.from(value).toString("hex")}"`;
    if (Array.isArray(value)) return `[${value.map(item => capnp(item)).join(",")}]`;
    if (value && typeof value === "object") return `(${Object.entries(value).filter(([, item]) => item !== undefined).map(([name, item]) => `${name} = ${capnp(item, name)}`).join(",")})`;
    return JSON.stringify(value);
  };
  await writeFile(join(directory, "config.capnp"), `using Workerd = import "/workerd/workerd.capnp"; const config :Workerd.Config = ${capnp({ services, extensions })};`);
  await Promise.all(files);
  await run(join(root, "node_modules/.bin/workerd"), ["test", join(directory, "config.capnp"), "test"], { cwd: directory, timeout: 20000 });
});
