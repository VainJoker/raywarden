import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import test from "node:test";
import { renderAssetHeaders } from "../scripts/patch-ui.mjs";
import { unstable_getVarsForDev, unstable_readConfig } from "wrangler";
import { parseJsonc } from "../scripts/deploy.mjs";
import { fileURLToPath } from "node:url";
import { Log, LogLevel, PLUGINS, serializeConfig } from "miniflare";

const run = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WEB_VAULT_VERSION = JSON.parse(await readFile(join(root, "package.json"), "utf8")).config.webVaultVersion;
const prepare = (root, args = [], options = {}) => run("bash", [join(root, "scripts", "prepare-ui.sh"), ...args], { cwd: tmpdir(), ...options });

async function writeVault(directory, version = WEB_VAULT_VERSION, html = "<html><head></head><body><app-root></app-root></body></html>") {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "vw-version.json"), JSON.stringify({ version }));
  await writeFile(join(directory, "index.html"), html);
}

async function archiveVault(source, destination) {
  await run("tar", ["-czf", destination, "-C", dirname(source), basename(source)]);
  return destination;
}

function maliciousArchive(name) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100);
  for (const offset of [100, 108, 116]) header.write("0000644\0", offset, 8);
  header.write("00000000000\0", 124, 12);
  header.write("00000000000\0", 136, 12);
  header.fill(32, 148, 156);
  header.write("0", 156);
  const checksum = header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, "0");
  header.write(`${checksum}\0 `, 148, 8);
  return gzipSync(Buffer.concat([header, Buffer.alloc(1024)]));
}

async function uiFixture(t) {
  const root = await mkdtemp(join(tmpdir(), "raywarden-ui-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "scripts"));
  for (const name of ["prepare-ui.sh", "patch-ui.mjs"]) {
    await copyFile(new URL(`../scripts/${name}`, import.meta.url), join(root, "scripts", name));
  }
  await mkdir(join(root, "static", "overrides"), { recursive: true });
  await copyFile(new URL("../static/security-headers.json", import.meta.url), join(root, "static/security-headers.json"));
  await writeFile(join(root, "package.json"), JSON.stringify({ config: { webVaultVersion: WEB_VAULT_VERSION } }));
  await writeFile(join(root, "static", "overrides", "vaultwarden.css"), "body { color: red; }\n");
  await writeFile(join(root, "static", "overrides", "raywarden.js"), "window.raywarden = true;\n");
  return root;
}

test("offline preparation copies both source assets, removes maps and is idempotent", async (t) => {
  const root = await uiFixture(t);
  const directory = join(root, "static", "web-vault");
  await writeVault(directory, WEB_VAULT_VERSION, '<html><head><script defer src="js/raywarden.js"></script><script src="/js/raywarden.js"></script></head><body><script>/* turnstile-send-guard-v2 */oldGuard();</script></body></html>');
  await mkdir(join(directory, "nested"));
  await writeFile(join(directory, "nested", "bundle.map"), "map");
  await prepare(root);
  const first = await readFile(join(directory, "index.html"), "utf8");
  await prepare(root);
  assert.equal(await readFile(join(directory, "index.html"), "utf8"), first);
  assert.equal(await readFile(join(directory, "_headers"), "utf8"), renderAssetHeaders(root));
  assert.equal(first.match(/js\/raywarden\.js/g).length, 1);
  assert.equal(first.match(/css\/vaultwarden\.css/g).length, 1);
  assert.ok(!first.includes("oldGuard"));
  for (const [folder, name] of [["css", "vaultwarden.css"], ["js", "raywarden.js"]]) {
    assert.equal(await readFile(join(directory, folder, name), "utf8"), await readFile(join(root, "static", "overrides", name), "utf8"));
  }
  await assert.rejects(readFile(join(directory, "nested", "bundle.map")), { code: "ENOENT" });
});

test("local pinned archive replaces stale files and rejects invalid or escaping archives", async (t) => {
  const root = await uiFixture(t);
  const destination = join(root, "static", "web-vault");
  const source = join(root, "release", "web-vault");
  await writeVault(destination);
  await writeFile(join(destination, "stale.js"), "old");
  await writeVault(source);
  await writeFile(join(source, "current.js"), "new");
  const archive = await archiveVault(source, join(root, "release.tar.gz"));
  await prepare(root, ["--archive", archive]);
  assert.equal(await readFile(join(destination, "current.js"), "utf8"), "new");
  await assert.rejects(readFile(join(destination, "stale.js")), { code: "ENOENT" });

  const before = await readFile(join(destination, "index.html"), "utf8");
  await writeVault(source, "2026.6.4");
  await archiveVault(source, archive);
  await assert.rejects(prepare(root, ["--archive", archive]), { code: 1 });
  await assert.rejects(prepare(root, ["--archive", archive], {
    env: { ...process.env, WEB_VAULT_SHA256: "0".repeat(64) },
  }), /SHA-256/);

  const traversal = join(root, "traversal.tar.gz");
  await writeFile(traversal, maliciousArchive("web-vault/../../escaped"));
  await assert.rejects(prepare(root, ["--archive", traversal]), /only paths inside/);
  await symlink("../../outside", join(source, "link"));
  const links = await archiveVault(source, join(root, "links.tar.gz"));
  await assert.rejects(prepare(root, ["--archive", links]), /without links/);
  assert.equal(await readFile(join(destination, "index.html"), "utf8"), before);
});

test("local env loads credentials from the existing dev vars file", async t => {
  const root = await mkdtemp(join(tmpdir(), "raywarden-dev-vars-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "scripts"));
  for (const name of ["wrangler.jsonc", "scripts/local-config.mjs", "scripts/deploy.mjs"]) {
    await copyFile(new URL(`../${name}`, import.meta.url), join(root, name));
  }
  await writeFile(join(root, ".dev.vars"), "OWNER_SETUP_TOKEN=local-test-token\n");
  await run(process.execPath, ["scripts/local-config.mjs"], { cwd: root });
  const config = join(root, ".wrangler-local.generated.json");
  const generated = parseJsonc(await readFile(config, "utf8"));
  assert.equal(generated.secrets, undefined);
  assert.ok(parseJsonc(await readFile(join(root, "wrangler.jsonc"), "utf8")).secrets.required.includes("KEY_ENCRYPTION_KEY"));
  const local = unstable_readConfig({ config, env: "local" });
  const bindings = unstable_getVarsForDev(config, undefined, local.vars, "local", true, local.secrets);
  assert.deepEqual(bindings.OWNER_SETUP_TOKEN, { type: "secret_text", value: "local-test-token" });
});

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
  const config = join(directory, "config.bin");
  await writeFile(config, serializeConfig({ services, extensions }));
  await run(join(root, "node_modules/.bin/workerd"), ["test", "--binary", config, "test"], { cwd: directory, timeout: 20000 });
});
