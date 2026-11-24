import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import test from "node:test";
import { patchUi, readPinnedVaultVersion, renderAssetHeaders } from "../scripts/patch-ui.mjs";
import { WEB_VAULT_VERSION, archiveVault, writeVault } from "./script-fixtures.mjs";
import { unstable_getVarsForDev, unstable_readConfig } from "wrangler";
import { parseJsonc } from "../scripts/deploy.mjs";
import { fileURLToPath } from "node:url";
import { Log, LogLevel, PLUGINS } from "miniflare";

const run = promisify(execFile);
const prepare = (root, args = [], options = {}) => run("bash", [join(root, "scripts", "prepare-ui.sh"), ...args], { cwd: tmpdir(), ...options });
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
  await writeFile(join(directory, "demo.html"), "unguarded stale demo");
  await prepare(root);
  const first = await readFile(join(directory, "index.html"), "utf8");
  assert.equal(await readFile(join(directory, "_headers"), "utf8"), renderAssetHeaders(root));
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
  await assert.rejects(readFile(join(directory, "demo.html")), { code: "ENOENT" });
});

test("a local pinned archive replaces stale files after successful preparation", async (t) => {
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
});

test("download uses only the pinned GitHub release URL", async (t) => {
  const root = await uiFixture(t);
  const release = join(root, "release", "web-vault");
  await writeVault(release);
  const archive = await archiveVault(release, join(root, "release.tar.gz"));
  const bin = join(root, "bin");
  const capture = join(root, "download-url");
  await mkdir(bin);
  await writeFile(join(bin, "curl"), `#!/usr/bin/env bash
set -euo pipefail
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    https://*) printf '%s' "$1" > "$UI_TEST_CAPTURE"; shift ;;
    *) shift ;;
  esac
done
cp -- "$UI_TEST_ARCHIVE" "$output"
`, { mode: 0o755 });
  await prepare(root, ["--download"], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, UI_TEST_CAPTURE: capture, UI_TEST_ARCHIVE: archive } });
  assert.equal(await readFile(capture, "utf8"), `https://github.com/dani-garcia/bw_web_builds/releases/download/v${WEB_VAULT_VERSION}/bw_web_v${WEB_VAULT_VERSION}.tar.gz`);
});

test("wrong versions and malformed archives preserve the existing vault", async (t) => {
  const root = await uiFixture(t);
  const destination = join(root, "static", "web-vault");
  await writeVault(destination);
  const before = await readFile(join(destination, "index.html"), "utf8");
  const release = join(root, "release", "web-vault");
  await writeVault(release, "2026.6.4");
  const wrongVersion = await archiveVault(release, join(root, "wrong.tar.gz"));
  await assert.rejects(prepare(root, ["--archive", wrongVersion]), { code: 1 });
  const malformed = join(root, "malformed.tar.gz");
  await writeFile(malformed, "not a gzip archive");
  await assert.rejects(prepare(root, ["--archive", malformed]));
  assert.equal(await readFile(join(destination, "index.html"), "utf8"), before);
});

test("archive paths outside web-vault and symbolic links are rejected before installation", async (t) => {
  const root = await uiFixture(t);
  const destination = join(root, "static", "web-vault");
  await writeVault(destination);
  const before = await readFile(join(destination, "index.html"), "utf8");
  await mkdir(join(root, "outside"));
  await writeFile(join(root, "outside", "file"), "must not install");
  const wrongRoot = join(root, "outside.tar.gz");
  await run("tar", ["-czf", wrongRoot, "-C", root, "outside"]);
  await assert.rejects(prepare(root, ["--archive", wrongRoot]), /only paths inside/);
  const release = join(root, "release", "web-vault");
  await writeVault(release);
  await symlink("../../outside", join(release, "link"));
  const links = await archiveVault(release, join(root, "links.tar.gz"));
  await assert.rejects(prepare(root, ["--archive", links]), /without links/);
  assert.equal(await readFile(join(destination, "index.html"), "utf8"), before);
});

test("a real tar entry with parent traversal cannot escape the extraction directory", async (t) => {
  const root = await uiFixture(t);
  const destination = join(root, "static", "web-vault");
  await writeVault(destination);
  const before = await readFile(join(destination, "index.html"), "utf8");
  const archive = join(root, "traversal.tar.gz");
  await writeFile(archive, maliciousArchive("web-vault/../../escaped"));
  await assert.rejects(prepare(root, ["--archive", archive]), /only paths inside/);
  assert.equal(await readFile(join(destination, "index.html"), "utf8"), before);
  await assert.rejects(readFile(join(root, "escaped")), { code: "ENOENT" });
});

test("missing assets, moving version labels and ambiguous input fail clearly", async (t) => {
  const root = await uiFixture(t);
  await assert.rejects(prepare(root), /Missing existing Web Vault/);
  await assert.rejects(prepare(root, ["--download", "--archive"]), /Usage/);
  const release = join(root, "release", "web-vault");
  await writeVault(release);
  const archive = await archiveVault(release, join(root, "release.tar.gz"));
  await assert.rejects(
    prepare(root, ["--archive", archive], { env: { ...process.env, WEB_VAULT_SHA256: "0".repeat(64) } }),
    /SHA-256/,
  );
  await writeFile(join(root, "package.json"), JSON.stringify({ config: { webVaultVersion: "latest" } }));
  assert.throws(() => readPinnedVaultVersion(root), /must pin a release/);
  await assert.rejects(prepare(root), { code: 1 });
});

test("HTML patch validates version and document structure before writing", async (t) => {
  const root = await uiFixture(t);
  const directory = join(root, "static", "web-vault");
  const html = "<html><body>no head</body></html>";
  await writeVault(directory, "2026.6.4", html);
  assert.throws(() => patchUi(root, directory), /does not match pinned/);
  assert.equal(await readFile(join(directory, "index.html"), "utf8"), html);
  await writeFile(join(directory, "vw-version.json"), JSON.stringify({ version: WEB_VAULT_VERSION }));
  assert.throws(() => patchUi(root, directory), /no closing head/);
  assert.equal(await readFile(join(directory, "index.html"), "utf8"), html);
});


test("local dev serves the HTTPS origin required by the pinned Web Vault", async () => {
  const config = parseJsonc(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  const domain = new URL(config.env.local.vars.DOMAIN);
  assert.equal(domain.protocol, "https:");
  assert.equal(domain.hostname, "localhost");
  assert.equal(domain.port, "8787");
  assert.equal(config.dev.local_protocol, "https");
});

test("local env loads credentials from the existing dev vars file", async t => {
  const root = await mkdtemp(join(tmpdir(), "raywarden-dev-vars-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "scripts"));
  for (const name of ["wrangler.jsonc", "scripts/local-config.mjs", "scripts/deploy.mjs"]) {
    await copyFile(new URL(`../${name}`, import.meta.url), join(root, name));
  }
  await writeFile(join(root, ".dev.vars"), "OWNER_SETUP_TOKEN=local-test-token\nJWT_SECRET=local-legacy-key\n");
  await run(process.execPath, ["scripts/local-config.mjs"], { cwd: root });
  const config = join(root, ".wrangler-local.generated.json");
  const generated = parseJsonc(await readFile(config, "utf8"));
  assert.equal(generated.secrets, undefined);
  assert.ok(parseJsonc(await readFile(join(root, "wrangler.jsonc"), "utf8")).secrets.required.includes("KEY_ENCRYPTION_KEY"));
  const local = unstable_readConfig({ config, env: "local" });
  const bindings = unstable_getVarsForDev(config, undefined, local.vars, "local", true, local.secrets);
  assert.deepEqual(bindings.OWNER_SETUP_TOKEN, { type: "secret_text", value: "local-test-token" });
  assert.deepEqual(bindings.JWT_SECRET, { type: "secret_text", value: "local-legacy-key" });
});

async function devFixture(t) {
  const root = await mkdtemp(join(tmpdir(), "raywarden-dev-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const directory of ["scripts", "static/overrides", "bin", "cargo/bin"]) {
    await mkdir(join(root, directory), { recursive: true });
  }
  for (const name of ["Justfile", "package.json", "package-lock.json", "rust-toolchain.toml", "wrangler.jsonc", "scripts/local-config.mjs", "scripts/deploy.mjs", "scripts/patch-ui.mjs", "scripts/prepare-ui.sh", "static/security-headers.json", "static/overrides/vaultwarden.css", "static/overrides/raywarden.js"]) {
    await copyFile(new URL(`../${name}`, import.meta.url), join(root, name));
  }
  const release = join(root, "release", "web-vault");
  await writeVault(release, WEB_VAULT_VERSION, "<html><head></head><body></body></html>");
  await archiveVault(release, join(root, "release.tar.gz"));
  const stub = async (name, source) => writeFile(join(root, name), `#!${process.execPath}\n${source}`, { mode: 0o755 });
  const imports = 'import fs from "node:fs"; const args = process.argv.slice(2); const log = line => fs.appendFileSync(process.env.DEV_TEST_LOG, line + "\\n");\n';
  await stub("bin/npm", imports + `
    log("npm " + args.join(" "));
    if (process.env.DEV_TEST_NPM_FAIL) process.exit(1);
    fs.mkdirSync("node_modules/wrangler/bin", { recursive: true });
    fs.writeFileSync("node_modules/wrangler/package.json", '{"type":"commonjs"}');
    fs.writeFileSync("node_modules/wrangler/bin/wrangler.js", ${JSON.stringify(String.raw`const fs = require("node:fs"); const args = process.argv.slice(2); if (args[0] === "--version") console.log("4.163.0"); else fs.appendFileSync(process.env.DEV_TEST_LOG, "wrangler " + JSON.stringify(args) + "\n");`)});
  `);
  await stub("cargo/bin/rustup", imports + `
    if (args[0] === "toolchain" && args[1] === "install") {
      log("rust-install"); fs.writeFileSync("rust-ready", "yes");
    } else {
      if (!fs.existsSync("rust-ready")) process.exit(1);
      if (args[0] === "run") console.log("rustc pinned");
      if (args[0] === "target") console.log("wasm32-unknown-unknown");
      if (args[0] === "component") console.log("rustfmt-x86_64-unknown-linux-gnu\\nclippy-x86_64-unknown-linux-gnu");
    }
  `);
  await stub("cargo/bin/cargo", imports + `
    log("cargo " + args.join(" "));
    const version = JSON.parse(fs.readFileSync("package.json")).config.workerBuildVersion;
    fs.mkdirSync(".tools/bin", { recursive: true });
    fs.writeFileSync(".tools/bin/worker-build", "#!/usr/bin/env bash\\necho '" + version + "'\\n", { mode: 0o755 });
  `);
  await stub("bin/curl", imports + `
    log("download");
    fs.copyFileSync("release.tar.gz", args[args.indexOf("--output") + 1]);
  `);
  const env = { ...process.env, PATH: `${join(root, "bin")}:${process.env.PATH}`, CARGO_HOME: join(root, "cargo"), JUST_TEMPDIR: root, DEV_TEST_LOG: join(root, "trace") };
  return {
    root,
    just: (recipe, extra = {}) => run("just", [recipe], { cwd: root, env: { ...env, ...extra } }),
    trace: () => readFile(join(root, "trace"), "utf8"),
  };
}

test("just dev prepares a fresh checkout, then reuses tools and UI before local migration and startup", async t => {
  const f = await devFixture(t);
  await f.just("dev");
  const first = await f.trace();
  assert.match(first, /npm ci --include=dev --include=optional --ignore-scripts=false/);
  assert.match(first, /rust-install/);
  assert.match(first, /cargo install worker-build --version =0\.9\.0 --locked --root \.tools/);
  assert.match(first, /download/);
  const commands = first.split("\n")
    .filter(line => line.startsWith("wrangler ["))
    .map(line => JSON.parse(line.slice("wrangler ".length)));
  assert.equal(commands.length, 2);
  assert.deepEqual(commands[0].slice(0, 4), ["d1", "migrations", "apply", "DB"]);
  assert.equal(commands[1][0], "dev");
  for (const args of commands) {
    assert.equal(args[args.indexOf("--config") + 1], ".wrangler-local.generated.json");
    assert.equal(args[args.indexOf("--env") + 1], "local");
    assert.ok(args.includes("--local"));
    assert.equal(args[args.indexOf("--persist-to") + 1], ".wrangler/local");
  }
  assert.ok(first.indexOf("download") < first.indexOf('wrangler ["d1"'));
  assert.ok(first.indexOf('wrangler ["d1"') < first.indexOf('wrangler ["dev"'));
  await f.just("dev");
  const second = (await f.trace()).slice(first.length);
  assert.doesNotMatch(second, /npm |rust-install|cargo |download/);
  assert.match(second, /wrangler \["d1"/);
  assert.match(second, /wrangler \["dev"/);
});

test("changed locks and missing Wrangler trigger installation; failed installs never start dev", async t => {
  const f = await devFixture(t);
  await f.just("setup-node");
  const first = await f.trace();
  await writeFile(join(f.root, "package-lock.json"), (await readFile(join(f.root, "package-lock.json"), "utf8")) + "\n");
  await f.just("setup-node");
  assert.equal((await f.trace()).slice(first.length).match(/npm ci/g)?.length, 1);
  await rm(join(f.root, "node_modules/wrangler/bin/wrangler.js"));
  await assert.rejects(f.just("dev", { DEV_TEST_NPM_FAIL: "1" }));
  assert.doesNotMatch(await f.trace(), /wrangler \[|download/);
  await f.just("dev");
  assert.match(await f.trace(), /wrangler \["dev"/);
});

test("UI preparation downloads missing or incompatible releases and refreshes matching assets offline", async t => {
  const f = await devFixture(t);
  await f.just("ui");
  const first = await f.trace();
  assert.equal(first, "download\n");
  await writeFile(join(f.root, "static/overrides/raywarden.js"), "// updated override\n");
  await f.just("ui");
  assert.equal(await f.trace(), first);
  assert.equal(await readFile(join(f.root, "static/web-vault/js/raywarden.js"), "utf8"), "// updated override\n");
  await writeFile(join(f.root, "static/web-vault/vw-version.json"), '{"version":"2026.6.4"}');
  await f.just("ui");
  assert.equal(await f.trace(), "download\ndownload\n");
  await rm(join(f.root, "static/web-vault/index.html"));
  await f.just("ui");
  assert.equal(await f.trace(), "download\ndownload\ndownload\n");
  await rm(join(f.root, "static/web-vault/index.html"));
  await assert.rejects(f.just("ui-offline"));
  assert.equal(await f.trace(), "download\ndownload\ndownload\n");
});

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

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
