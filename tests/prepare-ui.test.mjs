import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import test from "node:test";
import { renderAssetHeaders, patchUi, readPinnedVaultVersion } from "../scripts/patch-ui.mjs";

const run = promisify(execFile);
const WEB_VAULT_VERSION = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")).config.webVaultVersion;
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

async function fixture(t) {
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

async function vault(directory, version = WEB_VAULT_VERSION, html = "<html><head></head><body><app-root></app-root></body></html>") {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "vw-version.json"), JSON.stringify({ version }));
  await writeFile(join(directory, "index.html"), html);
}

test("offline preparation copies both source assets, removes maps and is idempotent", async (t) => {
  const root = await fixture(t);
  const directory = join(root, "static", "web-vault");
  await vault(directory, WEB_VAULT_VERSION, '<html><head><script defer src="js/raywarden.js"></script><script src="/js/raywarden.js"></script></head><body><script>/* turnstile-send-guard-v2 */oldGuard();</script></body></html>');
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
  const root = await fixture(t);
  const destination = join(root, "static", "web-vault");
  const source = join(root, "release", "web-vault");
  await vault(destination);
  await writeFile(join(destination, "stale.js"), "old");
  await vault(source);
  await writeFile(join(source, "current.js"), "new");
  const archive = join(root, "release.tar.gz");
  await run("tar", ["-czf", archive, "-C", join(root, "release"), "web-vault"]);
  await prepare(root, ["--archive", archive]);
  assert.equal(await readFile(join(destination, "current.js"), "utf8"), "new");
  await assert.rejects(readFile(join(destination, "stale.js")), { code: "ENOENT" });
});

test("download uses only the pinned GitHub release URL", async (t) => {
  const root = await fixture(t);
  await vault(join(root, "release", "web-vault"));
  const archive = join(root, "release.tar.gz");
  await run("tar", ["-czf", archive, "-C", join(root, "release"), "web-vault"]);
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
  const root = await fixture(t);
  const destination = join(root, "static", "web-vault");
  await vault(destination);
  const before = await readFile(join(destination, "index.html"), "utf8");
  await vault(join(root, "release", "web-vault"), "2026.6.4");
  const wrongVersion = join(root, "wrong.tar.gz");
  await run("tar", ["-czf", wrongVersion, "-C", join(root, "release"), "web-vault"]);
  await assert.rejects(prepare(root, ["--archive", wrongVersion]), { code: 1 });
  const malformed = join(root, "malformed.tar.gz");
  await writeFile(malformed, "not a gzip archive");
  await assert.rejects(prepare(root, ["--archive", malformed]));
  assert.equal(await readFile(join(destination, "index.html"), "utf8"), before);
});

test("archive paths outside web-vault and symbolic links are rejected before installation", async (t) => {
  const root = await fixture(t);
  const destination = join(root, "static", "web-vault");
  await vault(destination);
  const before = await readFile(join(destination, "index.html"), "utf8");
  await mkdir(join(root, "outside"));
  await writeFile(join(root, "outside", "file"), "must not install");
  const wrongRoot = join(root, "outside.tar.gz");
  await run("tar", ["-czf", wrongRoot, "-C", root, "outside"]);
  await assert.rejects(prepare(root, ["--archive", wrongRoot]), /only paths inside/);
  await vault(join(root, "release", "web-vault"));
  await symlink("../../outside", join(root, "release", "web-vault", "link"));
  const links = join(root, "links.tar.gz");
  await run("tar", ["-czf", links, "-C", join(root, "release"), "web-vault"]);
  await assert.rejects(prepare(root, ["--archive", links]), /without links/);
  assert.equal(await readFile(join(destination, "index.html"), "utf8"), before);
});

test("a real tar entry with parent traversal cannot escape the extraction directory", async (t) => {
  const root = await fixture(t);
  const destination = join(root, "static", "web-vault");
  await vault(destination);
  const before = await readFile(join(destination, "index.html"), "utf8");
  const archive = join(root, "traversal.tar.gz");
  await writeFile(archive, maliciousArchive("web-vault/../../escaped"));
  await assert.rejects(prepare(root, ["--archive", archive]), /only paths inside/);
  assert.equal(await readFile(join(destination, "index.html"), "utf8"), before);
  await assert.rejects(readFile(join(root, "escaped")), { code: "ENOENT" });
});

test("missing assets, moving version labels and ambiguous input fail clearly", async (t) => {
  const root = await fixture(t);
  await assert.rejects(prepare(root), /Missing existing Web Vault/);
  await assert.rejects(prepare(root, ["--download", "--archive"]), /Usage/);
  await writeFile(join(root, "package.json"), JSON.stringify({ config: { webVaultVersion: "latest" } }));
  assert.throws(() => readPinnedVaultVersion(root), /must pin a release/);
  await assert.rejects(prepare(root), { code: 1 });
});

test("HTML patch validates version and document structure before writing", async (t) => {
  const root = await fixture(t);
  const directory = join(root, "static", "web-vault");
  const html = "<html><body>no head</body></html>";
  await vault(directory, "2026.6.4", html);
  assert.throws(() => patchUi(root, directory), /does not match pinned/);
  assert.equal(await readFile(join(directory, "index.html"), "utf8"), html);
  await writeFile(join(directory, "vw-version.json"), JSON.stringify({ version: WEB_VAULT_VERSION }));
  assert.throws(() => patchUi(root, directory), /no closing head/);
  assert.equal(await readFile(join(directory, "index.html"), "utf8"), html);
});
