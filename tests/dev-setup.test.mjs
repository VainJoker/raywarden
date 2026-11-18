import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { parseJsonc } from "../scripts/deploy.mjs";

const run = promisify(execFile);

test("local dev serves the HTTPS origin required by the pinned Web Vault", async () => {
  const config = parseJsonc(await readFile(new URL("../wrangler.local.jsonc", import.meta.url), "utf8"));
  const domain = new URL(config.vars.DOMAIN);
  assert.equal(domain.protocol, "https:");
  assert.equal(domain.hostname, "localhost");
  assert.equal(domain.port, "8787");
  assert.equal(config.dev.local_protocol, "https");
});

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "raywarden-dev-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const directory of ["scripts", "static/overrides", "bin", "cargo/bin", "release/web-vault"]) {
    await mkdir(join(root, directory), { recursive: true });
  }
  for (const name of ["Justfile", "package.json", "package-lock.json", "rust-toolchain.toml", "scripts/patch-ui.mjs", "scripts/prepare-ui.sh", "static/overrides/vaultwarden.css", "static/overrides/raywarden.js"]) {
    await copyFile(new URL(`../${name}`, import.meta.url), join(root, name));
  }
  await writeFile(join(root, "release/web-vault/vw-version.json"), '{"version":"2026.7.0"}');
  await writeFile(join(root, "release/web-vault/index.html"), "<html><head></head><body></body></html>");
  await run("tar", ["-czf", join(root, "release.tar.gz"), "-C", join(root, "release"), "web-vault"]);
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
  const f = await fixture(t);
  await f.just("dev");
  const first = await f.trace();
  assert.match(first, /npm ci --include=dev --include=optional --ignore-scripts=false/);
  assert.match(first, /rust-install/);
  assert.match(first, /cargo install worker-build --version =0\.9\.0 --locked --root \.tools/);
  assert.match(first, /download/);
  assert.match(first, /wrangler \["d1","migrations","apply","warden-db".*"--local".*"\.wrangler\/local"/);
  assert.match(first, /wrangler \["dev","--local","--config","wrangler.local.jsonc"/);
  assert.ok(first.indexOf("download") < first.indexOf('wrangler ["d1"'));
  assert.ok(first.indexOf('wrangler ["d1"') < first.indexOf('wrangler ["dev"'));
  await f.just("dev");
  const second = (await f.trace()).slice(first.length);
  assert.doesNotMatch(second, /npm |rust-install|cargo |download/);
  assert.match(second, /wrangler \["d1"/);
  assert.match(second, /wrangler \["dev"/);
});

test("changed locks and missing Wrangler trigger installation; failed installs never start dev", async t => {
  const f = await fixture(t);
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
  const f = await fixture(t);
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
