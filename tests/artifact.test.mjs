import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { createArtifactManifest, deployArtifact, parseDeployArgs, verifyArtifact } from "../scripts/deploy.mjs";

const sha = "a".repeat(40);
const head = async () => sha;
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "raywarden-artifact-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const write = (path, content) => { mkdirSync(dirname(join(dir, path)), { recursive: true }); writeFileSync(join(dir, path), content); };
  const config = {
    name: "artifact-worker", main: "build/index.js", build: { command: "must-never-run" }, secrets: { required: ["DOMAIN"] }, vars: { LOG_LEVEL: "info" },
    assets: { directory: "static/web-vault", not_found_handling: "404-page" }, routes: [{ pattern: "vault.example.test", custom_domain: true }],
    d1_databases: [{ binding: "warden-db", database_name: "artifact-db", database_id: "11111111-1111-4111-8111-111111111111", migrations_dir: "sql/migrations" }],
    r2_buckets: [{ binding: "ATTACHMENTS_BUCKET", bucket_name: "artifact-files" }], migrations: [{ tag: "v1", new_sqlite_classes: ["NotifyDo"] }],
  };
  write("wrangler.jsonc", JSON.stringify(config));
  for (const path of ["Cargo.lock", "package-lock.json"]) write(path, "fixture\n");
  write("static/web-vault/index.html", "<!doctype html><title>Fixture</title>");
  write(".wrangler/deploy-check/production/index.js", 'import wasm from "./worker.wasm"; export default {};\n');
  write(".wrangler/deploy-check/production/worker.wasm", Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  const options = { configPath: join(dir, "wrangler.jsonc"), expectedSha: sha };
  return { dir, write, config, options };
}

test("manifest binds source SHA and configuration to final JavaScript/WASM, assets and locks", async (t) => {
  const { options } = fixture(t);
  const manifest = await createArtifactManifest(options, head);
  assert.equal(manifest.sourceSha, sha);
  assert.equal(manifest.environment, "production");
  assert.equal(manifest.entrypoint, ".wrangler/deploy-check/production/index.js");
  assert.deepEqual(Object.keys(manifest.files).sort(), [
    ".wrangler/deploy-check/production/index.js", ".wrangler/deploy-check/production/worker.wasm",
    "static/web-vault/index.html", "Cargo.lock", "package-lock.json",
  ].sort());
  const verified = await verifyArtifact(options, head);
  assert.equal(verified.manifest.sourceSha, sha);
});

test("changed final JavaScript, WASM, assets and locks prevent upload", async (t) => {
  for (const path of [".wrangler/deploy-check/production/index.js", ".wrangler/deploy-check/production/worker.wasm", "static/web-vault/index.html", "Cargo.lock", "package-lock.json"]) {
    const { options, write } = fixture(t);
    await createArtifactManifest(options, head);
    write(path, path.endsWith(".wasm") ? Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 0, 1, 0]) : "changed\n");
    let deployed = false;
    await assert.rejects(deployArtifact(options, () => { deployed = true; }, head, {}), /digest mismatch/);
    assert.equal(deployed, false);
  }
});

test("missing final JavaScript, WASM, assets and locks prevent upload", async (t) => {
  for (const path of [".wrangler/deploy-check/production/index.js", ".wrangler/deploy-check/production/worker.wasm", "static/web-vault/index.html", "Cargo.lock", "package-lock.json"]) {
    const { options, dir } = fixture(t);
    await createArtifactManifest(options, head);
    rmSync(join(dir, path));
    let deployed = false;
    await assert.rejects(deployArtifact(options, () => { deployed = true; }, head, {}), /inventory|no WASM|Missing/);
    assert.equal(deployed, false);
  }
});

test("typed WASM validation rejects a file without a WASM header", async (t) => {
  const { options, write } = fixture(t);
  write(".wrangler/deploy-check/production/worker.wasm", "invalid WASM");
  await assert.rejects(createArtifactManifest(options, head), /Invalid WASM module/);
});

test("wrong commit, environment or configuration cannot reuse an artifact", async (t) => {
  const { options, write, config } = fixture(t);
  const manifest = await createArtifactManifest(options, head);
  await assert.rejects(verifyArtifact(options, async () => "b".repeat(40)), /source SHA/);
  await assert.rejects(verifyArtifact({ ...options, expectedSha: "b".repeat(40) }, head), /source SHA/);
  write(".wrangler/artifact-manifest.json", JSON.stringify({ ...manifest, environment: "dev" }));
  await assert.rejects(verifyArtifact(options, head), /environment/);
  write(".wrangler/artifact-manifest.json", JSON.stringify(manifest));
  config.routes[0].pattern = "changed.example.test";
  write("wrangler.jsonc", JSON.stringify(config));
  await assert.rejects(verifyArtifact(options, head), /configuration changed/);
});

test("missing or added artifact modules are rejected before upload", async (t) => {
  const { options, write, dir } = fixture(t);
  await createArtifactManifest(options, head);
  write(".wrangler/deploy-check/production/unexpected.js", "export default 1;");
  await assert.rejects(verifyArtifact(options, head), /inventory/);
  rmSync(join(dir, ".wrangler/deploy-check/production/unexpected.js"));
  rmSync(join(dir, "static/web-vault/index.html"));
  await assert.rejects(verifyArtifact(options, head), /Missing prepared Web Vault/);
});

test("compiled deployment disables both custom and internal builds and retains resource identities", async (t) => {
  const { options, dir, config } = fixture(t);
  await createArtifactManifest(options, head);
  let temporary;
  let called = 0;
  await deployArtifact(options, (args, commandOptions) => {
    called++;
    assert.equal(commandOptions.projectRoot, dir);
    assert.deepEqual(args.slice(0, 2), ["deploy", "--no-bundle"]);
    assert.deepEqual(args.slice(-2), ["--env", ""]);
    assert.ok(!args.includes("--no-build"));
    temporary = args[args.indexOf("--config") + 1];
    const secretsFile = args[args.indexOf("--secrets-file") + 1];
    assert.deepEqual(JSON.parse(readFileSync(secretsFile, "utf8")), { DOMAIN: "https://vault.example.test" });
    assert.equal(statSync(dirname(secretsFile)).mode & 0o777, 0o700);
    assert.equal(statSync(secretsFile).mode & 0o777, 0o600);
    const deployed = JSON.parse(readFileSync(temporary, "utf8"));
    assert.equal(deployed.build, undefined);
    assert.equal(deployed.env, undefined);
    assert.equal(deployed.main, join(dir, ".wrangler/deploy-check/production/index.js"));
    assert.equal(deployed.base_dir, join(dir, ".wrangler/deploy-check/production"));
    assert.equal(deployed.find_additional_modules, true);
    assert.ok(deployed.rules.some((r) => r.type === "CompiledWasm"));
    assert.ok(deployed.rules.some((r) => r.type === "ESModule"));
    assert.ok(deployed.rules.every((r) => ["ESModule", "CommonJS", "CompiledWasm", "Text", "Data"].includes(r.type)));
    assert.equal(deployed.assets.directory, join(dir, "static/web-vault"));
    assert.equal(deployed.d1_databases[0].database_id, config.d1_databases[0].database_id);
    assert.equal(deployed.d1_databases[0].database_name, config.d1_databases[0].database_name);
    assert.equal(deployed.d1_databases[0].migrations_dir, join(dir, "sql/migrations"));
    assert.deepEqual(deployed.routes, config.routes);
    assert.deepEqual(deployed.vars, config.vars);
    assert.deepEqual(deployed.secrets, { required: ["DOMAIN"] });
    assert.equal(deployed.vars.DOMAIN, undefined);
  }, head, {});
  assert.equal(called, 1);
  assert.equal(existsSync(temporary), false);
  assert.deepEqual(JSON.parse(readFileSync(options.configPath, "utf8")), config);
});



test("failed artifact upload cleans its temporary configuration without rebuilding", async (t) => {
  const { options } = fixture(t);
  await createArtifactManifest(options, head);
  let temporary, secretsFile;
  await assert.rejects(deployArtifact(options, (args) => {
    temporary = args[args.indexOf("--config") + 1];
    secretsFile = args[args.indexOf("--secrets-file") + 1];
    assert.equal(existsSync(secretsFile), true);
    throw new Error("upload failed");
  }, head, {}), /upload failed/);
  assert.equal(existsSync(temporary), false);
  assert.equal(existsSync(secretsFile), false);
  assert.equal(existsSync(dirname(temporary)), false);
});

test("first upload supplies private owner secrets and the selected origin without putting values in argv or child environment", async (t) => {
  const { options, config } = fixture(t);
  await createArtifactManifest(options, head);
  const environment = { ALLOWED_EMAILS: " Owner+Vault@Example.Test ", OWNER_SETUP_TOKEN: "fake-private-setup-token-".repeat(2), DOMAIN: "https://ignored.example.test", CLOUDFLARE_API_TOKEN: "fake-cloudflare-token" };
  let temporary;
  await deployArtifact(options, (args, commandOptions) => {
    temporary = args[args.indexOf("--secrets-file") + 1];
    assert.deepEqual(JSON.parse(readFileSync(temporary, "utf8")), {
      ALLOWED_EMAILS: "owner+vault@example.test", OWNER_SETUP_TOKEN: environment.OWNER_SETUP_TOKEN, DOMAIN: "https://vault.example.test",
    });
    assert.equal(commandOptions.environment.ALLOWED_EMAILS, undefined);
    assert.equal(commandOptions.environment.OWNER_SETUP_TOKEN, undefined);
    assert.equal(commandOptions.environment.CLOUDFLARE_API_TOKEN, environment.CLOUDFLARE_API_TOKEN);
    for (const value of [environment.ALLOWED_EMAILS, environment.OWNER_SETUP_TOKEN]) assert.equal(args.join(" ").includes(value), false);
    const deployed = JSON.parse(readFileSync(args[args.indexOf("--config") + 1], "utf8"));
    assert.deepEqual(deployed.vars, config.vars);
  }, head, environment);
  assert.equal(existsSync(temporary), false);
  assert.equal(existsSync(dirname(temporary)), false);
});

test("redeploying without optional values preserves existing owner secrets rather than clearing them", async (t) => {
  for (const environment of [{}, { ALLOWED_EMAILS: "", OWNER_SETUP_TOKEN: "" }]) {
    const { options } = fixture(t);
    await createArtifactManifest(options, head);
    await deployArtifact(options, (args) => {
      assert.deepEqual(JSON.parse(readFileSync(args[args.indexOf("--secrets-file") + 1], "utf8")), { DOMAIN: "https://vault.example.test" });
    }, head, environment);
  }
});

test("invalid owner configuration fails before discovery, private files or upload without exposing values", async (t) => {
  const { options, dir } = fixture(t);
  await createArtifactManifest(options, head);
  const invalid = [
    ...[" ", "a@b.test,c@d.test", "a@b.test\nc@d.test", "*@example.test", "a?@example.test", "a@example", "a..b@example.test", ".a@example.test", "a.@example.test", "a@example..test", "a@-example.test", "a@exam_ple.test", "a".repeat(65) + "@example.test", "\u0085owner@example.test", "\u00a0owner@example.test\u00a0"].map(ALLOWED_EMAILS => ({ ALLOWED_EMAILS })),
    ...["a".repeat(31), "a".repeat(513), "😀".repeat(513), " a".repeat(32), "a".repeat(32) + " ", "a".repeat(32) + "\n", "a".repeat(32) + "\u0085"].map(OWNER_SETUP_TOKEN => ({ OWNER_SETUP_TOKEN })),
  ];
  for (const environment of invalid) {
    let uploads = 0, requests = 0;
    await assert.rejects(deployArtifact(options, () => { uploads++; }, head, environment, () => { requests++; }), error => {
      assert.match(error.message, /ALLOWED_EMAILS must|OWNER_SETUP_TOKEN must/);
      if (Object.values(environment)[0].trim().length > 1) assert.equal(error.message.includes(Object.values(environment)[0]), false);
      return true;
    });
    assert.equal(uploads, 0);
    assert.equal(requests, 0);
    assert.equal(readdirSync(join(dir, ".wrangler")).some(name => name.startsWith("compiled-config-")), false);
  }
});

test("setup token limits count Unicode characters while preserving the original bytes", async (t) => {
  const { options } = fixture(t);
  await createArtifactManifest(options, head);
  for (const token of ["a".repeat(32), "a".repeat(512), "😀".repeat(512)]) {
    await deployArtifact(options, (args) => {
      assert.equal(JSON.parse(readFileSync(args[args.indexOf("--secrets-file") + 1], "utf8")).OWNER_SETUP_TOKEN, token);
    }, head, { OWNER_SETUP_TOKEN: token });
  }
});

test("workers.dev first upload resolves the account subdomain before supplying DOMAIN", async (t) => {
  const { options, write, config } = fixture(t);
  delete config.routes;
  config.workers_dev = true;
  write("wrangler.jsonc", JSON.stringify(config));
  await createArtifactManifest(options, head);
  const account = "a".repeat(32), calls = [];
  await deployArtifact(options, (args) => {
    assert.deepEqual(JSON.parse(readFileSync(args[args.indexOf("--secrets-file") + 1], "utf8")), { DOMAIN: "https://artifact-worker.my-account.workers.dev" });
  }, head, { CLOUDFLARE_API_TOKEN: "fake-token", CLOUDFLARE_ACCOUNT_ID: account }, async (url, request) => {
    calls.push(url);
    assert.equal(url, `https://api.cloudflare.com/client/v4/accounts/${account}/workers/subdomain`);
    assert.equal(request.method ?? "GET", "GET");
    assert.equal(request.headers.Authorization, "Bearer fake-token");
    return Response.json({ success: true, result: { subdomain: "my-account" } });
  });
  assert.equal(calls.length, 1);
  await assert.rejects(deployArtifact(options, () => assert.fail("must not upload"), head, {}), /CLOUDFLARE_API_TOKEN is required/);
});

test("the default uploader propagates Wrangler process failure and removes its temporary configuration", async (t) => {
  const { options, dir, write } = fixture(t);
  write("node_modules/wrangler/bin/wrangler.js", 'require("node:fs").writeFileSync("invocation.json", JSON.stringify(process.argv.slice(2))); process.exitCode = 7;\n');
  await createArtifactManifest(options, head);
  await assert.rejects(deployArtifact(options, undefined, head, {}), { code: 7 });
  const args = JSON.parse(readFileSync(join(dir, "invocation.json"), "utf8"));
  assert.deepEqual(args.slice(0, 2), ["deploy", "--no-bundle"]);
  assert.deepEqual(args.slice(-2), ["--env", ""]);
  assert.equal(existsSync(args[args.indexOf("--config") + 1]), false);
});

test("deployment CLI requires a subcommand with command-specific flags and always targets production", () => {
  assert.throws(() => parseDeployArgs([]), /Usage/);
  assert.throws(() => parseDeployArgs(["--env", "production"]), /Usage/);
  assert.throws(() => parseDeployArgs(["worker", "--env", "dev"]), /Unknown/);
  assert.throws(() => parseDeployArgs(["worker", "--verify-only"]), /Unknown/);
  assert.throws(() => parseDeployArgs(["config", "--manifest", "file.json"]), /apply only/);
  assert.throws(() => parseDeployArgs(["verify", "--manifest"]), /requires a value/);
  assert.throws(() => parseDeployArgs(["verify", "--manifest", "one", "--manifest", "two"]), /duplicate/);
  assert.throws(() => parseDeployArgs(["verify", "--expected-sha", "invalid"]), /full commit SHA/);
  assert.equal(parseDeployArgs(["worker"]).command, "worker");
  assert.deepEqual(parseDeployArgs(["resources"]), { command: "resources" });
  assert.equal(parseDeployArgs(["manifest"], { ARTIFACT_SOURCE_SHA: sha }).expectedSha, sha);
});

test("existing artifacts can be verified and uploaded without raw build output or application sources", async (t) => {
  const { options, dir } = fixture(t);
  for (const path of ["build", "src", "sql", "static/overrides", "Cargo.toml", "rust-toolchain.toml"]) {
    assert.equal(existsSync(join(dir, path)), false);
  }
  await createArtifactManifest(options, head);
  await verifyArtifact(options, head);
  let called = false;
  await deployArtifact(options, (args) => {
    called = true;
    assert.deepEqual(args.slice(0, 2), ["deploy", "--no-bundle"]);
    const config = JSON.parse(readFileSync(args[args.indexOf("--config") + 1], "utf8"));
    assert.equal(config.build, undefined);
    assert.equal(config.main, join(dir, ".wrangler/deploy-check/production/index.js"));
  }, head, {});
  assert.equal(called, true);
});
