import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { artifactReleaseId, createArtifactManifest, deployArtifact, parseDeployArgs, verifyArtifact } from "../scripts/deploy.mjs";
import { productionConfig } from "./fixtures/production-config.mjs";

const sha = "a".repeat(40);
const head = async () => sha;
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "raywarden-artifact-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const write = (path, content) => { mkdirSync(dirname(join(dir, path)), { recursive: true }); writeFileSync(join(dir, path), content); };
  const config = {
    ...productionConfig({ name: "artifact-worker", databaseName: "artifact-db", bucketName: "artifact-files" }),
    main: "build/index.js",
    build: { command: "must-never-run" },
    vars: { LOG_LEVEL: "info" },
    assets: { directory: "static/web-vault", not_found_handling: "404-page" },
    migrations: [{ tag: "v1", new_sqlite_classes: ["notifydo"] }],
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

test("real Git subprocess receives no application Secrets while resolving the artifact commit", async (t) => {
  const { dir, options, write } = fixture(t), observation = join(dir, "git-environment.json");
  write("bin/git", `#!${process.execPath}\nconst fs = require("node:fs");\nfs.writeFileSync(${JSON.stringify(observation)}, JSON.stringify(Object.fromEntries(["ALLOWED_EMAILS","OWNER_SETUP_TOKEN","KEY_ENCRYPTION_KEY"].map(name => [name, Object.hasOwn(process.env,name)]))));\nfs.writeSync(1, ${JSON.stringify(sha + "\n")});\n`);
  chmodSync(join(dir, "bin/git"), 0o700);
  const inherited = process.env;
  try {
    process.env = { PATH: `${join(dir, "bin")}:${inherited.PATH}`, ALLOWED_EMAILS: "fake@example.test", OWNER_SETUP_TOKEN: "fake-setup", KEY_ENCRYPTION_KEY: "fake-root" };
    await createArtifactManifest(options);
  } finally { process.env = inherited; }
  assert.deepEqual(JSON.parse(readFileSync(observation, "utf8")), { ALLOWED_EMAILS: false, OWNER_SETUP_TOKEN: false, KEY_ENCRYPTION_KEY: false });
});

test("changed or missing final JavaScript, WASM, assets and locks prevent upload", async (t) => {
  const files = [
    ".wrangler/deploy-check/production/index.js", ".wrangler/deploy-check/production/worker.wasm",
    "static/web-vault/index.html", "Cargo.lock", "package-lock.json",
  ];
  for (const path of files) {
    const { options, dir, write } = fixture(t);
    await createArtifactManifest(options, head);
    const upload = () => assert.fail(`Invalid artifact reached the uploader: ${path}`);
    const original = readFileSync(join(dir, path));
    const tampered = path.endsWith(".wasm") ? Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 0, 1, 0]) : "changed\n";
    write(path, tampered);
    await assert.rejects(deployArtifact(options, upload, head, {}), /digest mismatch/, `changed ${path}`);
    write(path, original);

    rmSync(join(dir, path));
    const missing = path === "static/web-vault/index.html" ? /Missing prepared Web Vault/ : /inventory|no WASM|Missing/;
    await assert.rejects(deployArtifact(options, upload, head, {}), missing, `missing ${path}`);
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

test("unexpected artifact modules are rejected by verification", async (t) => {
  const { options, write } = fixture(t);
  await createArtifactManifest(options, head);
  write(".wrangler/deploy-check/production/unexpected.js", "export default 1;");
  await assert.rejects(verifyArtifact(options, head), /inventory/);
});

test("compiled deployment disables both custom and internal builds and retains resource identities", async (t) => {
  const { options, dir, config } = fixture(t);
  const manifest = await createArtifactManifest(options, head);
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
    assert.deepEqual(deployed.vars, { ...config.vars, RAYWARDEN_RELEASE_ID: artifactReleaseId(manifest) });
    assert.deepEqual(deployed.ratelimits, config.ratelimits);
    assert.deepEqual(deployed.secrets, config.secrets);
    assert.deepEqual(deployed.observability, config.observability);
    assert.equal(deployed.vars.DOMAIN, undefined);
  }, head, {});
  assert.equal(called, 1);
  assert.equal(existsSync(temporary), false);
  assert.deepEqual(JSON.parse(readFileSync(options.configPath, "utf8")), config);
});

test("missing required rate limit bindings reject artifact upload before network or private files", async (t) => {
  const { options, dir, config, write } = fixture(t);
  await createArtifactManifest(options, head);
  delete config.ratelimits;
  write("wrangler.jsonc", JSON.stringify(config));
  let uploads = 0, requests = 0;
  await assert.rejects(deployArtifact(options, () => { uploads++; }, head, {}, () => { requests++; }), /requires ratelimits/);
  assert.equal(uploads, 0);
  assert.equal(requests, 0);
  assert.equal(readdirSync(join(dir, ".wrangler")).some(name => name.startsWith("compiled-config-")), false);
});



test("first upload supplies private owner secrets and the selected origin without putting values in argv or child environment", async (t) => {
  const { options, config } = fixture(t);
  const manifest = await createArtifactManifest(options, head);
  const environment = { ALLOWED_EMAILS: " Owner+Vault@Example.Test ", OWNER_SETUP_TOKEN: "fake-private-setup-token-".repeat(2), KEY_ENCRYPTION_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", DOMAIN: "https://ignored.example.test", CLOUDFLARE_API_TOKEN: "fake-cloudflare-token" };
  let temporary;
  await deployArtifact(options, (args, commandOptions) => {
    temporary = args[args.indexOf("--secrets-file") + 1];
    assert.deepEqual(JSON.parse(readFileSync(temporary, "utf8")), {
      ALLOWED_EMAILS: "owner+vault@example.test", OWNER_SETUP_TOKEN: environment.OWNER_SETUP_TOKEN, DOMAIN: "https://vault.example.test",
      KEY_ENCRYPTION_KEY: environment.KEY_ENCRYPTION_KEY,
    });
    assert.equal(commandOptions.environment.ALLOWED_EMAILS, undefined);
    assert.equal(commandOptions.environment.OWNER_SETUP_TOKEN, undefined);
    assert.equal(commandOptions.environment.KEY_ENCRYPTION_KEY, undefined);
    assert.equal(commandOptions.environment.CLOUDFLARE_API_TOKEN, environment.CLOUDFLARE_API_TOKEN);
    for (const value of [environment.ALLOWED_EMAILS, environment.OWNER_SETUP_TOKEN, environment.KEY_ENCRYPTION_KEY]) assert.equal(args.join(" ").includes(value), false);
    const deployed = JSON.parse(readFileSync(args[args.indexOf("--config") + 1], "utf8"));
    assert.deepEqual(deployed.vars, { ...config.vars, RAYWARDEN_RELEASE_ID: artifactReleaseId(manifest) });
  }, head, environment);
  assert.equal(existsSync(temporary), false);
  assert.equal(existsSync(dirname(temporary)), false);
});

test("release identity changes when the same source produces a different bundle", async t => {
  const { options, write } = fixture(t);
  const before = await createArtifactManifest(options, head);
  const reversed = { ...before, files: Object.fromEntries(Object.entries(before.files).reverse()) };
  assert.equal(artifactReleaseId(reversed), artifactReleaseId(before));
  write(".wrangler/deploy-check/production/index.js", "export default { changed: true };\n");
  const after = await createArtifactManifest(options, head);
  assert.equal(after.sourceSha, before.sourceSha);
  assert.match(artifactReleaseId(after), /^[0-9a-f]{64}$/);
  assert.notEqual(artifactReleaseId(after), artifactReleaseId(before));
});

test("private enrollment deployment accepts and canonicalizes multiple exact account emails", async (t) => {
  const { options } = fixture(t);
  await createArtifactManifest(options, head);
  await deployArtifact(options, (args) => {
    const secrets = JSON.parse(readFileSync(args[args.indexOf("--secrets-file") + 1], "utf8"));
    assert.equal(secrets.ALLOWED_EMAILS, "alice@example.test,bob@example.test");
  }, head, { ALLOWED_EMAILS: " Bob@Example.Test,alice@example.test\nbob@example.test " });
});

test("redeploying without optional values preserves existing owner secrets rather than clearing them", async (t) => {
  for (const environment of [{}, { ALLOWED_EMAILS: "", OWNER_SETUP_TOKEN: "", KEY_ENCRYPTION_KEY: "" }]) {
    const { options } = fixture(t);
    await createArtifactManifest(options, head);
    await deployArtifact(options, (args) => {
      assert.deepEqual(JSON.parse(readFileSync(args[args.indexOf("--secrets-file") + 1], "utf8")), { DOMAIN: "https://vault.example.test" });
    }, head, environment);
  }
});

test("malformed wrapping keys fail before private files or network and never enter error messages", async (t) => {
  const { options, dir } = fixture(t);
  await createArtifactManifest(options, head);
  for (const value of ["private-short-key", " ".repeat(43), "A".repeat(42), "A".repeat(44), "A".repeat(42) + "=", "A".repeat(42) + "B", "A".repeat(42) + "+", "A".repeat(42) + "/", 7, null]) {
    let calls = 0;
    await assert.rejects(deployArtifact(options, () => { calls++; }, head, { KEY_ENCRYPTION_KEY: value }, () => { calls++; }), error => {
      assert.match(error.message, /KEY_ENCRYPTION_KEY must/);
      if (typeof value === "string" && value.trim().length > 1) assert.equal(error.message.includes(value), false);
      return true;
    });
    assert.equal(calls, 0);
    assert.equal(readdirSync(join(dir, ".wrangler")).some(name => name.startsWith("compiled-config-")), false);
  }
});

test("invalid owner configuration fails before discovery, private files or upload without exposing values", async (t) => {
  const { options, dir } = fixture(t);
  await createArtifactManifest(options, head);
  const invalid = [
    ...[" ", "a@example.test,", ",a@example.test", "a@example.test,,b@example.test", "*@example.test", "a?@example.test", "a@example", "a..b@example.test", ".a@example.test", "a.@example.test", "a@example..test", "a@-example.test", "a@exam_ple.test", "a".repeat(65) + "@example.test", "\u0085owner@example.test", "\u00a0owner@example.test\u00a0"].map(ALLOWED_EMAILS => ({ ALLOWED_EMAILS })),
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

test("Wrangler process failure propagates and removes both temporary deployment files", async (t) => {
  const { options, dir, write } = fixture(t);
  write("node_modules/wrangler/bin/wrangler.js", `
    const fs = require("node:fs");
    const args = process.argv.slice(2);
    const configPath = args[args.indexOf("--config") + 1];
    const secretsPath = args[args.indexOf("--secrets-file") + 1];
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    fs.writeFileSync("invocation.json", JSON.stringify({
      args, configPath, secretsPath,
      secretsExisted: fs.existsSync(secretsPath), hasBuild: Object.hasOwn(config, "build"),
    }));
    process.exitCode = 7;
  `);
  await createArtifactManifest(options, head);
  await assert.rejects(deployArtifact(options, undefined, head, {}), { code: 7 });
  const { args, configPath, secretsPath, secretsExisted, hasBuild } = JSON.parse(readFileSync(join(dir, "invocation.json"), "utf8"));
  assert.deepEqual(args.slice(0, 2), ["deploy", "--no-bundle"]);
  assert.deepEqual(args.slice(-2), ["--env", ""]);
  assert.equal(hasBuild, false);
  assert.equal(secretsExisted, true);
  assert.equal(existsSync(configPath), false);
  assert.equal(existsSync(secretsPath), false);
  assert.equal(existsSync(dirname(configPath)), false);
});

test("deployment CLI requires a subcommand with command-specific flags and always targets production", () => {
  assert.throws(() => parseDeployArgs([]), /Usage/);
  assert.throws(() => parseDeployArgs(["--env", "production"]), /Usage/);
  for (const args of [["config", "--env"], ["config", "--env", "production"], ["worker", "--env", "dev"]]) {
    assert.throws(() => parseDeployArgs(args), /Unknown/);
  }
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
