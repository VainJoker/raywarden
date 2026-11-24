import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import {
  CloudflareApi,
  PROJECT_ROOT,
  artifactReleaseId,
  checkHealth,
  createArtifactManifest,
  deployArtifact,
  main as deployMain,
  parseDeployArgs,
  parseJsonc,
  readTargetConfig,
  resolveAccountId,
  verifyArtifact,
  verifyResources,
} from "../scripts/deploy.mjs";
import { databaseId as uuid, productionConfig } from "./script-fixtures.mjs";

const account = "a".repeat(32);
function fixture(t, transform = (value) => value) {
  const dir = mkdtempSync(join(tmpdir(), "raywarden-deployment-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = transform(productionConfig({
    name: "configured-worker", databaseName: "configured-database", bucketName: "configured-files",
  }));
  const configPath = join(dir, "wrangler.jsonc");
  writeFileSync(configPath, JSON.stringify(config));
  return { dir, configPath, config };
}
const response = (result, status = 200) => new Response(JSON.stringify({ success: status < 400, result }), { status });

test("JSONC parsing preserves URLs, escaped quotes, comment-like strings and comma text", () => {
  const source = String.raw`{ // comment
    "url": "https://example.test/a//b/*literal*/", "quote": "a\"/*b*/", /* note */
    "values": ["x,}", "y,]",], "text": "//literal", }`;
  assert.deepEqual(parseJsonc(source), { url: "https://example.test/a//b/*literal*/", quote: 'a"/*b*/', values: ["x,}", "y,]"], text: "//literal" });
  assert.throws(() => parseJsonc('{"x":1/*unclosed'), /Unterminated/);
  assert.throws(() => parseJsonc('{"x":1 "y":2}'));
});

test("deployment health origin comes from a unique explicit route without a DOMAIN value", (t) => {
  const { configPath, config } = fixture(t);
  assert.equal(config.vars, undefined);
  assert.equal(readTargetConfig({ configPath }).domain, "https://vault.example.test");
});

test("deployment accepts omitted or empty routes without remote discovery during builds", (t) => {
  for (const routes of [undefined, []]) {
    const { configPath } = fixture(t, config => ({ ...config, routes, workers_dev: true }));
    const target = readTargetConfig({ configPath });
    assert.equal(target.domain, undefined);
    assert.equal(target.workersDev, true);
  }
});

test("workers.dev names obey DNS limits and omitted workers_dev follows Wrangler route inference", (t) => {
  for (const name of ["bad_name", "trailing-", "a".repeat(64)]) {
    const { configPath } = fixture(t, config => ({ ...config, name, routes: [], workers_dev: true }));
    assert.throws(() => readTargetConfig({ configPath }), /DNS label.*63/);
  }
  for (const name of ["A", "Worker-Name", "a".repeat(63)]) {
    const { configPath } = fixture(t, config => ({ ...config, name, routes: [], workers_dev: true }));
    assert.equal(readTargetConfig({ configPath }).name, name);
  }
  const routed = fixture(t, config => ({ ...config, name: "private_worker" }));
  assert.equal(readTargetConfig({ configPath: routed.configPath }).workersDev, false);
  const explicit = fixture(t, config => ({ ...config, name: "private_worker", workers_dev: true }));
  assert.throws(() => readTargetConfig({ configPath: explicit.configPath }), /DNS label/);
  const invalidFlag = fixture(t, config => ({ ...config, workers_dev: "false" }));
  assert.throws(() => readTargetConfig({ configPath: invalidFlag.configPath }), /must be a boolean/);
});

test("deployment rejects ambiguous routes, wildcards, schemes and non-hostname health targets", (t) => {
  for (const routes of [
    "vault.example.test", [null],
    [{ pattern: "vault.example.test", custom_domain: true }, { pattern: "other.example.test", custom_domain: true }],
    [{ pattern: "vault.example.test" }], [{ pattern: "vault.example.test", custom_domain: false }],
    ...["http://localhost:8787", "https://vault.example.test", "*.example.test", "vault.example.test/*", "vault.example.test?query", "vault.example.test#hash", "user@vault.example.test", "vault.example.test:443", "", " vault.example.test", "-vault.example.test", "vault..example.test"].map(pattern => [{ pattern, custom_domain: true }]),
  ]) {
    const { configPath } = fixture(t, config => ({ ...config, routes }));
    assert.throws(() => readTargetConfig({ configPath }), /routes must/);
  }
});

test("deployment CLI ignores WRANGLER_CONFIG and selects the fixed production config", async (t) => {
  const alternate = fixture(t);
  const configPath = resolve(PROJECT_ROOT, "wrangler.jsonc");
  const production = parseJsonc(readFileSync(configPath, "utf8"));
  const target = await deployMain(["config"], { WRANGLER_CONFIG: alternate.configPath, CLOUDFLARE_ENV: "local" });
  assert.equal(target.configPath, configPath);
  assert.equal(target.name, production.name);
  assert.notEqual(target.database.database_id, alternate.config.d1_databases[0].database_id);
});

test("resource verification ignores implicit WRANGLER_CONFIG but retains explicit programmatic configPath", async (t) => {
  const alternate = fixture(t);
  const expected = readTargetConfig({});
  const paths = [];
  const result = await verifyResources({
    CLOUDFLARE_API_TOKEN: "test", CLOUDFLARE_ACCOUNT_ID: account, CLOUDFLARE_ENV: "removed-environment", WRANGLER_CONFIG: alternate.configPath,
  }, async (url) => {
    paths.push(new URL(url).pathname);
    if (url.endsWith("/workers/subdomain")) return response({ subdomain: "configured-account" });
    if (url.endsWith(`/d1/database/${expected.database.database_id}`)) return response({ uuid: expected.database.database_id, name: expected.database.database_name });
    const bucket = expected.buckets.find((value) => url.endsWith(`/r2/buckets/${value.bucket_name}`));
    assert.ok(bucket, `Unexpected resource request: ${url}`);
    return response({ name: bucket.bucket_name });
  }, {});
  assert.equal(result.d1_database_id, expected.database.database_id);
  assert.equal(paths.length, 1 + expected.buckets.length + (expected.domain ? 0 : 1));
  // The fixture-based resource tests below continue exercising explicit configPath.
});

test("invalid configuration fails before any Cloudflare request", async (t) => {
  const { configPath } = fixture(t, (c) => { delete c.d1_databases[0].database_id; return c; });
  let called = false;
  await assert.rejects(verifyResources({ CLOUDFLARE_API_TOKEN: "test" }, () => { called = true; }, { configPath }), /real database_id/);
  assert.equal(called, false);
});

test("credential URL redaction and an external wrapping key are required before remote operations", async (t) => {
  for (const change of [
    config => { delete config.observability; },
    config => { delete config.observability.redact_query_string; },
    config => { config.observability.redact_query_string = false; },
    config => { config.observability.redact_query_string = "true"; },
    config => { delete config.secrets; },
    config => { config.secrets.required = ["DOMAIN"]; },
    config => { config.vars = { KEY_ENCRYPTION_KEY: "never-a-production-var" }; },
  ]) {
    const { configPath } = fixture(t, config => { change(config); return config; });
    let calls = 0;
    await assert.rejects(verifyResources({ CLOUDFLARE_API_TOKEN: "test" }, () => { calls++; }, { configPath }), /redact_query_string|KEY_ENCRYPTION_KEY/);
    assert.equal(calls, 0);
  }
});

test("resource verification uses only configured identities and GET, without editing config", async (t) => {
  const { configPath } = fixture(t);
  const original = readFileSync(configPath, "utf8");
  const paths = [];
  const output = await verifyResources({ CLOUDFLARE_API_TOKEN: "test", CLOUDFLARE_ACCOUNT_ID: account }, async (url, options) => {
    assert.equal(options.method ?? "GET", "GET");
    paths.push(new URL(url).pathname);
    if (url.endsWith(`/d1/database/${uuid}`)) return response({ uuid, name: "configured-database" });
    if (url.endsWith("/r2/buckets/configured-files")) return response({ name: "configured-files" });
    throw new Error(`Unexpected API path ${url}`);
  }, { configPath });
  assert.equal(output.worker_url, "https://vault.example.test");
  assert.equal(paths.length, 2);
  assert.equal(readFileSync(configPath, "utf8"), original);
});

test("D1 ID/name mismatch and HTTP errors never trigger replacement creation", async (t) => {
  const { configPath } = fixture(t);
  for (const result of [response({ uuid, name: "wrong" }), response(null, 403), response(null, 404)]) {
    let calls = 0;
    await assert.rejects(verifyResources({ CLOUDFLARE_API_TOKEN: "test", CLOUDFLARE_ACCOUNT_ID: account }, async (url, options) => {
      assert.equal(options.method ?? "GET", "GET");
      calls++;
      return result;
    }, { configPath }));
    assert.equal(calls, 1);
  }
});

test("account discovery rejects ambiguous accounts and handles API errors", async () => {
  await assert.rejects(resolveAccountId({ request: async () => ({ result: [{ id: account }, { id: "b".repeat(32) }] }) }), /exactly one/);
  const api = new CloudflareApi("test", async () => new Response("not-json", { status: 503 }));
  await assert.rejects(api.request("/accounts"), /invalid JSON/);
});

test("health checks configured /api/alive, retries failures and rejects SPA/redirects", async (t) => {
  const { configPath } = fixture(t);
  let calls = 0;
  let waits = 0;
  const result = await checkHealth({ configPath, attempts: 3 }, async (url, options) => {
    assert.equal(url, "https://vault.example.test/api/alive");
    assert.equal(options.redirect, "error");
    assert.equal(options.cache, "no-store");
    assert.equal(options.headers["User-Agent"], "raywarden-health/0.1");
    return ++calls === 1 ? new Response("<html>SPA</html>") : new Response('"2026-11-13T00:00:00Z"');
  }, async () => { waits++; });
  assert.equal(result.url, "https://vault.example.test/api/alive");
  assert.equal(waits, 1);
  await assert.rejects(checkHealth({ configPath, attempts: 1 }, async () => new Response("unavailable", { status: 503 })), /HTTP 503/);
});

test("deployment health accepts only timestamps served by the expected release", async (t) => {
  const { configPath } = fixture(t);
  const expectedReleaseId = "a".repeat(64);
  const header = "X-Raywarden-Release-Id";
  const timestamp = "2024-02-29T00:00:00.123456Z";
  const options = { configPath, attempts: 1, expectedReleaseId };
  for (const value of [null, [], {}, "ok", "2026-02-29T00:00:00Z", "2026-11-13T25:00:00Z"]) {
    await assert.rejects(checkHealth(options, async () => Response.json(value, {
      headers: { [header]: expectedReleaseId },
    })), /Expected an RFC3339 timestamp/);
  }
  for (const headers of [{}, { [header]: "b".repeat(64) }]) {
    await assert.rejects(checkHealth(options, async () => Response.json(timestamp, { headers })), /expected release artifact/);
  }
  let calls = 0;
  await checkHealth({ ...options, attempts: 2 }, async () => Response.json(timestamp, {
    headers: { [header]: ++calls === 2 ? expectedReleaseId : "b".repeat(64) },
  }), async () => {});
  assert.equal(calls, 2);
});

test("production preflight validates supplied Secrets before remote steps and permits inherited ones", async () => {
  for (const name of ["KEY_ENCRYPTION_KEY", "OWNER_SETUP_TOKEN", "ALLOWED_EMAILS"]) {
    const value = "malformed-fixture-value";
    await assert.rejects(deployMain(["preflight"], { [name]: value }), error => {
      assert.match(error.message, new RegExp(`^${name} `));
      assert.ok(!error.message.includes(value));
      return true;
    });
  }
  await deployMain(["preflight"], {});
  await deployMain(["preflight"], {
    ALLOWED_EMAILS: "owner@example.test", OWNER_SETUP_TOKEN: "fixture-only-setup-token-value-long-enough",
    KEY_ENCRYPTION_KEY: Buffer.alloc(32, 3).toString("base64url"),
  });
});

test("configuration rejects unsupported bindings", (t) => {
  const badD1 = fixture(t, (c) => { c.d1_databases[0].binding = "wrong"; return c; });
  assert.throws(() => readTargetConfig({ configPath: badD1.configPath }), /binding=DB/);
  const badR2 = fixture(t, (c) => { c.r2_buckets[0].binding = "wrong"; return c; });
  assert.throws(() => readTargetConfig({ configPath: badR2.configPath }), /incomplete R2/);
});

test("rate limit configuration fails before remote discovery when required bindings are missing or ambiguous", async (t) => {
  for (const change of [
    config => { delete config.ratelimits; },
    config => { config.ratelimits = {}; },
    config => { config.ratelimits = []; },
    config => { config.ratelimits.splice(0, 1); },
    config => { config.ratelimits.splice(1, 1); },
    config => { config.ratelimits[0].name = "LOGIN_RATE_LIMITER_typo"; },
    config => { config.ratelimits.push({ ...config.ratelimits[0] }); },
    config => { config.ratelimits[1].namespace_id = "03101"; },
  ]) {
    const { configPath } = fixture(t, config => { change(config); return config; });
    let requests = 0;
    await assert.rejects(verifyResources({ CLOUDFLARE_API_TOKEN: "test" }, () => { requests++; }, { configPath }), /rate limit|ratelimits/);
    assert.equal(requests, 0);
  }
});

test("rate limit configuration rejects invalid provider parameters without echoing their values", (t) => {
  const invalid = [
    ...[undefined, "", "private-limiter-value", 3101, "1.5", "-1"].map(namespace_id => binding => { binding.namespace_id = namespace_id; }),
    ...[undefined, null, {}].map(simple => binding => { binding.simple = simple; }),
    ...[0, -1, 1.5, "5", Number.MAX_SAFE_INTEGER + 1].map(limit => binding => { binding.simple.limit = limit; }),
    ...[0, 30, "60", null].map(period => binding => { binding.simple.period = period; }),
  ];
  for (const index of [0, 1]) for (const change of invalid) {
    const { configPath } = fixture(t, config => { change(config.ratelimits[index]); return config; });
    assert.throws(() => readTargetConfig({ configPath }), error => {
      assert.match(error.message, /LOGIN_RATE_LIMITER|SEND_ACCESS_RATE_LIMITER/);
      assert.match(error.message, /namespace_id|simple/);
      assert.equal(error.message.includes("private-limiter-value"), false);
      return true;
    });
  }
  for (const period of [10, 60]) {
    const { configPath } = fixture(t, config => { config.ratelimits[0].simple = { limit: 7, period }; return config; });
    assert.equal(readTargetConfig({ configPath }).name, "configured-worker");
  }
});

test("resources and health discover workers.dev without a custom domain or DOMAIN value", async (t) => {
  const { configPath } = fixture(t, c => { delete c.routes; c.workers_dev = true; return c; });
  const env = { CLOUDFLARE_API_TOKEN: "test", CLOUDFLARE_ACCOUNT_ID: account };
  const calls = [];
  const fetch = async (url, options) => {
    calls.push(url);
    if (url.endsWith(`/d1/database/${uuid}`)) return response({ uuid, name: "configured-database" });
    if (url.endsWith("/r2/buckets/configured-files")) return response({ name: "configured-files" });
    if (url.endsWith("/workers/subdomain")) {
      assert.equal(options.headers.Authorization, "Bearer test");
      return response({ subdomain: "my-account" });
    }
    assert.equal(url, "https://configured-worker.my-account.workers.dev/api/alive");
    assert.equal(options.headers.Authorization, undefined);
    return new Response('"2026-11-13T00:00:00Z"');
  };
  const output = await verifyResources(env, fetch, { configPath });
  assert.equal(output.worker_url, "https://configured-worker.my-account.workers.dev");
  const health = await checkHealth({ configPath, attempts: 1 }, fetch, undefined, env);
  assert.equal(health.url, `${output.worker_url}/api/alive`);
  assert.equal(calls.length, 5);
});

test("workers.dev discovery reports missing subdomains, disabled endpoints and API failures", async (t) => {
  const env = { CLOUDFLARE_API_TOKEN: "test", CLOUDFLARE_ACCOUNT_ID: account };
  const { configPath } = fixture(t, c => { delete c.routes; return c; });
  for (const subdomain of [undefined, "", "bad/path", "bad.example", "-bad"]) {
    await assert.rejects(checkHealth({ configPath }, async () => response({ subdomain }), undefined, env), /account workers.dev subdomain/);
  }
  await assert.rejects(checkHealth({ configPath }, async () => response(null, 403), undefined, env), /HTTP 403/);
  const disabled = fixture(t, c => { delete c.routes; c.workers_dev = false; return c; });
  await assert.rejects(checkHealth({ configPath: disabled.configPath }, () => { throw new Error("Unexpected fetch"); }, undefined, env), /enable workers_dev/);
});

test("Integration gates same-run deployment on both checks and coverage, and only stores release artifacts", () => {
  const integration = readFileSync(resolve(PROJECT_ROOT, ".github/workflows/integration.yml"), "utf8");
  const deploy = readFileSync(resolve(PROJECT_ROOT, ".github/workflows/cloudflare.yml"), "utf8");
  const [check, rest] = integration.split("\n  coverage:\n");
  const [coverage, deployCall] = rest.split("\n  deploy:\n");
  assert.ok(coverage && deployCall);
  assert.match(deployCall, /needs: \[check, coverage\]/);
  assert.match(deployCall, /uses: \.\/\.github\/workflows\/cloudflare\.yml/);
  assert.match(coverage, /just coverage$/m);
  assert.match(check, /run: just ci[\s\S]*run: just dry-run[\s\S]*run: just test-worker[\s\S]*run: just test-d1[\s\S]*run: just artifact/);
  assert.match(check, /if: startsWith\(github.ref, 'refs\/tags\/v'\)\s+run: just artifact/);
  assert.match(check, /if: startsWith\(github.ref, 'refs\/tags\/v'\)\s+uses: actions\/upload-artifact@/);
  assert.match(deploy, /on:\n  workflow_call:/);
  assert.doesNotMatch(deploy, /workflow_dispatch:|inputs[.:]|run_id|run-id:|getWorkflowRun|listJobsForWorkflowRun/);
  assert.match(deploy, /queue: max/);
  assert.match(deploy, /cancel-in-progress: false/);
  assert.match(deploy, /environment: production/);
  assert.match(deploy, /run: just artifact-check[\s\S]*run: just deploy-preflight[\s\S]*just db-migrate production[\s\S]*run: just deploy-worker[\s\S]*run: just deploy-health/);
  assert.doesNotMatch(deploy, /just ci|just dry-run|just build|rust: "true"/);
  assert.match(deploy, /ref: \$\{\{ github\.sha \}\}/);
  assert.match(deploy, /ARTIFACT_SOURCE_SHA: \$\{\{ github\.sha \}\}/);
  for (const workflow of [integration, deploy]) {
    assert.match(workflow, /name: raywarden-release-production-\$\{\{ github\.sha \}\}/);
    assert.doesNotMatch(workflow, /\bfeat\b|\[deploy\]|head_commit\.message/);
  }
  for (const job of [deployCall, deploy]) {
    assert.match(job, /^    if: startsWith\(github\.ref, 'refs\/tags\/v'\) && \(github\.event_name == 'push' \|\| github\.event_name == 'workflow_dispatch'\)$/m);
  }
});

test("Release-plz queues main releases and publishes to Git before preparing the next PR", () => {
  const workflow = readFileSync(resolve(PROJECT_ROOT, ".github/workflows/release.yml"), "utf8");
  const config = readFileSync(resolve(PROJECT_ROOT, "release-plz.toml"), "utf8");
  const cargo = readFileSync(resolve(PROJECT_ROOT, "Cargo.toml"), "utf8");
  assert.match(workflow, /if: github.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /push:\n    branches: \[main\]/);
  assert.match(workflow, /fetch-depth: 0/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /cancel-in-progress: false\n  queue: max/);
  assert.match(workflow, /permissions:\n  contents: read/);
  assert.doesNotMatch(workflow, /release-plz\/action|secrets.GITHUB_TOKEN|CARGO_REGISTRY_TOKEN|just deploy|secrets: inherit/);
  assert.match(workflow, /GITHUB_TOKEN: \$\{\{ secrets.RELEASE_PLZ_TOKEN \}\}/);
  assert.match(workflow, /release-plz release --git-token[\s\S]*release-plz release-pr --git-token/);
  assert.match(config, /^git_only = true$/m);
  assert.match(config, /^release_always = false$/m);
  assert.match(config, /^git_tag_name = "v\{\{ version \}\}"$/m);
  assert.match(config, /^dependencies_update = false$/m);
  assert.match(cargo.split("[lib]")[0], /^publish = false$/m);
});

test("Dependabot merging explicitly requires both GitHub Actions checks", () => {
  const config = readFileSync(resolve(PROJECT_ROOT, ".github/mergify.yml"), "utf8");
  const workflow = readFileSync(resolve(PROJECT_ROOT, ".github/workflows/integration.yml"), "utf8");
  assert.match(config, /base=main/);
  for (const job of ["check", "coverage"]) {
    const name = workflow.match(new RegExp(`^  ${job}:\\n    name: (.+)$`, "m"))?.[1];
    assert.ok(name, `Integration is missing its ${job} status check`);
    assert.ok(config.includes(`"check-success = @github-actions/${name}"`));
  }
});

test("production and local configurations isolate resources and route dynamic endpoints through the Worker", () => {
  const production = parseJsonc(readFileSync(resolve(PROJECT_ROOT, "wrangler.jsonc"), "utf8"));
  assert.deepEqual(Object.keys(production.env), ["local"]);
  const local = production.env.local;
  assert.equal(local.workers_dev, false);
  assert.deepEqual(local.routes, []);
  assert.deepEqual(local.triggers.crons, []);
  assert.equal(local.secrets, undefined);
  assert.notEqual(production.name, local.name);
  assert.notEqual(production.d1_databases[0].database_id, local.d1_databases[0].database_id);
  assert.notEqual(production.d1_databases[0].database_name, local.d1_databases[0].database_name);
  assert.notEqual(production.r2_buckets[0].bucket_name, local.r2_buckets[0].bucket_name);
  assert.deepEqual(local.durable_objects.bindings, production.durable_objects.bindings);
  const namespaces = [];
  for (const config of [production, local]) {
    assert.equal(config.main ?? production.main, "build/index.js");
    assert.equal(config.d1_databases[0].binding, "DB");
    assert.equal(config.r2_buckets[0].binding, "ATTACHMENTS_BUCKET");
    for (const name of ["LOGIN_RATE_LIMITER", "SEND_ACCESS_RATE_LIMITER"]) {
      const limiter = config.ratelimits.find((value) => value.name === name);
      assert.ok(limiter, `${config.name} needs ${name}`);
      assert.match(String(limiter.namespace_id), /^\d+$/);
      namespaces.push(limiter.namespace_id);
    }
    const assets = config.assets ?? production.assets;
    for (const path of ["/two-factor/send-email-login", "/css/vaultwarden.css", "/demo.html"]) {
      assert.ok(assets.run_worker_first.some((rule) => rule === path || (rule.endsWith("/*") && path.startsWith(rule.slice(0, -1)))), `${config.name} must route ${path} through the Worker`);
    }
  }
  assert.equal(new Set(namespaces).size, 4);
});

const sha = "a".repeat(40);
const head = async () => sha;
function artifactFixture(t) {
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
  const { options } = artifactFixture(t);
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
  const { dir, options, write } = artifactFixture(t), observation = join(dir, "git-environment.json");
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
    const { options, dir, write } = artifactFixture(t);
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
  const { options, write } = artifactFixture(t);
  write(".wrangler/deploy-check/production/worker.wasm", "invalid WASM");
  await assert.rejects(createArtifactManifest(options, head), /Invalid WASM module/);
});

test("wrong commit, environment or configuration cannot reuse an artifact", async (t) => {
  const { options, write, config } = artifactFixture(t);
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
  const { options, write } = artifactFixture(t);
  await createArtifactManifest(options, head);
  write(".wrangler/deploy-check/production/unexpected.js", "export default 1;");
  await assert.rejects(verifyArtifact(options, head), /inventory/);
});

test("compiled deployment disables both custom and internal builds and retains resource identities", async (t) => {
  const { options, dir, config } = artifactFixture(t);
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
  const { options, dir, config, write } = artifactFixture(t);
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
  const { options, config } = artifactFixture(t);
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
  const { options, write } = artifactFixture(t);
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
  const { options } = artifactFixture(t);
  await createArtifactManifest(options, head);
  await deployArtifact(options, (args) => {
    const secrets = JSON.parse(readFileSync(args[args.indexOf("--secrets-file") + 1], "utf8"));
    assert.equal(secrets.ALLOWED_EMAILS, "alice@example.test,bob@example.test");
  }, head, { ALLOWED_EMAILS: " Bob@Example.Test,alice@example.test\nbob@example.test " });
});

test("redeploying without optional values preserves existing owner secrets rather than clearing them", async (t) => {
  for (const environment of [{}, { ALLOWED_EMAILS: "", OWNER_SETUP_TOKEN: "", KEY_ENCRYPTION_KEY: "" }]) {
    const { options } = artifactFixture(t);
    await createArtifactManifest(options, head);
    await deployArtifact(options, (args) => {
      assert.deepEqual(JSON.parse(readFileSync(args[args.indexOf("--secrets-file") + 1], "utf8")), { DOMAIN: "https://vault.example.test" });
    }, head, environment);
  }
});

test("malformed wrapping keys fail before private files or network and never enter error messages", async (t) => {
  const { options, dir } = artifactFixture(t);
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
  const { options, dir } = artifactFixture(t);
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
  const { options } = artifactFixture(t);
  await createArtifactManifest(options, head);
  for (const token of ["a".repeat(32), "a".repeat(512), "😀".repeat(512)]) {
    await deployArtifact(options, (args) => {
      assert.equal(JSON.parse(readFileSync(args[args.indexOf("--secrets-file") + 1], "utf8")).OWNER_SETUP_TOKEN, token);
    }, head, { OWNER_SETUP_TOKEN: token });
  }
});

test("workers.dev first upload resolves the account subdomain before supplying DOMAIN", async (t) => {
  const { options, write, config } = artifactFixture(t);
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
  const { options, dir, write } = artifactFixture(t);
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
  const { options, dir } = artifactFixture(t);
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
