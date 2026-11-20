import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  parseJsonc, PROJECT_ROOT, readTargetConfig,
  CloudflareApi, verifyResources, resolveAccountId, checkHealth, main as deployMain,
} from "../scripts/deploy.mjs";

const account = "a".repeat(32);
const uuid = "11111111-1111-4111-8111-111111111111";
function fixture(t, transform = (value) => value) {
  const dir = mkdtempSync(join(tmpdir(), "raywarden-deployment-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binding = { binding: "DB", database_name: "configured-database", database_id: uuid, migrations_dir: "sql/migrations" };
  const config = transform({
    name: "configured-worker", secrets: { required: ["DOMAIN", "KEY_ENCRYPTION_KEY"] }, routes: [{ pattern: "vault.example.test", custom_domain: true }],
    observability: { redact_query_string: true, logs: { enabled: true, invocation_logs: false } },
    d1_databases: [binding], r2_buckets: [{ binding: "ATTACHMENTS_BUCKET", bucket_name: "configured-files" }],
    ratelimits: [
      { name: "LOGIN_RATE_LIMITER", namespace_id: "3101", simple: { limit: 5, period: 60 } },
      { name: "SEND_ACCESS_RATE_LIMITER", namespace_id: "3103", simple: { limit: 15, period: 60 } },
    ],
  });
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
    assert.equal(options.headers["User-Agent"], "raywarden-health/0.1");
    return ++calls === 1 ? new Response("<html>SPA</html>") : new Response('"2026-11-13T00:00:00Z"');
  }, async () => { waits++; });
  assert.equal(result.url, "https://vault.example.test/api/alive");
  assert.equal(waits, 1);
  await assert.rejects(checkHealth({ configPath, attempts: 1 }, async () => new Response("unavailable", { status: 503 })), /HTTP 503/);
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
    return new Response('"healthy"');
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
  assert.match(check, /run: just ci[\s\S]*run: just dry-run[\s\S]*run: just test-worker[\s\S]*run: just artifact/);
  assert.match(check, /if: startsWith\(github.ref, 'refs\/tags\/v'\)\s+run: just artifact/);
  assert.match(check, /if: startsWith\(github.ref, 'refs\/tags\/v'\)\s+uses: actions\/upload-artifact@/);
  assert.match(deploy, /on:\n  workflow_call:/);
  assert.doesNotMatch(deploy, /workflow_dispatch:|inputs[.:]|run_id|run-id:|getWorkflowRun|listJobsForWorkflowRun/);
  assert.match(deploy, /queue: max/);
  assert.match(deploy, /cancel-in-progress: false/);
  assert.match(deploy, /environment: production/);
  assert.match(deploy, /run: just artifact-check[\s\S]*just db-migrate production[\s\S]*run: just deploy-worker[\s\S]*run: just health/);
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
