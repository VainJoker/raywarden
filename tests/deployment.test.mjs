import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  parseJsonc, PROJECT_ROOT, readTargetConfig,
  CloudflareApi, verifyResources, resolveAccountId, checkHealth, parseDeployArgs, main as deployMain,
} from "../scripts/deploy.mjs";

const account = "a".repeat(32);
const uuid = "11111111-1111-4111-8111-111111111111";
function fixture(t, transform = (value) => value) {
  const dir = mkdtempSync(join(tmpdir(), "raywarden-deployment-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binding = { binding: "warden-db", database_name: "configured-database", database_id: uuid, migrations_dir: "sql/migrations" };
  const config = transform({ name: "configured-worker", secrets: { required: ["DOMAIN"] }, routes: [{ pattern: "vault.example.test", custom_domain: true }], d1_databases: [binding], r2_buckets: [{ binding: "ATTACHMENTS_BUCKET", bucket_name: "configured-files" }] });
  const configPath = join(dir, "wrangler.jsonc");
  writeFileSync(configPath, JSON.stringify(config));
  return { dir, configPath, config };
}
const response = (result, status = 200) => new Response(JSON.stringify({ success: status < 400, result }), { status });

// Execute the actual inline resolver; the GitHub client is the only substitute.
function sourceFixture({ input = "123", source = {}, jobs } = {}) {
  const workflow = readFileSync(resolve(PROJECT_ROOT, ".github/workflows/cloudflare.yaml"), "utf8");
  const script = workflow.match(/^          script: \|\n((?:            [^\n]*\n|\n)+)/m)?.[1];
  assert.ok(script, "Missing inline deployment source resolver");
  const execute = new (async () => {}).constructor("github", "context", "core", "process", script.replace(/^            /gm, ""));
  const sha = "a".repeat(40);
  const run = {
    repository: { full_name: "example/raywarden" }, head_repository: { full_name: "example/raywarden" },
    path: ".github/workflows/integration.yml", head_branch: "main", event: "push", head_sha: sha,
    status: "completed", conclusion: "failure", run_attempt: 2, ...source,
  };
  const check = {
    name: "Linux Rust, JavaScript, SQL and Worker build", head_sha: sha,
    status: "completed", conclusion: "success", run_attempt: 1,
  };
  const calls = [], outputs = {};
  const actions = {
    async getWorkflowRun(options) { calls.push(["run", options]); return { data: run }; },
    listJobsForWorkflowRun() { throw new Error("Jobs must be paginated"); },
  };
  const github = {
    rest: { actions },
    async paginate(method, options) {
      assert.equal(method, actions.listJobsForWorkflowRun);
      calls.push(["jobs", options]);
      return jobs ?? [check, { name: "Deploy to Cloudflare", conclusion: "failure", run_attempt: 2 }];
    },
  };
  const context = {
    repo: { owner: "example", repo: "raywarden" }, sha: "b".repeat(40), runId: 900,
    eventName: "workflow_dispatch", workflow: "Integration",
  };
  const core = { setOutput(name, value) { outputs[name] = String(value); } };
  return {
    calls, outputs, check, github, context,
    resolve: () => execute(github, context, core, { env: { INTEGRATION_RUN_ID: input } }),
  };
}

test("reusable deployment keeps its own run even when Integration was manually triggered", async () => {
  const f = sourceFixture({ input: "" });
  await f.resolve();
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.outputs, { sha: f.context.sha, run_id: String(f.context.runId) });
});

test("manual deployment selects the source commit and permits retry after a failed deployment", async () => {
  for (const event of ["push", "workflow_dispatch"]) {
    const f = sourceFixture({ input: " 123 ", source: { event } });
    await f.resolve();
    assert.deepEqual(f.outputs, { sha: "a".repeat(40), run_id: "123" });
    assert.notEqual(f.outputs.sha, f.context.sha);
    assert.deepEqual(f.calls, [
      ["run", { owner: "example", repo: "raywarden", run_id: "123" }],
      ["jobs", { owner: "example", repo: "raywarden", run_id: "123", filter: "all", per_page: 100 }],
    ]);
  }
});

test("manual deployment rejects foreign, PR, non-main, unfinished and malformed sources before selecting an artifact", async () => {
  for (const source of [
    { repository: { full_name: "other/raywarden" } }, { head_repository: { full_name: "fork/raywarden" } },
    { head_repository: null }, { path: ".github/workflows/coverage.yml" }, { head_branch: "feature" },
    { event: "pull_request" }, { event: "workflow_run" }, { status: "in_progress" }, { status: "queued" },
    { head_sha: "main" },
  ]) {
    const f = sourceFixture({ source });
    await assert.rejects(f.resolve(), /Source must|Wait for/);
    assert.deepEqual(f.outputs, {});
    assert.equal(f.calls.length, 1);
  }
});

test("manual deployment requires the latest check success and cannot fall back to a previous successful attempt", async () => {
  const { check } = sourceFixture();
  for (const jobs of [
    [], [{ ...check, name: "unrelated job" }], [{ ...check, head_sha: "c".repeat(40) }],
    [{ ...check, run_attempt: undefined }], [{ ...check, run_attempt: 0 }],
    [check, { ...check, run_attempt: 2, conclusion: "failure" }],
    [check, { ...check, run_attempt: 2, conclusion: "cancelled" }],
    [check, { ...check, run_attempt: 2, status: "in_progress", conclusion: null }],
    [{ ...check, conclusion: "skipped" }],
  ]) {
    const f = sourceFixture({ jobs });
    await assert.rejects(f.resolve(), /Cannot identify|latest Integration check/);
    assert.deepEqual(f.outputs, {});
  }
  const f = sourceFixture({ jobs: [{ ...check, run_attempt: 2 }, { ...check, conclusion: "failure" }] });
  await f.resolve();
  assert.equal(f.outputs.sha, check.head_sha);
});

test("malformed run IDs and GitHub API failures never select an artifact", async () => {
  for (const input of ["0", "-1", "1e3", "123\n456", "$(command)"]) {
    const f = sourceFixture({ input });
    await assert.rejects(f.resolve(), /positive integer/);
    assert.deepEqual(f.calls, []);
    assert.deepEqual(f.outputs, {});
  }
  for (const stage of ["run", "jobs"]) {
    const f = sourceFixture();
    const fail = async () => { throw new Error("GitHub unavailable"); };
    if (stage === "run") f.github.rest.actions.getWorkflowRun = fail;
    else f.github.paginate = fail;
    await assert.rejects(f.resolve(), /GitHub unavailable/);
    assert.deepEqual(f.outputs, {});
  }
});

test("JSONC parsing preserves URLs, escaped quotes, comment-like strings and comma text", () => {
  const source = String.raw`{ // comment
    "url": "https://example.test/a//b/*literal*/", "quote": "a\"/*b*/", /* note */
    "values": ["x,}", "y,]",], "text": "//literal", }`;
  assert.deepEqual(parseJsonc(source), { url: "https://example.test/a//b/*literal*/", quote: 'a"/*b*/', values: ["x,}", "y,]"], text: "//literal" });
  assert.throws(() => parseJsonc('{"x":1/*unclosed'), /Unterminated/);
  assert.throws(() => parseJsonc('{"x":1 "y":2}'));
});

test("remote commands are production-only and reject environment selection", () => {
  assert.deepEqual(parseDeployArgs(["config"]), { command: "config" });
  for (const args of [["config", "--env"], ["config", "--env", "production"], ["worker", "--env", "dev"]]) {
    assert.throws(() => parseDeployArgs(args), /Unknown/);
  }
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
  const target = await deployMain(["config"], { WRANGLER_CONFIG: alternate.configPath, CLOUDFLARE_ENV: "removed-environment" });
  assert.equal(target.configPath, resolve(PROJECT_ROOT, "wrangler.jsonc"));
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
  assert.throws(() => readTargetConfig({ configPath: badD1.configPath }), /binding=warden-db/);
  const badR2 = fixture(t, (c) => { c.r2_buckets[0].binding = "wrong"; return c; });
  assert.throws(() => readTargetConfig({ configPath: badR2.configPath }), /incomplete R2/);
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

test("integration gates same-run deployment on successful checks and keeps coverage separate", () => {
  const integration = readFileSync(resolve(PROJECT_ROOT, ".github/workflows/integration.yml"), "utf8");
  const coverage = readFileSync(resolve(PROJECT_ROOT, ".github/workflows/coverage.yml"), "utf8");
  const [check, deployCall] = integration.split("\n  deploy:\n");
  const deploy = readFileSync(resolve(PROJECT_ROOT, ".github/workflows/cloudflare.yaml"), "utf8");
  assert.ok(deployCall, "Integration must call deployment after checks");
  assert.match(deployCall, /uses: \.\/\.github\/workflows\/cloudflare\.yaml/);
  assert.match(deployCall, /secrets: inherit/);
  assert.match(deploy, /workflow_call:/);
  assert.match(deploy, /ALLOWED_EMAILS: \$\{\{ secrets\.ALLOWED_EMAILS \}\}/);
  assert.match(deploy, /OWNER_SETUP_TOKEN: \$\{\{ secrets\.OWNER_SETUP_TOKEN \}\}/);
  assert.doesNotMatch(deploy, /DOMAIN: \$\{\{ secrets\.DOMAIN \}\}/);
  assert.match(deploy, /workflow_dispatch:\n    inputs:\n      run_id:/);
  assert.match(deploy, /required: true\n        type: string/);
  assert.doesNotMatch(deploy, /workflow_run:/);
  const setup = readFileSync(resolve(PROJECT_ROOT, ".github/actions/setup/action.yml"), "utf8");
  assert.doesNotMatch(integration, /just bootstrap|dependency-locks/);
  assert.match(integration, /just setup/);
  assert.match(integration, /just ci/);
  assert.match(integration, /just ui-download/);
  assert.match(integration, /just dry-run/);
  assert.match(integration, /just test-worker/);
  assert.ok(integration.indexOf("run: just dry-run") < integration.indexOf("run: just test-worker"));
  assert.ok(integration.indexOf("run: just test-worker") < integration.indexOf("run: just artifact"));
  assert.match(integration, /run: just artifact$/m);
  assert.match(setup, /config\.justVersion/);
  assert.match(setup, /node-version-file: \.node-version/);
  assert.match(setup, /default: "false"/);
  for (const workflow of [integration, coverage, deploy]) assert.match(workflow, /uses: \.\/\.github\/actions\/setup/);
  for (const workflow of [check, coverage]) assert.match(workflow, /rust: "true"/);
  assert.doesNotMatch(deploy, /rust: "true"/);
  assert.match(integration, /include-hidden-files: true/);
  assert.match(integration, /overwrite: true/);
  assert.match(integration, /name: raywarden-release-production-\$\{\{ github\.sha \}\}/);
  assert.doesNotMatch(integration, /TARGET_ENV|inputs\.environment|options: \[production, dev\]/);
  assert.match(integration, /\.wrangler\/deploy-check\//);
  assert.match(coverage, /just coverage-setup/);
  assert.match(coverage, /just coverage$/m);
  assert.match(coverage, /coverage\/lcov\.info/);
  assert.doesNotMatch(coverage, /tarpaulin|just ci|just ui|just dry-run/);
  assert.match(integration, /workflow_dispatch:/);
  assert.match(deployCall, /needs: check/);
  assert.doesNotMatch(integration, /workflow_run:|run_id|run-id:|github-token:|getWorkflowRun|always\(\)/);
  assert.doesNotMatch(check, /actions: read/);
  assert.match(deployCall, /permissions:\n      contents: read\n      actions: read/);
  assert.match(deploy, /permissions:\n  contents: read\n  actions: read/);
  const condition = deployCall.match(/^    if: (.+)$/m)?.[1];
  assert.ok(condition, "Deployment must explicitly restrict its branch and event");
  const mayDeploy = new Function("github", `return (${condition});`);
  for (const [ref, event_name, expected] of [
    ["refs/heads/main", "push", true],
    ["refs/heads/main", "workflow_dispatch", true],
    ["refs/heads/main", "pull_request", false],
    ["refs/heads/feature", "push", false],
    ["refs/heads/feature", "workflow_dispatch", false],
    ["refs/pull/1/merge", "pull_request", false],
  ]) assert.equal(mayDeploy({ ref, event_name }), expected, `${event_name} on ${ref}`);
  assert.match(check, /concurrency:\n      group: ci-.*\n      cancel-in-progress: true/);
  assert.match(deploy, /concurrency:\n      group: cloudflare-deploy-.*\n      cancel-in-progress: false/);
  assert.equal(deploy.match(/ARTIFACT_SOURCE_SHA: \$\{\{ steps\.source\.outputs\.sha \}\}/g)?.length, 2);
  assert.match(deploy, /actions\/download-artifact@v4/);
  assert.match(deploy, /environment: production/);
  assert.match(deploy, /ref: \$\{\{ steps\.source\.outputs\.sha \}\}/);
  assert.match(deploy, /name: raywarden-release-production-\$\{\{ steps\.source\.outputs\.sha \}\}/);
  assert.match(deploy, /github-token: \$\{\{ github\.token \}\}/);
  assert.match(deploy, /repository: \$\{\{ github\.repository \}\}/);
  assert.match(deploy, /run-id: \$\{\{ steps\.source\.outputs\.run_id \}\}/);
  assert.match(deploy, /INTEGRATION_RUN_ID: \$\{\{ inputs\.run_id \}\}/);
  const deploymentCondition = deploy.match(/^    if: (.+)$/m)?.[1];
  assert.ok(deploymentCondition);
  const mayRunDeployment = new Function("github", `return (${deploymentCondition});`);
  assert.equal(mayRunDeployment({ ref: "refs/heads/main" }), true);
  assert.equal(mayRunDeployment({ ref: "refs/heads/feature" }), false);
  assert.ok(deploy.indexOf("id: source") < deploy.indexOf("- name: Check out source"));
  assert.match(deploy, /just db-migrate production/);
  assert.doesNotMatch(deploy, /TARGET_ENV|inputs\.environment|outputs\.environment/);
  assert.match(deploy, /cancel-in-progress: false/);
  assert.match(deploy, /just artifact-check/);
  assert.match(deploy, /just setup-deploy/);
  assert.doesNotMatch(deploy, /just setup(?: |$)|just ci|just dry-run|just bootstrap|just build|cargo|rustup|just ui/m);
  assert.ok(deploy.indexOf('just artifact-check') < deploy.indexOf('just db-migrate'));
  assert.ok(deploy.indexOf('just db-migrate') < deploy.indexOf('just deploy-worker'));
  for (const old of ["ci.yml", "deploy.yml"]) assert.equal(existsSync(resolve(PROJECT_ROOT, ".github/workflows", old)), false);
});

test("production and local configurations isolate resources and route dynamic endpoints through the Worker", () => {
  const production = parseJsonc(readFileSync(resolve(PROJECT_ROOT, "wrangler.jsonc"), "utf8"));
  const local = parseJsonc(readFileSync(resolve(PROJECT_ROOT, "wrangler.local.jsonc"), "utf8"));
  assert.equal(production.env, undefined);
  assert.notEqual(production.name, local.name);
  assert.notEqual(production.d1_databases[0].database_id, local.d1_databases[0].database_id);
  assert.notEqual(production.d1_databases[0].database_name, local.d1_databases[0].database_name);
  assert.notEqual(production.r2_buckets[0].bucket_name, local.r2_buckets[0].bucket_name);
  const namespaces = [];
  for (const config of [production, local]) {
    assert.equal(config.main, "build/index.js");
    assert.equal(config.d1_databases[0].binding, "warden-db");
    assert.equal(config.r2_buckets[0].binding, "ATTACHMENTS_BUCKET");
    for (const name of ["LOGIN_RATE_LIMITER", "SEND_ACCESS_RATE_LIMITER"]) {
      const limiter = config.ratelimits.find((value) => value.name === name);
      assert.ok(limiter, `${config.name} needs ${name}`);
      assert.match(String(limiter.namespace_id), /^\d+$/);
      namespaces.push(limiter.namespace_id);
    }
    for (const path of ["/two-factor/send-email-login", "/css/vaultwarden.css", "/demo.html"]) {
      assert.ok(config.assets.run_worker_first.some((rule) => rule === path || (rule.endsWith("/*") && path.startsWith(rule.slice(0, -1)))), `${config.name} must route ${path} through the Worker`);
    }
  }
  assert.equal(new Set(namespaces).size, 4);
});
