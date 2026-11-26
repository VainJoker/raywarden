import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import {
  PROJECT_ROOT, artifactReleaseId, checkHealth, createArtifactManifest, deployArtifact as deployImpl,
  main as deployMain, parseDeployArgs, parseJsonc, readTargetConfig, verifyArtifact, verifyResources,
} from "../scripts/deploy.mjs";

const account = "a".repeat(32), uuid = "11111111-1111-4111-8111-111111111111", sha = "a".repeat(40);
const wrappingKey = Buffer.alloc(32, 3).toString("base64url"), head = async () => sha;
const response = (result, status = 200) => new Response(JSON.stringify({ success: status < 400, result }), { status });

function prodConfig({ name = "configured-worker", databaseName = "configured-db", bucketName = "configured-files" } = {}) {
  return {
    name, secrets: { required: ["DOMAIN", "KEY_ENCRYPTION_KEY"] },
    observability: { redact_query_string: true }, routes: [{ pattern: "vault.example.test", custom_domain: true }],
    d1_databases: [{ binding: "DB", database_name: databaseName, database_id: uuid, migrations_dir: "sql/migrations" }],
    r2_buckets: [{ binding: "ATTACHMENTS_BUCKET", bucket_name: bucketName }],
    ratelimits: [
      { name: "LOGIN_RATE_LIMITER", namespace_id: "3101", simple: { limit: 5, period: 60 } },
      { name: "SEND_ACCESS_RATE_LIMITER", namespace_id: "3103", simple: { limit: 15, period: 60 } },
    ],
  };
}

test("JSONC, target config, resource verification, health, and manifest lifecycle", async (t) => {
  assert.deepEqual(parseJsonc('{ // note\n "url": "https://a//b/*c*/", "arr": [1,], }'), { url: "https://a//b/*c*/", arr: [1] });
  assert.throws(() => parseJsonc('{"x":1/*'), /Unterminated/);

  const dir = mkdtempSync(join(tmpdir(), "raywarden-deploy-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const write = (p, body) => { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), body); };

  const cfg = { ...prodConfig(), routes: undefined, workers_dev: true, main: "build/index.js", build: { command: "skip" }, vars: { LOG_LEVEL: "info" }, assets: { directory: "static/web-vault" } };
  write("wrangler.jsonc", JSON.stringify(cfg));
  for (const p of ["Cargo.lock", "package-lock.json"]) write(p, "lock\n");
  write("static/web-vault/index.html", "<!doctype html>");
  write(".wrangler/deploy-check/production/index.js", "export default {};\n");
  write(".wrangler/deploy-check/production/worker.wasm", Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));

  const configPath = join(dir, "wrangler.jsonc"), env = { CLOUDFLARE_API_TOKEN: "tok", CLOUDFLARE_ACCOUNT_ID: account };
  const releaseId = "b".repeat(64);
  const fetchMock = async (url) => {
    if (url.endsWith(`/d1/database/${uuid}`)) return response({ uuid, name: "configured-db" });
    if (url.endsWith("/r2/buckets/configured-files")) return response({ name: "configured-files" });
    if (url.endsWith("/workers/subdomain")) return response({ subdomain: "acct" });
    if (url.endsWith("/versions")) return response({ items: [] });
    return Response.json("2026-11-13T00:00:00Z", { headers: { "X-Raywarden-Release-Id": releaseId } });
  };
  assert.equal((await verifyResources(env, fetchMock, { configPath })).worker_url, "https://configured-worker.acct.workers.dev");
  await checkHealth({ configPath, attempts: 1, expectedReleaseId: releaseId }, fetchMock, async () => {}, env);

  const opts = { configPath, expectedSha: sha };
  const manifest = await createArtifactManifest(opts, head);
  assert.equal((await verifyArtifact(opts, head)).manifest.sourceSha, sha);

  let tempCfg;
  await deployImpl(opts, (args, cmdOpts) => {
    tempCfg = args[args.indexOf("--config") + 1];
    assert.equal(statSync(args[args.indexOf("--secrets-file") + 1]).mode & 0o777, 0o600);
    assert.equal(cmdOpts.environment.KEY_ENCRYPTION_KEY, undefined);
    assert.equal(JSON.parse(readFileSync(tempCfg, "utf8")).vars.RAYWARDEN_RELEASE_ID, artifactReleaseId(manifest));
  }, head, { ...env, KEY_ENCRYPTION_KEY: wrappingKey, ALLOWED_EMAILS: "owner@example.test" }, fetchMock);
  assert.equal(existsSync(tempCfg), false);

  const realCfg = parseJsonc(readFileSync(resolve(PROJECT_ROOT, "wrangler.jsonc"), "utf8"));
  assert.notEqual(realCfg.d1_databases[0].database_id, realCfg.env.local.d1_databases[0].database_id);
  await deployMain(["preflight"], { ALLOWED_EMAILS: "owner@example.test", KEY_ENCRYPTION_KEY: wrappingKey });
  assert.equal(parseDeployArgs(["manifest"], { ARTIFACT_SOURCE_SHA: sha }).expectedSha, sha);
});
