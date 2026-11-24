import { createHash } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

export const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DATABASE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Wrangler's JSONC subset: comments and trailing commas. Scan outside JSON
// strings so URLs, escaped quotes and comment-like text retain their contents.
export function parseJsonc(source) {
  let clean = "";
  let string = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (string) {
      clean += c;
      if (c === "\\") clean += source[++i] ?? "";
      else if (c === '"') string = false;
    } else if (c === '"') { string = true; clean += c; }
    else if (c === "/" && source[i + 1] === "/") {
      while (i < source.length && source[i] !== "\n") i++;
      clean += "\n";
    } else if (c === "/" && source[i + 1] === "*") {
      const end = source.indexOf("*/", i + 2);
      if (end < 0) throw new Error("Unterminated JSONC comment");
      clean += " ";
      i = end + 1;
    } else clean += c;
  }
  let json = "";
  string = false;
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i];
    if (string) {
      json += c;
      if (c === "\\") json += clean[++i] ?? "";
      else if (c === '"') string = false;
    } else if (c === '"') { string = true; json += c; }
    else if (c === "," && /^[\s]*[}\]]/.test(clean.slice(i + 1))) json += " ";
    else json += c;
  }
  return JSON.parse(json.replace(/^\uFEFF/, ""));
}

function validateRateLimitBindings(config) {
  const required = ["LOGIN_RATE_LIMITER", "SEND_ACCESS_RATE_LIMITER"];
  if (!Array.isArray(config.ratelimits)) throw new Error(`production requires ratelimits bindings: ${required.join(", ")}`);
  const namespaces = [];
  for (const name of required) {
    const bindings = config.ratelimits.filter(binding => binding?.name === name);
    if (bindings.length !== 1) throw new Error(`production requires exactly one ${name} rate limit binding`);
    const binding = bindings[0];
    if (typeof binding.namespace_id !== "string" || !/^\d+$/.test(binding.namespace_id)) {
      throw new Error(`${name} requires a numeric string namespace_id`);
    }
    if (!Number.isSafeInteger(binding.simple?.limit) || binding.simple.limit <= 0 || ![10, 60].includes(binding.simple?.period)) {
      throw new Error(`${name} requires a positive integer simple.limit and simple.period of 10 or 60 seconds`);
    }
    namespaces.push(binding.namespace_id.replace(/^0+(?=\d)/, ""));
  }
  if (new Set(namespaces).size !== required.length) throw new Error("production login and Send rate limit bindings must use distinct namespace_id values");
}

export function readTargetConfig({ configPath = resolve(PROJECT_ROOT, "wrangler.jsonc") } = {}) {
  configPath = resolve(configPath);
  const config = parseJsonc(readFileSync(configPath, "utf8"));
  const name = config.name;
  if (typeof name !== "string" || name.length > 255 || !/^[a-z0-9][a-z0-9_-]*$/i.test(name)) throw new Error("Invalid or missing production Worker name");
  if (!Array.isArray(config.d1_databases) || config.d1_databases.length !== 1) throw new Error("production must configure exactly one explicit D1 binding");
  const database = config.d1_databases[0];
  if (database.binding !== "DB" || typeof database.database_name !== "string" || !database.database_name || !DATABASE_ID.test(database.database_id ?? "")) throw new Error("production D1 binding requires binding=DB, database_name and a real database_id");
  if (!database.migrations_dir || typeof database.migrations_dir !== "string") throw new Error("production D1 binding requires an explicit migrations_dir");
  const projectDir = dirname(configPath);
  const migrationsDir = resolve(projectDir, database.migrations_dir);
  const relativeDir = relative(projectDir, migrationsDir);
  if (relativeDir.startsWith("..") || isAbsolute(relativeDir)) throw new Error("migrations_dir must be inside the project");
  // Fail before resource discovery, migrations or upload. Runtime failures
  // also reject protected attempts rather than removing guessing protection.
  validateRateLimitBindings(config);
  if (config.observability?.redact_query_string !== true) {
    throw new Error("production requires observability.redact_query_string=true for credential-bearing URLs");
  }
  if (!Array.isArray(config.secrets?.required) || !config.secrets.required.includes("KEY_ENCRYPTION_KEY")) {
    throw new Error("production requires KEY_ENCRYPTION_KEY in secrets.required");
  }
  if (Object.hasOwn(config.vars ?? {}, "KEY_ENCRYPTION_KEY")) {
    throw new Error("KEY_ENCRYPTION_KEY must be a Worker Secret, not a production var");
  }
  // Custom domains are optional. Without one, resolve workers.dev remotely.
  const routes = config.routes ?? [];
  if (!Array.isArray(routes)) throw new Error("routes must be an array");
  const route = routes.length === 1 ? routes[0] : undefined;
  const hostname = route?.pattern;
  if (routes.length && (route?.custom_domain !== true || typeof hostname !== "string" || hostname.length > 253 ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(hostname))) {
    throw new Error("when configured, routes must contain one custom_domain route with a plain hostname");
  }
  const domain = routes.length ? `https://${hostname.toLowerCase()}` : undefined;
  if (config.workers_dev !== undefined && typeof config.workers_dev !== "boolean") throw new Error("workers_dev must be a boolean");
  // Wrangler infers false when routes exist and workers_dev is omitted.
  const workersDev = config.workers_dev ?? routes.length === 0;
  if (workersDev && !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(name)) throw new Error("Worker name must be a DNS label of at most 63 characters when workers_dev is enabled");
  const buckets = config.r2_buckets ?? [];
  if (!Array.isArray(buckets) || buckets.some((b) => b.binding !== "ATTACHMENTS_BUCKET" || typeof b.bucket_name !== "string" || !b.bucket_name)) throw new Error("production contains an incomplete R2 binding");
  return { configPath, projectDir, name, database, migrationsDir, buckets, domain, workersDev, accountId: config.account_id ?? "" };
}

const ACCOUNT_ID = /^[0-9a-f]{32}$/i;
export class CloudflareApiError extends Error {
  constructor(message, status) { super(message); this.name = "CloudflareApiError"; this.status = status; }
}

export class CloudflareApi {
  constructor(token, fetchImpl = globalThis.fetch) {
    if (!token) throw new Error("CLOUDFLARE_API_TOKEN is required");
    this.token = token;
    this.fetchImpl = fetchImpl;
  }
  async request(path) {
    // Verify configured resources; never create substitutes or alter the config.
    const response = await this.fetchImpl(`https://api.cloudflare.com/client/v4${path}`, {
      headers: { Accept: "application/json", Authorization: `Bearer ${this.token}` },
    });
    let payload;
    try { payload = await response.json(); }
    catch { throw new CloudflareApiError(`Cloudflare returned invalid JSON (HTTP ${response.status})`, response.status); }
    if (!response.ok || payload?.success === false) {
      const message = payload?.errors?.map((e) => e.message).filter(Boolean).join("; ");
      throw new CloudflareApiError(message || `Cloudflare HTTP ${response.status}`, response.status);
    }
    return payload;
  }
}

export async function resolveAccountId(api, configuredAccountId = "") {
  const supplied = configuredAccountId.trim();
  if (supplied) {
    if (!ACCOUNT_ID.test(supplied)) throw new Error("CLOUDFLARE_ACCOUNT_ID must contain 32 hexadecimal characters");
    return supplied;
  }
  const accounts = [];
  for (let page = 1; page <= 100; page++) {
    const payload = await api.request(`/accounts?page=${page}&per_page=50`);
    if (!Array.isArray(payload.result)) throw new Error("Cloudflare did not return an account list");
    accounts.push(...payload.result);
    if (payload.result.length < 50 || page >= Number(payload.result_info?.total_pages || Infinity)) break;
    if (page === 100) throw new Error("Account pagination exceeded 100 pages");
  }
  if (accounts.length !== 1 || !ACCOUNT_ID.test(accounts[0]?.id ?? "")) throw new Error("API token must access exactly one account, or set CLOUDFLARE_ACCOUNT_ID explicitly");
  return accounts[0].id;
}

export async function resolveWorkerUrl(target, api, accountId) {
  if (target.domain) return target.domain;
  if (!target.workersDev) throw new Error("No public health endpoint: enable workers_dev or configure a custom_domain route");
  const { result } = await api.request(`/accounts/${accountId}/workers/subdomain`);
  const subdomain = result?.subdomain;
  if (typeof subdomain !== "string" || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(subdomain)) {
    throw new Error("Configure an account workers.dev subdomain in Cloudflare Dashboard before deploying without routes");
  }
  return `https://${target.name.toLowerCase()}.${subdomain.toLowerCase()}.workers.dev`;
}

export async function verifyResources(env = process.env, fetchImpl = globalThis.fetch, options = {}) {
  // Validate all local resource identities before the first remote request.
  const target = readTargetConfig({ configPath: options.configPath });
  const api = new CloudflareApi(env.CLOUDFLARE_API_TOKEN, fetchImpl);
  const accountId = await resolveAccountId(api, env.CLOUDFLARE_ACCOUNT_ID || target.accountId);
  const { result: database } = await api.request(`/accounts/${accountId}/d1/database/${target.database.database_id}`);
  if (database?.uuid !== target.database.database_id || database?.name !== target.database.database_name) throw new Error("Configured D1 ID/name do not match the selected account; no resource was created or rewritten");
  for (const bucket of target.buckets) {
    const { result } = await api.request(`/accounts/${accountId}/r2/buckets/${encodeURIComponent(bucket.bucket_name)}`);
    if (result?.name !== bucket.bucket_name) throw new Error(`R2 bucket identity mismatch for ${bucket.bucket_name}`);
  }
  const workerUrl = await resolveWorkerUrl(target, api, accountId);
  const outputs = { account_id: accountId, worker_name: target.name, d1_database_id: target.database.database_id, worker_url: workerUrl, target_environment: "production" };
  console.log(`Verified production: Worker ${target.name}, D1 ${target.database.database_name}, ${target.buckets.length} R2 bucket(s)`);
  return outputs;
}


const RELEASE_HEADER = "X-Raywarden-Release-Id";
const RELEASE_VARIABLE = "RAYWARDEN_RELEASE_ID";
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;

function isHealthTimestamp(value) {
  const date = typeof value === "string" && RFC3339.exec(value);
  if (!date) return false;
  const [year, month, day] = date.slice(1).map(Number);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= days[month - 1];
}

export async function checkHealth({ configPath, attempts = 12, interval: retryIntervalMs = 5000, expectedReleaseId } = {}, fetchImpl = globalThis.fetch, wait = delay, environment = process.env) {
  const target = readTargetConfig({ configPath });
  let origin = target.domain;
  if (!origin) {
    const api = new CloudflareApi(environment.CLOUDFLARE_API_TOKEN, fetchImpl);
    const accountId = await resolveAccountId(api, environment.CLOUDFLARE_ACCOUNT_ID || target.accountId);
    origin = await resolveWorkerUrl(target, api, accountId);
  }
  const url = `${origin}/api/alive`;
  let failure;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const response = await fetchImpl(url, { cache: "no-store", redirect: "error", signal: AbortSignal.timeout(10000), headers: { Accept: "application/json", "User-Agent": "raywarden-health/0.1" } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = await response.text();
      let timestamp;
      try { timestamp = JSON.parse(body); } catch { throw new Error("Expected JSON from /api/alive"); }
      if (!isHealthTimestamp(timestamp)) throw new Error("Expected an RFC3339 timestamp from /api/alive");
      if (expectedReleaseId !== undefined && response.headers.get(RELEASE_HEADER) !== expectedReleaseId) {
        throw new Error("The public endpoint has not reported the expected release artifact");
      }
      console.log(`Health check passed: ${url}`);
      return { url };
    } catch (error) { failure = error; }
    if (attempt < attempts) await wait(retryIntervalMs);
  }
  throw new Error(`Health check failed for ${url}: ${failure?.message}`);
}


const SHA = /^[0-9a-f]{40}$/;
const fileSha256 = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
const posix = (path) => path.split(sep).join("/");
function withoutSetupSecrets(environment) {
  const { ALLOWED_EMAILS: _email, OWNER_SETUP_TOKEN: _token, KEY_ENCRYPTION_KEY: _key, ...remaining } = environment;
  return remaining;
}
async function readGitHead(projectDir) {
  const { stdout } = await promisify(execFile)("git", ["rev-parse", "HEAD"], { cwd: projectDir, env: withoutSetupSecrets(process.env) });
  return stdout.trim();
}
function resolveArtifactPath(projectDir, path) {
  const full = resolve(projectDir, path);
  const rel = relative(projectDir, full);
  if (!rel || rel.startsWith("..") || resolve(projectDir, rel) !== full) throw new Error(`Artifact path must be inside the project: ${path}`);
  return full;
}
function filesBelow(projectDir, path) {
  const full = resolveArtifactPath(projectDir, path);
  if (!existsSync(full)) throw new Error(`Missing artifact input: ${path}`);
  const stat = lstatSync(full);
  if (stat.isSymbolicLink()) throw new Error(`Artifact inputs cannot contain symbolic links: ${path}`);
  if (stat.isFile()) return [posix(relative(projectDir, full))];
  if (!stat.isDirectory()) throw new Error(`Unsupported artifact input: ${path}`);
  return readdirSync(full).sort().flatMap((name) => filesBelow(projectDir, posix(relative(projectDir, resolve(full, name)))));
}
function collectArtifactFiles(target, bundleFiles) {
  const remainingFiles = ["static/web-vault", "Cargo.lock", "package-lock.json"]
    .flatMap((path) => filesBelow(target.projectDir, path));
  return [...bundleFiles, ...remainingFiles].sort();
}
function validateArtifactInputs(target, bundleDirectory) {
  const assets = resolveArtifactPath(target.projectDir, "static/web-vault/index.html");
  if (!existsSync(assets)) throw new Error("Missing prepared Web Vault; obtain a validated release artifact");
  const bundleFiles = filesBelow(target.projectDir, bundleDirectory);
  const wasm = bundleFiles.filter((file) => file.endsWith(".wasm"));
  if (!wasm.length) throw new Error("Prebundled Worker artifact contains no WASM module");
  for (const file of wasm) {
    if (!readFileSync(resolveArtifactPath(target.projectDir, file)).subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))) throw new Error(`Invalid WASM module: ${file}`);
  }
  return bundleFiles;
}
export async function createArtifactManifest({ configPath, manifestPath, expectedSha } = {}, head = readGitHead) {
  const target = readTargetConfig({ configPath });
  const sourceSha = await head(target.projectDir);
  if (!SHA.test(sourceSha) || (expectedSha && sourceSha !== expectedSha)) throw new Error("Artifact source SHA does not match the checked-out commit");
  const bundleDirectory = ".wrangler/deploy-check/production";
  const bundleFiles = validateArtifactInputs(target, bundleDirectory);
  const config = parseJsonc(readFileSync(target.configPath, "utf8"));
  const entryName = basename(config.main).replace(/\.[cm]?tsx?$/, ".js");
  const entrypoint = `${bundleDirectory}/${entryName}`;
  if (!bundleFiles.includes(entrypoint)) throw new Error(`Missing prebundled entrypoint ${entrypoint}; run the release dry-run for this environment`);
  const files = Object.fromEntries(collectArtifactFiles(target, bundleFiles).map((file) => [file, fileSha256(resolveArtifactPath(target.projectDir, file))]));
  const manifest = { formatVersion: 1, sourceSha, environment: "production", configurationSha256: fileSha256(target.configPath), bundleDirectory, entrypoint, files };
  const output = manifestPath ? resolve(manifestPath) : resolve(target.projectDir, ".wrangler/artifact-manifest.json");
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Recorded ${files && Object.keys(files).length} artifact files for production at ${sourceSha}`);
  return manifest;
}

export async function verifyArtifact({ configPath, manifestPath, expectedSha } = {}, head = readGitHead) {
  const target = readTargetConfig({ configPath });
  const file = manifestPath ? resolve(manifestPath) : resolve(target.projectDir, ".wrangler/artifact-manifest.json");
  const manifest = JSON.parse(readFileSync(file, "utf8"));
  const sourceSha = await head(target.projectDir);
  if (manifest.formatVersion !== 1 || !SHA.test(manifest.sourceSha ?? "") || manifest.sourceSha !== sourceSha || (expectedSha && sourceSha !== expectedSha)) throw new Error("Artifact source SHA does not match the selected successful run and checkout");
  if (manifest.environment !== "production") throw new Error("Artifact environment does not match the deployment target");
  if (manifest.configurationSha256 !== fileSha256(target.configPath)) throw new Error("Deployment configuration changed after this artifact was built");
  const bundleDirectory = ".wrangler/deploy-check/production";
  if (manifest.bundleDirectory !== bundleDirectory || !manifest.entrypoint?.startsWith(`${bundleDirectory}/`)) throw new Error("Invalid artifact bundle path");
  const bundleFiles = validateArtifactInputs(target, bundleDirectory);
  const files = collectArtifactFiles(target, bundleFiles);
  if (!manifest.files || JSON.stringify(Object.keys(manifest.files).sort()) !== JSON.stringify(files)) throw new Error("Artifact file inventory changed or files are missing");
  for (const path of files) if (manifest.files[path] !== fileSha256(resolveArtifactPath(target.projectDir, path))) throw new Error(`Artifact digest mismatch: ${path}`);
  if (!files.includes(manifest.entrypoint)) throw new Error("Artifact entrypoint is missing");
  console.log(`Verified production artifact from ${sourceSha}`);
  return { target, manifest };
}

export function artifactReleaseId(manifest) {
  const files = Object.keys(manifest.files).sort().map(path => [path, manifest.files[path]]);
  return createHash("sha256").update(JSON.stringify([
    manifest.formatVersion, manifest.sourceSha, manifest.environment, manifest.configurationSha256,
    manifest.bundleDirectory, manifest.entrypoint, files,
  ])).digest("hex");
}

export function compiledConfig(target, manifest) {
  const config = parseJsonc(readFileSync(target.configPath, "utf8"));
  delete config.build;
  delete config.env;
  config.vars = { ...config.vars, [RELEASE_VARIABLE]: artifactReleaseId(manifest) };
  for (const binding of config.d1_databases ?? []) if (binding.migrations_dir) binding.migrations_dir = resolve(target.projectDir, binding.migrations_dir);
  config.main = resolveArtifactPath(target.projectDir, manifest.entrypoint);
  config.base_dir = resolveArtifactPath(target.projectDir, manifest.bundleDirectory);
  config.find_additional_modules = true;
  config.rules = [
    { type: "CompiledWasm", globs: ["**/*.wasm"], fallthrough: true },
    { type: "ESModule", globs: ["**/*.js", "**/*.mjs"], fallthrough: true },
    { type: "Text", globs: ["**/*.txt", "**/*.html", "**/*.sql"], fallthrough: true },
    { type: "Data", globs: ["**/*.bin"], fallthrough: true },
  ];
  config.assets = { ...config.assets, directory: resolve(target.projectDir, "static/web-vault") };
  return config;
}

function runWrangler(args, { projectRoot, environment }) {
  const logPath = environment.WRANGLER_LOG_PATH ?? resolve(projectRoot, ".wrangler/logs");
  const resolvedLogPath = resolve(projectRoot, logPath);
  mkdirSync(resolvedLogPath.endsWith(".log") ? dirname(resolvedLogPath) : resolvedLogPath, { recursive: true });
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, [resolve(projectRoot, "node_modules/wrangler/bin/wrangler.js"), ...args], {
      cwd: projectRoot,
      env: { ...environment, WRANGLER_SEND_METRICS: "false", WRANGLER_LOG_PATH: logPath },
      stdio: "inherit",
    });
    child.once("error", fail);
    child.once("close", (code, signal) => {
      if (code === 0) done();
      else fail(Object.assign(new Error(`Wrangler failed (${code ?? signal})`), { code, signal }));
    });
  });
}

function configuredSecrets(environment) {
  const secrets = {};
  const encryptionKey = environment.KEY_ENCRYPTION_KEY;
  if (encryptionKey !== undefined && encryptionKey !== "") {
    if (typeof encryptionKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(encryptionKey) ||
        Buffer.from(encryptionKey, "base64url").length !== 32 || Buffer.from(encryptionKey, "base64url").toString("base64url") !== encryptionKey) {
      throw new Error("KEY_ENCRYPTION_KEY must be 32 bytes encoded as unpadded canonical base64url");
    }
    secrets.KEY_ENCRYPTION_KEY = encryptionKey;
  }
  const email = environment.ALLOWED_EMAILS;
  if (email !== undefined && email !== "") {
    const emails = email.split(/[,\n]/).map(value => {
      const normalized = value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "").toLowerCase();
      const parts = normalized.split("@");
      const local = parts[0], domain = parts[1];
      if (/[^\x00-\x7f]/.test(value) || /\p{Cc}/u.test(value) || normalized.length > 254 || parts.length !== 2 ||
          !local || local.length > 64 || !/^[a-z0-9._+-]+$/.test(local) || local.startsWith(".") || local.endsWith(".") || local.includes("..") ||
          !domain || domain.length > 253 || domain.split(".").length < 2 ||
          domain.split(".").some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
        throw new Error("ALLOWED_EMAILS must contain complete email addresses separated by commas or newlines, without wildcards or empty entries");
      }
      return normalized;
    });
    secrets.ALLOWED_EMAILS = [...new Set(emails)].sort().join(",");
  }
  const token = environment.OWNER_SETUP_TOKEN;
  if (token !== undefined && token !== "") {
    const length = Array.from(token).length;
    if (length < 32 || length > 512 || /^\p{White_Space}|\p{White_Space}$/u.test(token) || /\p{Cc}/u.test(token)) {
      throw new Error("OWNER_SETUP_TOKEN must contain 32 to 512 characters without control characters or surrounding whitespace");
    }
    secrets.OWNER_SETUP_TOKEN = token;
  }
  return secrets;
}

export async function deployArtifact(options = {}, runner = runWrangler, head = readGitHead, environment = process.env, fetchImpl = globalThis.fetch) {
  const { target, manifest } = await verifyArtifact(options, head);
  // Invalid supplied values fail before network calls or temporary secret files.
  // Omitted optional values inherit the existing encrypted Worker bindings.
  const secrets = configuredSecrets(environment);
  let domain = target.domain;
  if (!domain) {
    const api = new CloudflareApi(environment.CLOUDFLARE_API_TOKEN, fetchImpl);
    const accountId = await resolveAccountId(api, environment.CLOUDFLARE_ACCOUNT_ID || target.accountId);
    domain = await resolveWorkerUrl(target, api, accountId);
  }
  secrets.DOMAIN = domain;
  const tempRoot = resolve(target.projectDir, ".wrangler");
  mkdirSync(tempRoot, { recursive: true });
  const temp = mkdtempSync(resolve(tempRoot, "compiled-config-"));
  try {
    chmodSync(temp, 0o700);
    const configPath = resolve(temp, "wrangler.json");
    const secretsPath = resolve(temp, "secrets.json");
    writeFileSync(configPath, JSON.stringify(compiledConfig(target, manifest), null, 2));
    writeFileSync(secretsPath, JSON.stringify(secrets), { mode: 0o600 });
    // --no-bundle skips Wrangler's internal compiler. Removing build above also
    // prevents the separate custom command from invoking worker-build/Cargo.
    // First deployment cannot pre-create secrets on a nonexistent Worker.
    // Values travel only through the private file, never in argv or logs.
    return await runner(["deploy", "--no-bundle", "--config", configPath, "--secrets-file", secretsPath, "--env", ""], { projectRoot: target.projectDir, environment: withoutSetupSecrets(environment) });
  } finally { rmSync(temp, { recursive: true, force: true }); }
}


export function parseDeployArgs(args, environment = process.env) {
  const [command, ...flags] = args;
  if (!["config", "preflight", "resources", "health", "release-health", "manifest", "verify", "worker"].includes(command)) {
    throw new Error("Usage: deploy.mjs config|preflight|resources|health|release-health|manifest|verify|worker");
  }
  const options = {};
  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    const key = { "--manifest": "manifestPath", "--expected-sha": "expectedSha" }[flag];
    if (!key || options[key] !== undefined) throw new Error(`Unknown or duplicate deployment argument: ${flag}`);
    const value = flags[++i];
    if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value`);
    options[key] = value;
  }
  const artifactCommand = ["manifest", "verify", "worker", "release-health"].includes(command);
  if (!artifactCommand && (options.manifestPath !== undefined || options.expectedSha !== undefined)) {
    throw new Error("--manifest and --expected-sha apply only to manifest, verify, worker and release-health");
  }
  if (artifactCommand) {
    options.expectedSha ??= environment.ARTIFACT_SOURCE_SHA;
    if (options.expectedSha && !SHA.test(options.expectedSha)) throw new Error("--expected-sha must be a full commit SHA");
  }
  return { command, ...options };
}

export async function main(argv = process.argv.slice(2), environment = process.env) {
  const { command, ...options } = parseDeployArgs(argv, environment);
  switch (command) {
    case "config": {
      const target = readTargetConfig(options);
      console.log(`Valid production: ${target.name}, ${target.database.database_name}, ${target.domain ?? "workers.dev (resolved during resource verification)"}`);
      return target;
    }
    case "resources": return verifyResources(environment, globalThis.fetch, options);
    case "health": return checkHealth(options, globalThis.fetch, delay, environment);
    case "release-health": {
      const { target, manifest } = await verifyArtifact(options);
      const healthOptions = { configPath: target.configPath, expectedReleaseId: artifactReleaseId(manifest) };
      return checkHealth(healthOptions, globalThis.fetch, delay, environment);
    }
    case "preflight": {
      readTargetConfig(options);
      configuredSecrets(environment);
      console.log("Supplied production secret formats are valid");
      break;
    }
    case "manifest": return createArtifactManifest(options);
    case "verify": return verifyArtifact(options);
    case "worker": return deployArtifact(options, undefined, undefined, environment);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`Deployment command failed: ${error.message}`);
    process.exitCode = 1;
  });
}
