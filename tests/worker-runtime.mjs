import RustWorker, { HeavyDo, NotifyDo } from "./index.js";
import { schema, reset } from "./runtime-schema.mjs";
import { runAccountCompatibility } from "./account-runtime.mjs";
import { runSendCompatibility } from "./send-runtime.mjs";
import { runTwoFactorCompatibility } from "./two-factor-runtime.mjs";
import { runJwtCompatibility } from "./jwt-runtime.mjs";
import { runConfigurationCompatibility } from "./config-runtime.mjs";
import { runPresentationCompatibility } from "./presentation-runtime.mjs";
import { runAdminNotificationCompatibility } from "./admin-notify-runtime.mjs";
import { runSetupCompatibility } from "./setup-runtime.mjs";
import { runPasswordCompatibility } from "./password-runtime.mjs";
import { runPreloginCompatibility } from "./prelogin-runtime.mjs";
import { runRecoveryCompatibility } from "./recovery-runtime.mjs";
import { runSetPasswordCompatibility } from "./set-password-runtime.mjs";
import { runAuthSessionChecks } from "./auth-session-runtime.mjs";
import { runSendParityCompatibility } from "./send-parity-runtime.mjs";
import { runRouteParityCompatibility } from "./route-parity-runtime.mjs";
import { runAccountSettingsChecks } from "./account-settings-runtime.mjs";
import { runProtectedActionCompatibility } from "./protected-action-runtime.mjs";
import { runPersonalVaultCompatibility } from "./personal-vault-runtime.mjs";
import { assertDownloadSecurityHeaders, runSecurityHeadersCompatibility } from "./security-headers-runtime.mjs";
import { runRateLimitChecks } from "./rate-limit-runtime.mjs";

const SECRET = "runtime-test-only-access-secret";
const USER = "00000000-0000-4000-8000-000000000001";
const CIPHER = "00000000-0000-4000-8000-000000000002";
const FILE = "00000000-0000-4000-8000-000000000003";
const SEND = "00000000-0000-4000-8000-000000000004";
const NOW = "2026-01-01T00:00:00.000Z";
const ORIGIN = "https://client.test";
const ATTACHMENT_KEY = `${CIPHER}/${FILE}`;
const SEND_KEY = `sends/${SEND}/${FILE}`;
const encoder = new TextEncoder();

function equal(actual, expected, message = "value mismatch") {
  if (actual !== expected) throw new Error(`${message}: expected ${expected}, received ${actual}`);
}
function ok(value, message) { if (!value) throw new Error(message); }
function sameBytes(actual, expected) {
  equal(actual.length, expected.length, "byte length");
  for (let i = 0; i < expected.length; i++) equal(actual[i], expected[i], `byte ${i}`);
}

// Match workerd's D1PreparedStatement.bind contract before native SQLite:
// booleans become integers; BigInt/undefined are rejected rather than masked.
function d1Binding(value) {
  if (typeof value === "boolean") return Number(value);
  if (value === null || typeof value === "number" || typeof value === "string" || value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
  if (Array.isArray(value) && value.every(byte => typeof byte === "number" && byte >= 0 && byte < 256)) return new Uint8Array(value).buffer;
  const error = new Error(`D1_TYPE_ERROR: Type '${typeof value}' is not supported`);
  lastSqlFailure = { message: error.message };
  throw error;
}

// The SDK binding adapter executes production SQL in workerd's native SQLite.
// It has no access to an application database or to the network.
let sqlState;
let lastSqlFailure;
class D1Database {
  constructor({ empty = false } = {}) {
    sqlState.storage.sql.exec(reset + schema);
    lastSqlFailure = undefined;
    this.batches = 0; this.claims = 0; this.queries = []; this.failBatch = false;
    this.execute("INSERT INTO jwt_keys(id,access_secret,refresh_secret) VALUES('global',?,?)", [SECRET,"runtime-test-refresh-secret"]);
    if (!empty) {
      this.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,security_stamp,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", [USER,"owner@example.test","hash","2.wrapped","2.private","public","owner-stamp",NOW,NOW]);
      this.execute("INSERT INTO users(id,email,master_password_hash,key,private_key,public_key,security_stamp,created_at,updated_at) VALUES('other-owner','other@example.test','hash','key','private','public','other','old','old')");
      this.execute("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", [USER,"device","runtime",0,"session",NOW,NOW]);
      this.cipher = { id: CIPHER, user_id: USER, organization_id: null, cipher_type: 1, data: '{"name":"encrypted"}', is_favorite: 0, folder_id: null, deleted_at: null, archived_at: null, created_at: NOW, updated_at: NOW };
      this.attachment = { id: FILE, cipher_id: CIPHER, file_name: "encrypted-name", file_size_bytes: 6, encrypted_key: "encrypted-key", created_at: NOW, updated_at: NOW, organization_id: null };
      this.pending = { ...this.attachment };
      this.send = { id: SEND, user_id: USER, name: "encrypted", notes: null, send_type: 1, data: '{"fileName":"encrypted"}', encrypted_key: "encrypted-key", password_hash: null, password_salt: null, password_iterations: null, max_access_count: null, access_count: 0, created_at: NOW, updated_at: NOW, expires_at: null, deletes_at: "2099-01-01T00:00:00.000Z", is_disabled: 0, is_email_hidden: 0, access_stamp: "send-stamp", file_id: FILE, file_size_bytes: 6, upload_state: 0 };
    }
    this.queries = [];
  }
  execute(sql, params = []) {
    this.queries?.push(sql);
    if (/^UPDATE sends SET upload_state=2/.test(sql)) this.claims++;
    let cursor;
    try { cursor = sqlState.storage.sql.exec(sql, ...params.map(v => v === undefined ? null : v)); }
    catch (error) { lastSqlFailure = { sql, message: error.message }; throw error; }
    const results = cursor.toArray();
    const changes = sqlState.storage.sql.exec("SELECT changes() AS n").one().n;
    return { success: true, results, meta: { changes } };
  }
  prepare(sql) {
    const db = this;
    const statement = (params = []) => ({
      sql, params,
      bind(...values) { return statement(values.map(d1Binding)); },
      async first(column) { const row = db.execute(sql, params).results[0] ?? null; return column && row ? row[column] : row; },
      async run() { return db.execute(sql, params); },
      async all() { return db.execute(sql, params); },
    });
    return statement();
  }
  async batch(statements) {
    this.batches++;
    if (this.failBatch) throw new Error("fixture transaction rejected");
    return sqlState.storage.transactionSync(() => statements.map(s => this.execute(s.sql, s.params)));
  }
  row(table, id) {
    const row = sqlState.storage.sql.exec(`SELECT * FROM ${table} WHERE id=?`, id).toArray()[0];
    if (!row) return null;
    return new Proxy(row, { set: (target, column, value) => {
      sqlState.storage.sql.exec(`UPDATE ${table} SET ${column}=? WHERE id=?`, value, id);
      target[column] = value; return true;
    } });
  }
  setRow(table, id, row) {
    if (!row) { sqlState.storage.sql.exec(`DELETE FROM ${table} WHERE id=?`, id); return; }
    const columns = new Set(sqlState.storage.sql.exec(`PRAGMA table_info(${table})`).toArray().map(c => c.name));
    const keys = Object.keys(row).filter(key => columns.has(key));
    sqlState.storage.sql.exec(`INSERT INTO ${table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')}) ON CONFLICT(id) DO UPDATE SET ${keys.map(k => `${k}=excluded.${k}`).join(',')}`, ...keys.map(k => row[k]));
  }
  get cipher() { return this.row("ciphers", CIPHER); }
  set cipher(value) { this.setRow("ciphers", CIPHER, value); }
  get attachment() { return this.row("attachments", FILE); }
  set attachment(value) { this.setRow("attachments", FILE, value); }
  get pending() { return this.row("attachments_pending", FILE); }
  set pending(value) { this.setRow("attachments_pending", FILE, value); }
  get send() { return this.row("sends", SEND); }
  set send(value) { this.setRow("sends", SEND, value); }
  get sessionValid() { return sqlState.storage.sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token === "session"; }
  set sessionValid(value) { sqlState.storage.sql.exec("UPDATE devices SET session_token=? WHERE user_id=? AND device_id='device'", value ? "session" : "revoked", USER); }
}

class R2Bucket {
  constructor() { this.objects = new Map(); this.httpMetadata = new Map(); this.uploads = new Map(); this.uploadMetadata = new Map(); this.deleted = []; this.parts = []; this.heads = 0; this.gets = 0; this.created = 0; this.aborted = 0; this.completed = 0; }
  object(key, body) {
    const data = this.objects.get(key);
    if (!data) return null;
    const object = { key, size: data.length, httpMetadata: this.httpMetadata.get(key) ?? {}, httpEtag: '\"fixture-etag\"' };
    if (body) { object.body = body; object.bodyUsed = false; }
    return object;
  }
  async head(key) { this.heads++; return this.object(key); }
  async get(key, options = {}) {
    this.gets++;
    const all = this.objects.get(key);
    if (!all) return null;
    const range = options.range;
    const data = range ? all.subarray(range.offset, range.offset + range.length) : all;
    let offset = 0;
    this.lastBody = new ReadableStream({ pull(controller) {
      if (offset === data.length) { controller.close(); return; }
      const end = Math.min(offset + 65536, data.length);
      controller.enqueue(data.subarray(offset, end));
      offset = end;
    } });
    return this.object(key, this.lastBody);
  }
  async put(key, data, options = {}) {
    this.objects.set(key, new Uint8Array(await new Response(data).arrayBuffer()));
    this.httpMetadata.set(key, { ...options.httpMetadata });
    this.afterPut?.();
    return this.object(key);
  }
  async delete(key) { for (const value of Array.isArray(key) ? key : [key]) { this.deleted.push(value); this.objects.delete(value); this.httpMetadata.delete(value); } }
  handle(key, uploadId) {
    const bucket = this;
    return {
      uploadId,
      async uploadPart(partNumber, data) {
        const bytes = new Uint8Array(await new Response(data).arrayBuffer());
        bucket.parts.push(bytes.length);
        bucket.uploads.get(uploadId).set(partNumber, bytes);
        return { partNumber, etag: `part-${partNumber}` };
      },
      async complete(parts) {
        const stored = bucket.uploads.get(uploadId);
        const size = parts.reduce((n, p) => n + stored.get(p.partNumber).length, 0);
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const p of parts) { const part = stored.get(p.partNumber); bytes.set(part, offset); offset += part.length; }
        bucket.objects.set(key, bytes);
        bucket.httpMetadata.set(key, bucket.uploadMetadata.get(uploadId) ?? {});
        bucket.uploads.delete(uploadId);
        bucket.uploadMetadata.delete(uploadId);
        bucket.completed++;
        return bucket.object(key);
      },
      async abort() { bucket.uploads.delete(uploadId); bucket.uploadMetadata.delete(uploadId); bucket.aborted++; },
    };
  }
  async createMultipartUpload(key, options = {}) {
    const id = `upload-${++this.created}`;
    this.uploads.set(id, new Map());
    this.uploadMetadata.set(id, { ...options.httpMetadata });
    return this.handle(key, id);
  }
  resumeMultipartUpload(key, id) { return this.handle(key, id); }
}

class DurableObjectNamespace {
  constructor(handler) { this.handler = handler; }
  idFromName(name) { return { name }; }
  get(id) { return { fetch: (request) => this.handler(request, id.name) }; }
}

class KvNamespace {
  constructor() { this.objects = new Map(); this.gets = 0; this.puts = 0; this.deleted = []; }
  async get(key, options) { return (await this.getWithMetadata(key, options)).value; }
  async getWithMetadata(key, options) {
    this.gets++;
    equal(options.type, "arrayBuffer", "KV reads must keep the historical raw-byte format");
    const object = this.objects.get(key);
    return object ? { value: object.value.slice(0), metadata: object.metadata } : { value: null, metadata: null };
  }
  async put(key, value, options) {
    this.puts++;
    ok(value instanceof ArrayBuffer, "KV put must store raw ArrayBuffer bytes");
    this.objects.set(key, { value: value.slice(0), metadata: options.metadata });
  }
  async delete(key) { this.deleted.push(key); this.objects.delete(key); }
  async list() { throw new Error("Unexpected KV list in file fixture"); }
}

// Normal fixtures have working platform protection. Failure cases explicitly
// remove or replace these bindings, so they exercise fail-closed production code.
class Ratelimit {
  async limit() { return { success: true }; }
}

function fixture(ctx, options = {}) {
  const db = new D1Database(options);
  const bucket = new R2Bucket();
  const env = { DOMAIN: "https://vault.test", LOG_LEVEL: "off", HEAVY_DO_ENABLED: "false", CORS_ALLOWED_ORIGINS: ORIGIN,
    KEY_ENCRYPTION_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    LOGIN_RATE_LIMITER: new Ratelimit(), SEND_ACCESS_RATE_LIMITER: new Ratelimit(),
    DB: db, ATTACHMENTS_BUCKET: bucket };
  if (!options.empty) {
    bucket.objects.set(ATTACHMENT_KEY, new Uint8Array([0, 1, 2, 3, 128, 255]));
    bucket.objects.set(SEND_KEY, new Uint8Array([0, 1, 2, 3, 128, 255]));
  }
  return { db, bucket, env, fetch: (path, init) => new RustWorker(ctx, env).fetch(new Request(`https://vault.test${path}`, init)) };
}
function attachmentUploadFixture(ctx) {
  const f = fixture(ctx);
  f.db.attachment = null;
  f.bucket.objects.delete(ATTACHMENT_KEY);
  sqlState.storage.sql.exec("DELETE FROM storage_cleanup_jobs");
  return f;
}

function kvFixture(ctx, upload = false) {
  const f = upload ? attachmentUploadFixture(ctx) : fixture(ctx); const kv = new KvNamespace();
  delete f.env.ATTACHMENTS_BUCKET;
  f.env.ATTACHMENTS_KV = kv;
  return { ...f, kv };
}
function base64url(bytes) { return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""); }
async function token(claims, secret = SECRET) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(encoder.encode('{"alg":"HS256","typ":"JWT"}'));
  const body = base64url(encoder.encode(JSON.stringify({ iat: now, nbf: now - 1, exp: now + 300, ...claims })));
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return `${header}.${body}.${base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(`${header}.${body}`))))}`;
}
const attachmentToken = (claims = {}, secret) => token({ sub: USER, cipher_id: CIPHER, attachment_id: FILE, device: "device", ...claims }, secret);
const sendToken = (scope = "send.download", claims = {}) => token({ sub: scope === "send.upload" ? USER : SEND, aud: "raywarden.send", scope, send_id: SEND, file_id: FILE, access_stamp: "send-stamp", sstamp: "owner-stamp", device: "device", session_token: "session", ...claims });
const accessToken = (claims = {}) => token({ sub: USER, token_use: "access", sstamp: "owner-stamp", session_token: "session", device: "device", ...claims });
const attachmentPath = (suffix, signed) => `/api/ciphers/${CIPHER}/attachment/${FILE}/${suffix}?token=${signed}`;
function byteStream(size, fail = false) {
  let offset = 0;
  return new ReadableStream({ pull(controller) {
    if (offset === size) { if (fail) controller.error(new Error("fixture interrupted stream")); else controller.close(); return; }
    const chunk = new Uint8Array(Math.min(65536, size - offset));
    for (let i = 0; i < chunk.length; i++) chunk[i] = (offset + i) % 251;
    offset += chunk.length;
    controller.enqueue(chunk);
  } });
}

async function runSuite(ctx) {
  equal(typeof RustWorker, "function", "default Worker export");
  equal(typeof HeavyDo, "function", "HeavyDo export");
  equal(typeof NotifyDo, "function", "NotifyDo export");
  let passed = 0;
  const failed = [];
  async function check(name, run) {
    try { await run(); passed++; console.log(`PASS ${name}`); }
    catch (error) { failed.push({ name, error }); console.error(`FAIL ${name}: ${error.stack ?? error}`); if (lastSqlFailure) console.error("Most recent SQL boundary failure:", JSON.stringify(lastSqlFailure)); }
  }
  async function inertDownload(f, path, bytes, disposition) {
    for (const [method, range, status] of [["GET", null, 200], ["HEAD", null, 200], ["GET", "bytes=1-5", 206], ["HEAD", "bytes=1-5", 206], ["GET", "bytes=999-", 416]]) {
      const heads = f.bucket.heads, gets = f.bucket.gets;
      const response = await f.fetch(path, { method, headers: range ? { Range: range } : {} });
      equal(response.status, status, `${method} ${range ?? "full"}`);
      if (f.env.ATTACHMENTS_BUCKET) {
        equal(f.bucket.heads, heads + 1, "download reads R2 metadata once");
        equal(f.bucket.gets, gets + (method === "HEAD" || status === 416 ? 0 : 1), "only successful GET reads the R2 body once");
      }
      assertDownloadSecurityHeaders(response, disposition);
      if (status === 206) equal(response.headers.get("Content-Range"), `bytes 1-5/${bytes.length}`);
      if (status === 416) equal(response.headers.get("Content-Range"), `bytes */${bytes.length}`);
      if (method === "HEAD" || status === 416) equal(f.bucket.gets, gets, "metadata-only response avoids object reads");
      else if (f.env.ATTACHMENTS_BUCKET) equal(response.body, f.bucket.lastBody, "untrusted MIME keeps the native R2 stream");
      const expected = method === "HEAD" || status === 416 ? [] : status === 206 ? bytes.subarray(1, 6) : bytes;
      sameBytes(new Uint8Array(await response.arrayBuffer()), expected);
    }
  }

  await check("Rust entry, metadata and CORS", async () => {
    const f = fixture(ctx);
    let databaseLookups = 0, corsLookups = 0;
    Object.defineProperty(f.env, "DB", { get() { databaseLookups++; return f.db; } });
    Object.defineProperty(f.env, "CORS_ALLOWED_ORIGINS", { get() { corsLookups++; return ORIGIN; } });
    const response = await f.fetch("/api/alive", { headers: { Origin: ORIGIN } });
    equal(response.status, 200);
    JSON.parse(await response.text());
    equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    equal(databaseLookups, 1, "database binding lookups");
    equal(corsLookups, 1, "CORS configuration lookups");
  });
  await check("scheduled cleanup advances only affected revisions and drains deleted objects", async () => {
    const f = fixture(ctx);
    const sql = sqlState.storage.sql;
    const old = "2020-01-01T00:00:00.000Z", future = "2090-01-01T00:00:00.000Z";
    const retained = "retained-cipher", staleUpload = "stale-upload", currentUpload = "current-upload";
    f.db.cipher.deleted_at = old;
    f.db.setRow("ciphers", retained, { ...f.db.cipher, id: retained, user_id: "other-owner", deleted_at: null });
    f.db.setRow("attachments_pending", staleUpload, { ...f.db.pending, id: staleUpload, cipher_id: retained, created_at: old });
    f.db.setRow("attachments_pending", currentUpload, { ...f.db.pending, id: currentUpload, cipher_id: retained, created_at: future });
    f.bucket.objects.set(`${retained}/${staleUpload}`, new Uint8Array([1]));
    sql.exec("UPDATE users SET updated_at=?", future);
    sql.exec("INSERT INTO global_domains_cache VALUES(1, 4000000000)");
    let databaseLookups = 0;
    Object.defineProperty(f.env, "DB", { get() { databaseLookups++; return f.db; } });
    const runScheduled = () => new RustWorker(ctx, f.env).scheduled({ cron: "0 0 * * *", scheduledTime: Date.now() });

    sql.exec("CREATE TRIGGER reject_trash_delete BEFORE DELETE ON ciphers BEGIN SELECT RAISE(ABORT, 'injected trash cleanup failure'); END");
    await runScheduled();
    ok(f.db.cipher, "a failed purge removed the cipher");
    equal(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at, future);
    ok(f.bucket.objects.has(ATTACHMENT_KEY), "a failed purge removed retained bytes");
    equal(f.db.row("attachments_pending", staleUpload), null);

    sql.exec("DROP TRIGGER reject_trash_delete");
    await runScheduled();

    equal(f.db.cipher, null);
    ok(f.db.row("ciphers", retained), "cleanup removed a live cipher");
    equal(f.db.row("attachments_pending", staleUpload), null);
    ok(f.db.row("attachments_pending", currentUpload), "cleanup removed a current upload");
    equal(f.bucket.deleted.sort().join(","), [ATTACHMENT_KEY, `${retained}/${staleUpload}`].sort().join(","));
    equal(sql.exec("SELECT COUNT(*) AS n FROM storage_cleanup_jobs").one().n, 0);
    equal(Date.parse(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at), Date.parse(future) + 1);
    equal(sql.exec("SELECT updated_at FROM users WHERE id='other-owner'").one().updated_at, future);
    equal(databaseLookups, 2, "each scheduled invocation resolves D1 once");
  });
  await check("local requests skip the HeavyDo binding and leave unused bodies unread", async () => {
    const f = fixture(ctx); f.env.HEAVY_DO_ENABLED = "true";
    let bindings = 0, pulls = 0;
    Object.defineProperty(f.env, "HEAVY_DO", { get() { bindings++; throw new Error("local request consulted HeavyDo"); } });
    const alive = await f.fetch("/api/alive///?keep=a%2Fb");
    equal(alive.status, 200); await alive.arrayBuffer();
    const body = new ReadableStream({ pull() { pulls++; throw new Error("unused request body was read"); } }, { highWaterMark: 0 });
    const missing = await f.fetch("/api/not-a-route///?keep=a%2Fb", { method: "POST", body });
    equal(missing.status, 404); await missing.arrayBuffer();
    equal(bindings, 0, "local requests must not resolve the HeavyDo binding");
    equal(pulls, 0, "routing an unused body must not consume it");
  });
  await check("HeavyDo selects token and registration shards without changing forwarded requests or CORS", async () => {
    const maximumPrefix = "grant_type=password&username=OWNER%40EXAMPLE.TEST&padding=";
    const cases = [
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=password&username=%20OWNER%40EXAMPLE.TEST%20&password=opaque", "heavy:9"],
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=client_credentials&client_id=%20USER.ALICE%20&client_secret=opaque", "heavy:0"],
      ...["/api/accounts/register", "/identity/accounts/register", "/identity/accounts/register/finish"].map(path =>
        [path, "application/json", '{"email":" OWNER@EXAMPLE.TEST ","preserve":"a b"}', "heavy:9"]),
      ["/identity/connect/token", "application/x-www-form-urlencoded", maximumPrefix + "x".repeat(65536 - maximumPrefix.length), "heavy:9"],
    ];
    for (const [path, contentType, text, shard] of cases) {
      const f = fixture(ctx); f.env.HEAVY_DO_ENABLED = "true"; f.env.HEAVY_DO_SHARDS = "16";
      f.db.prepare = () => { throw new Error("offloaded request touched D1 before forwarding"); };
      let forwarded = 0;
      f.env.HEAVY_DO = new DurableObjectNamespace(async (request, name) => {
        forwarded++;
        equal(name, shard, "normalized identity selects the expected shard");
        equal(request.method, "POST"); equal(request.bodyUsed, false);
        const url = new URL(request.url);
        equal(url.pathname, path); equal(url.search, "?keep=a%2Fb&flag=two+words");
        equal(request.headers.get("Content-Type"), contentType);
        equal(await request.text(), text, "shard selection must preserve the complete original body");
        return new Response("offloaded", { status: 202, headers: { "Access-Control-Allow-Origin": ORIGIN, Vary: "X-Heavy-Fixture" } });
      });
      const bytes = encoder.encode(text); let offset = 0;
      const body = new ReadableStream({ pull(controller) {
        if (offset === bytes.length) { controller.close(); return; }
        const end = Math.min(offset + 4096, bytes.length);
        controller.enqueue(bytes.subarray(offset, end)); offset = end;
      } }, { highWaterMark: 0 });
      const response = await f.fetch(`${path}///?keep=a%2Fb&flag=two+words`, { method: "POST", body,
        headers: { "Content-Type": contentType, Origin: ORIGIN, "CF-Connecting-IP": "198.51.100.7" } });
      equal(response.status, 202); equal(await response.text(), "offloaded");
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
      equal(response.headers.get("Vary"), "X-Heavy-Fixture", "successful DO responses retain their own CORS headers");
      equal(response.headers.get("X-Content-Type-Options"), "nosniff", "forwarded responses receive public defaults");
      equal(forwarded, 1);
    }
  });
  await check("the real HeavyDo uses the same CORS and response policy as local Axum", async () => {
    const f = fixture(ctx);
    const register = () => f.fetch("/api/accounts/register", {
      method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN },
      body: JSON.stringify({ email: "owner@example.test" }),
    });
    const local = await register();
    f.env.HEAVY_DO_ENABLED = "true";
    let forwarded = 0;
    f.env.HEAVY_DO = new DurableObjectNamespace(request => {
      forwarded++;
      return new HeavyDo(sqlState, f.env).fetch(request);
    });
    const offloaded = await register();
    equal(forwarded, 1);
    equal(offloaded.status, local.status);
    equal(await offloaded.text(), await local.text());
    for (const name of ["access-control-allow-origin", "cache-control", "content-security-policy", "x-content-type-options"]) {
      equal(offloaded.headers.get(name), local.headers.get(name), name);
    }
  });
  await check("lightweight grants and invalid or oversized shard input fall back to the same Axum response", async () => {
    const prefix = "grant_type=password&padding=";
    const cases = [
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=refresh_token"],
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=send_access"],
      ["/identity/connect/token", "application/x-www-form-urlencoded", "grant_type=password&auth_request=pending&username=owner%40example.test&password=opaque"],
      ["/api/accounts/register", "application/json", "{"],
      ["/identity/connect/token", "application/x-www-form-urlencoded", prefix + "x".repeat(65537 - prefix.length)],
      ["/identity/accounts/register/finish", "application/json", JSON.stringify({ email: "owner@example.test", padding: "x".repeat(65537) })],
    ];
    for (const [path, contentType, text] of cases) {
      const baseline = fixture(ctx);
      const expected = await baseline.fetch(path, { method: "POST", headers: { "Content-Type": contentType, Origin: ORIGIN }, body: text });
      const expectedBody = await expected.text();
      const f = fixture(ctx); f.env.HEAVY_DO_ENABLED = "true";
      let forwarded = 0;
      f.env.HEAVY_DO = new DurableObjectNamespace(() => { forwarded++; return new Response("unexpected offload", { status: 202 }); });
      const bytes = encoder.encode(text); let offset = 0;
      const body = new ReadableStream({ pull(controller) {
        if (offset === bytes.length) { controller.close(); return; }
        const end = Math.min(offset + 16384, bytes.length);
        controller.enqueue(bytes.subarray(offset, end)); offset = end;
      } }, { highWaterMark: 0 });
      const response = await f.fetch(`${path}///?keep=a%2Fb`, { method: "POST", headers: { "Content-Type": contentType, Origin: ORIGIN }, body });
      equal(forwarded, 0, `${path} should remain local`);
      equal(response.status, expected.status); equal(await response.text(), expectedBody, "fallback must preserve application validation");
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    }
  });
  await check("HeavyDo forwards file uploads before reading their stream", async () => {
    const f = fixture(ctx); f.env.HEAVY_DO_ENABLED = "true"; f.env.HEAVY_DO_SHARDS = "16";
    f.db.prepare = () => { throw new Error("offloaded upload touched D1 before forwarding"); };
    let pulls = 0, forwarded = 0;
    const bytes = encoder.encode("streamed-upload");
    const body = new ReadableStream({ pull(controller) { pulls++; controller.enqueue(bytes); controller.close(); } }, { highWaterMark: 0 });
    f.env.HEAVY_DO = new DurableObjectNamespace(async (request, name) => {
      forwarded++; equal(pulls, 0, "upload must reach the DO before any source bytes are pulled");
      equal(name, "heavy:8", "bearer subject selects the upload shard"); equal(request.method, "PUT");
      equal(new URL(request.url).pathname, `/api/ciphers/${CIPHER}/attachment/${FILE}/azure-upload`);
      equal(new URL(request.url).search, "?token=capability&keep=a%2Fb");
      sameBytes(new Uint8Array(await request.arrayBuffer()), bytes);
      return new Response(null, { status: 201 });
    });
    const bearer = `e30.${base64url(encoder.encode('{"sub":"alice"}'))}.unverified`;
    const response = await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}/azure-upload///?token=capability&keep=a%2Fb`,
      { method: "PUT", headers: { Authorization: `Bearer ${bearer}` }, body });
    equal(response.status, 201); equal(forwarded, 1); equal(pulls, 1);
  });
  await check("missing and malformed D1 bindings return a sanitized error with CORS", async () => {
    for (const binding of [undefined, {}]) {
      const f = fixture(ctx);
      f.env.DB = binding;
      const response = await f.fetch("/api/alive", { headers: { Origin: ORIGIN } });
      equal(response.status, 500);
      equal((await response.json()).message, "Internal server error");
      equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    }
    equal((await fixture(ctx).fetch("/api/alive")).status, 200);
  });
  await check("notification internal routes never reach a DO or database", async () => {
    const f = fixture(ctx);
    f.db.prepare = () => { throw new Error("notification dispatch touched D1"); };
    for (const path of ["/notifications/internal/fanout", "/notifications/unknown"]) equal((await f.fetch(path, { method: "POST" })).status, 404);
    equal((await f.fetch("/notifications/hub/negotiate", { method: "OPTIONS", headers: { Origin: ORIGIN } })).status, 204);
    equal((await f.fetch("/notifications/hub")).status, 503);
  });
  await check("notification WebSocket upgrades retain their native socket", async () => {
    const f = fixture(ctx); const pair = new WebSocketPair(); pair[1].accept();
    f.db.prepare = () => { throw new Error("notification dispatch touched D1"); };
    f.env.NOTIFY_DO = new DurableObjectNamespace(async (request, name) => {
      equal(name, "global"); equal(new URL(request.url).pathname, "/notifications/hub");
      return new Response(null, { status: 101, webSocket: pair[0] });
    });
    const response = await f.fetch("/notifications/hub///", { headers: { Upgrade: "websocket", Origin: ORIGIN } });
    equal(response.status, 101); equal(response.webSocket, pair[0], "upgraded socket identity");
    response.webSocket.accept(); response.webSocket.close(1000); pair[1].close(1000);
  });
  await check("signed attachment GET preserves bytes and native R2 stream", async () => {
    const f = fixture(ctx);
    const response = await f.fetch(attachmentPath("download", await attachmentToken()), { headers: { Origin: ORIGIN } });
    equal(response.status, 200);
    equal(response.headers.get("Content-Length"), "6");
    assertDownloadSecurityHeaders(response);
    equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    equal(response.body, f.bucket.lastBody, "native download stream identity");
    sameBytes(new Uint8Array(await response.arrayBuffer()), [0, 1, 2, 3, 128, 255]);
  });
  await check("attachment HEAD and Range contracts", async () => {
    const f = fixture(ctx);
    const path = attachmentPath("download", await attachmentToken());
    const head = await f.fetch(path, { method: "HEAD" });
    assertDownloadSecurityHeaders(head);
    equal(head.status, 200); equal(head.headers.get("Content-Length"), "6"); equal((await head.arrayBuffer()).byteLength, 0); equal(f.bucket.gets, 0, "HEAD avoids reading object bytes");
    for (const [range, expected, contentRange] of [["bytes=1-3", [1, 2, 3], "bytes 1-3/6"], ["bytes=-2", [128, 255], "bytes 4-5/6"]]) {
      const response = await f.fetch(path, { headers: { Range: range } });
      assertDownloadSecurityHeaders(response);
      equal(response.status, 206); equal(response.headers.get("Content-Range"), contentRange); sameBytes(new Uint8Array(await response.arrayBuffer()), expected);
    }
    const invalid = await f.fetch(path, { headers: { Range: "bytes=99-" } });
    assertDownloadSecurityHeaders(invalid);
    equal(invalid.status, 416); equal(invalid.headers.get("Content-Range"), "bytes */6");
    const full = await f.fetch(path, { headers: { Range: "bytes=1-3", "If-Range": '"different-etag"' } });
    equal(full.status, 200); assertDownloadSecurityHeaders(full); equal((await full.arrayBuffer()).byteLength, 6);
  });
  await check("attachment capabilities reject wrong signature, path, expiry and owner", async () => {
    for (const signed of [await attachmentToken({}, "wrong-secret"), await attachmentToken({ attachment_id: "other" }), await attachmentToken({ exp: 1 })]) {
      const f = fixture(ctx);
      equal((await f.fetch(attachmentPath("download", signed))).status, 401); equal(f.bucket.gets, 0);
    }
    const f = fixture(ctx); f.db.cipher.user_id = "other-owner";
    equal((await f.fetch(attachmentPath("download", await attachmentToken()))).status, 404);
  });
  await check("Azure attachment PUT streams and atomically publishes metadata", async () => {
    const f = attachmentUploadFixture(ctx);
    const response = await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6), headers: { Origin: ORIGIN } });
    equal(response.status, 201, await response.clone().text()); equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    sameBytes(f.bucket.objects.get(f.db.attachment.storage_key), [0, 1, 2, 3, 4, 5]); equal(f.db.pending, null); equal(f.db.batches, 1);
  });
  await check("attachment uploads publish the committed revision for both authorization paths", async () => {
    for (const useCapability of [true, false]) {
      const f = attachmentUploadFixture(ctx);
      const future = "2099-01-01T00:00:00.000Z";
      sqlState.storage.sql.exec("UPDATE users SET updated_at=? WHERE id=?", future, USER);
      const messages = [];
      f.env.NOTIFY_DO = new DurableObjectNamespace(async request => {
        messages.push(await request.json());
        return new Response('{"sent":1}');
      });
      let response;
      if (useCapability) {
        response = await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) });
      } else {
        const form = new FormData();
        form.append("data", new Blob(["sample"]), "encrypted-name");
        response = await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, {
          method: "POST", body: form, headers: { Authorization: `Bearer ${await accessToken()}` },
        });
      }
      equal(response.status, useCapability ? 201 : 200, await response.text());
      equal(messages.length, 1);
      equal(messages[0].selector.user_id, USER);
      const stored = f.db.row("users", USER).updated_at;
      ok(Date.parse(stored) > Date.parse(future), "upload did not advance the cursor");

      // MessagePack fixstr "RevisionDate", then the 64-bit timestamp extension.
      const frame = atob(messages[0].message);
      const marker = String.fromCharCode(0xac) + "RevisionDate" + String.fromCharCode(0xd7, 0xff);
      const index = frame.indexOf(marker);
      ok(index >= 0, "notification is missing the revision timestamp");
      const data = Uint8Array.from(frame.slice(index + marker.length, index + marker.length + 8), char => char.charCodeAt(0));
      const millis = Date.parse(stored);
      const timestamp = (BigInt(millis % 1000) * 1_000_000n << 34n) | BigInt(Math.floor(millis / 1000));
      equal(new DataView(data.buffer).getBigUint64(0), timestamp);
    }
  });
  await check("attachment publication failure cleans bytes and keeps pending reservation", async () => {
    const f = attachmentUploadFixture(ctx); f.db.failBatch = true;
    equal((await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) })).status, 500);
    equal(f.bucket.objects.has(ATTACHMENT_KEY), false); ok(f.bucket.deleted.some(key => key.startsWith(`attachments/${CIPHER}/${FILE}/`)), "failed staged object was not deleted"); ok(f.db.pending, "pending metadata was removed on failure");
  });
  await check("R2 multipart accepts a streamed file beyond Axum's default body limit", async () => {
    const f = attachmentUploadFixture(ctx); const size = 8 * 1024 * 1024 + 257; f.db.pending.file_size_bytes = size;
    equal((await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(size), headers: { "Content-Type": "text/html" } })).status, 201);
    equal(f.bucket.created, 1); equal(f.bucket.completed, 1); equal(f.bucket.parts.join(","), `${8 * 1024 * 1024},257`);
    const bytes = f.bucket.objects.get(f.db.attachment.storage_key); equal(bytes.length, size);
    equal(f.bucket.httpMetadata.get(f.db.attachment.storage_key).contentType, "text/html", "multipart SDK metadata is represented by the fixture");
    for (let i = 0; i < bytes.length; i++) if (bytes[i] !== i % 251) throw new Error(`multipart byte order changed at ${i}`);
    const response = await f.fetch(attachmentPath("download", await attachmentToken()));
    assertDownloadSecurityHeaders(response); equal(response.body, f.bucket.lastBody, "multipart download keeps its native stream");
    sameBytes(new Uint8Array(await response.arrayBuffer()), bytes);
  });
  await check("interrupted multipart aborts the upload and removes incomplete bytes", async () => {
    const f = attachmentUploadFixture(ctx); f.db.pending.file_size_bytes = 10 * 1024 * 1024;
    equal((await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(8 * 1024 * 1024 + 131072, true) })).status, 400);
    equal(f.bucket.created, 1); equal(f.bucket.aborted, 1); equal(f.bucket.uploads.size, 0); equal(f.bucket.objects.has(ATTACHMENT_KEY), false); ok(f.db.pending, "pending reservation was not preserved");
  });
  await check("failed R2 multipart completion aborts the original handle", async () => {
    const f = attachmentUploadFixture(ctx);
    const size = 8 * 1024 * 1024 + 257;
    f.db.pending.file_size_bytes = size;
    const resume = f.bucket.resumeMultipartUpload.bind(f.bucket);
    f.bucket.resumeMultipartUpload = (key, id) => ({
      ...resume(key, id),
      async complete() { throw new Error("R2 completion failed"); },
    });

    const response = await f.fetch(attachmentPath("azure-upload", await attachmentToken()), {
      method: "PUT",
      body: byteStream(size),
    });
    equal(response.status, 500);
    equal(f.bucket.created, 1);
    equal(f.bucket.aborted, 1);
    equal(f.bucket.uploads.size, 0);
    equal(f.db.batches, 0);
    ok(f.db.pending, "pending reservation was not preserved");
  });
  await check("Send GET, HEAD and Range use the compiled Rust routes", async () => {
    const f = fixture(ctx); const path = `/api/sends/${SEND}/${FILE}?t=${await sendToken()}`;
    const disposition = 'attachment; filename="send-file"';
    const head = await f.fetch(path, { method: "HEAD" }); equal(head.status, 200); assertDownloadSecurityHeaders(head, disposition); equal(head.headers.get("Content-Length"), "6"); equal((await head.arrayBuffer()).byteLength, 0);
    const response = await f.fetch(path, { headers: { Range: "bytes=2-4" } }); equal(response.status, 206); assertDownloadSecurityHeaders(response, disposition); sameBytes(new Uint8Array(await response.arrayBuffer()), [2, 3, 128]);
  });
  await check("disabled, pending and rotated Sends revoke outstanding download capabilities", async () => {
    for (const patch of [{ is_disabled: 1 }, { upload_state: 1 }, { access_stamp: "rotated" }, { deletes_at: NOW }]) {
      const f = fixture(ctx); Object.assign(f.db.send, patch);
      equal((await f.fetch(`/api/sends/${SEND}/${FILE}?t=${await sendToken()}`)).status, 404); equal(f.bucket.gets, 0);
    }
  });
  await check("Send Azure upload validates the session and finalizes metadata once", async () => {
    const f = fixture(ctx); f.db.send.upload_state = 1;
    equal((await f.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(6) })).status, 201);
    equal(f.db.send.upload_state, 0); sameBytes(f.bucket.objects.get(f.db.send.storage_key), [0, 1, 2, 3, 4, 5]); equal(f.db.batches, 1);
  });
  await check("revoked Send upload session rejects before reserving or storing bytes", async () => {
    const f = fixture(ctx); f.db.send.upload_state = 1; f.db.sessionValid = false;
    equal((await f.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(6) })).status, 401);
    equal(f.db.claims, 0); equal(f.db.send.upload_state, 1);
  });
  await check("session revocation during Send upload prevents publication and cleans the object", async () => {
    const f = fixture(ctx); f.db.send.upload_state = 1; f.bucket.afterPut = () => { f.db.sessionValid = false; };
    equal((await f.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(6) })).status, 401);
    equal(f.db.send.upload_state, 1); sameBytes(f.bucket.objects.get(SEND_KEY), [0, 1, 2, 3, 128, 255]); ok(f.bucket.deleted.some(key => key.startsWith(`${SEND_KEY}/`)), "revoked staged upload was not cleaned");
  });
  await check("short Send upload cleans the object and unlocks its reservation for retry", async () => {
    const f = fixture(ctx); f.db.send.upload_state = 1;
    equal((await f.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(5) })).status, 400);
    equal(f.db.send.upload_state, 1); sameBytes(f.bucket.objects.get(SEND_KEY), [0, 1, 2, 3, 128, 255]); ok(f.bucket.deleted.some(key => key.startsWith(`${SEND_KEY}/`)), "failed Send staged object was not cleaned");
  });
  await check("Axum Multipart accepts a Send file above 2MiB and rejects trailing fields before publication", async () => {
    const size = 3 * 1024 * 1024 + 17;
    for (const extra of [false, true]) {
      const f = fixture(ctx); f.db.send.upload_state = 1; f.db.send.file_size_bytes = size;
      const form = new FormData();
      form.append("data", new Blob([new Uint8Array(size).fill(173)]), "encrypted");
      if (extra) form.append("extra", "unexpected-field");
      const response = await f.fetch(`/api/sends/${SEND}/file/${FILE}`, { method: "POST", body: form, headers: { Authorization: `Bearer ${await accessToken()}` } });
      equal(response.status, extra ? 400 : 201);
      equal(f.db.send.upload_state, extra ? 1 : 0);
      equal(f.db.batches, extra ? 0 : 1, "metadata must stay unpublished until MIME validation completes");
      if (extra) {
        sameBytes(f.bucket.objects.get(SEND_KEY), [0, 1, 2, 3, 128, 255]); ok(f.bucket.deleted.some(key => key.startsWith(`${SEND_KEY}/`)), "malformed staged multipart object was not cleaned");
      } else {
        const bytes = f.bucket.objects.get(f.db.send.storage_key); equal(bytes.length, size);
        for (const byte of bytes) if (byte !== 173) throw new Error("multipart file bytes changed");
      }
    }
  });
  await check("KV historical raw bytes without metadata retain signed GET, HEAD and Range support", async () => {
    const f = kvFixture(ctx);
    const bytes = new Uint8Array([0, 255, 13, 10, 128, 195]);
    f.kv.objects.set(ATTACHMENT_KEY, { value: bytes.buffer, metadata: null });
    const path = attachmentPath("download", await attachmentToken());
    const full = await f.fetch(path); equal(full.status, 200); assertDownloadSecurityHeaders(full); sameBytes(new Uint8Array(await full.arrayBuffer()), bytes);
    equal(f.kv.gets, 1, "GET reads KV bytes once");
    const head = await f.fetch(path, { method: "HEAD" }); equal(head.status, 200); assertDownloadSecurityHeaders(head); equal(head.headers.get("Content-Length"), "6"); equal((await head.arrayBuffer()).byteLength, 0);
    equal(f.kv.gets, 2, "HEAD reuses its single KV read for metadata");
    const range = await f.fetch(path, { headers: { Range: "bytes=1-3" } }); equal(range.status, 206); assertDownloadSecurityHeaders(range); equal(range.headers.get("Content-Range"), "bytes 1-3/6"); sameBytes(new Uint8Array(await range.arrayBuffer()), [255, 13, 10]);
    equal(f.kv.gets, 3, "Range slices its single KV read");
    const invalid = await f.fetch(path, { headers: { Range: "bytes=99-" } }); equal(invalid.status, 416); assertDownloadSecurityHeaders(invalid); equal(invalid.headers.get("Content-Range"), "bytes */6"); equal((await invalid.arrayBuffer()).byteLength, 0);
    equal(f.kv.gets, 4, "416 derives the object size from one KV read");
    equal(f.kv.puts, 0);
  });
  await check("KV upload stores raw bytes and compatible content-type metadata", async () => {
    const f = kvFixture(ctx, true); const signed = await attachmentToken();
    equal((await f.fetch(attachmentPath("azure-upload", signed), { method: "PUT", body: byteStream(6), headers: { "Content-Type": "application/x-encrypted" } })).status, 201);
    const object = f.kv.objects.get(f.db.attachment.storage_key); sameBytes(new Uint8Array(object.value), [0, 1, 2, 3, 4, 5]); equal(object.metadata.size, 6); equal(object.metadata.httpMetadata.contentType, "application/x-encrypted");
    const response = await f.fetch(attachmentPath("download", signed)); equal(response.status, 200); assertDownloadSecurityHeaders(response); sameBytes(new Uint8Array(await response.arrayBuffer()), [0, 1, 2, 3, 4, 5]);
  });
  await check("R2 and KV historical document MIME metadata cannot make attachments or Sends executable", async () => {
    const bytes = encoder.encode("<html>harmless historical file</html>");
    for (const backend of ["R2", "KV"]) {
      for (const kind of ["attachment", "send"]) {
        const f = backend === "KV" ? kvFixture(ctx) : fixture(ctx);
        const key = kind === "attachment" ? ATTACHMENT_KEY : SEND_KEY;
        if (backend === "KV") f.kv.objects.set(key, { value: bytes.buffer, metadata: { size: bytes.length, httpMetadata: { contentType: "text/html; charset=utf-8" } } });
        else { f.bucket.objects.set(key, bytes); f.bucket.httpMetadata.set(key, { contentType: "text/html; charset=utf-8" }); }
        const path = kind === "attachment" ? attachmentPath("download", await attachmentToken()) : `/api/sends/${SEND}/${FILE}?t=${await sendToken()}`;
        await inertDownload(f, path, bytes, kind === "send" ? 'attachment; filename="send-file"' : "attachment");
        const stored = backend === "KV" ? f.kv.objects.get(key) : f.bucket.objects.get(key);
        sameBytes(backend === "KV" ? new Uint8Array(stored.value) : stored, bytes);
        if (backend === "KV") equal(f.kv.puts, 0, "legacy downloads never rewrite KV");
        else equal(f.bucket.created, 0, "legacy downloads never rewrite R2");
      }
    }
  });
  await check("new R2 and KV document MIME uploads remain byte-exact inert attachment and Send downloads", async () => {
    const bytes = encoder.encode("<html>harmless uploaded file</html>");
    for (const backend of ["R2", "KV"]) {
      for (const kind of ["attachment", "send"]) {
        const f = backend === "KV" ? kvFixture(ctx, kind === "attachment") : kind === "attachment" ? attachmentUploadFixture(ctx) : fixture(ctx);
        if (kind === "attachment") f.db.pending.file_size_bytes = bytes.length;
        else { f.db.send.upload_state = 1; f.db.send.file_size_bytes = bytes.length; }
        const upload = kind === "attachment" ? attachmentPath("azure-upload", await attachmentToken()) : `/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`;
        equal((await f.fetch(upload, { method: "PUT", headers: { "Content-Type": "text/html; charset=utf-8" }, body: bytes })).status, 201, `${backend} ${kind} upload`);
        const key = kind === "attachment" ? f.db.attachment.storage_key : f.db.send.storage_key;
        const stored = backend === "KV" ? f.kv.objects.get(key) : f.bucket.objects.get(key);
        sameBytes(backend === "KV" ? new Uint8Array(stored.value) : stored, bytes);
        const metadata = backend === "KV" ? stored.metadata.httpMetadata : f.bucket.httpMetadata.get(key);
        equal(metadata.contentType, kind === "attachment" ? "text/html; charset=utf-8" : "application/octet-stream", `${backend} ${kind} upload metadata`);
        const path = kind === "attachment" ? attachmentPath("download", await attachmentToken()) : `/api/sends/${SEND}/${FILE}?t=${await sendToken()}`;
        await inertDownload(f, path, bytes, kind === "send" ? 'attachment; filename="send-file"' : "attachment");
      }
    }
  });
  await check("the actual 25MiB KV boundary rejects the first excess stream byte before KV.put", async () => {
    const f = kvFixture(ctx, true); const maximum = 25 * 1024 * 1024; f.db.pending.file_size_bytes = maximum;
    const response = await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(maximum + 1) });
    equal(response.status, 400); equal(f.kv.puts, 0); equal(f.kv.objects.has(ATTACHMENT_KEY), false); equal(f.db.batches, 0); ok(f.db.pending, "oversized upload removed its pending reservation");
  });
  await runVaultCompatibility(ctx, check);
  const suiteContext = { fixture: (options) => fixture(ctx, options), check, accessToken, USER, CIPHER, FILE, SEND, NOW, sql: sqlState.storage.sql,
    notificationFetch: (f, request) => new NotifyDo(sqlState, f.env).fetch(request) };
  await runAccountCompatibility(suiteContext);
  await runSendCompatibility(suiteContext);
  await runTwoFactorCompatibility(suiteContext);
  await runJwtCompatibility(suiteContext);
  await runConfigurationCompatibility(suiteContext);
  await runPresentationCompatibility(suiteContext);
  await runAdminNotificationCompatibility(suiteContext);
  await runSetupCompatibility(suiteContext);
  await runPasswordCompatibility(suiteContext);
  await runPreloginCompatibility(suiteContext);
  await runRecoveryCompatibility(suiteContext);
  await runSetPasswordCompatibility(suiteContext);
  await runAuthSessionChecks(suiteContext);
  await runSendParityCompatibility(suiteContext);
  await runRouteParityCompatibility(suiteContext);
  await runAccountSettingsChecks(suiteContext);
  await runProtectedActionCompatibility(suiteContext);
  await runPersonalVaultCompatibility(suiteContext);
  await runSecurityHeadersCompatibility(suiteContext);
  await runRateLimitChecks(suiteContext);
  console.log(`Compiled Rust Worker runtime: ${passed} checks passed`);
  if (failed.length) throw new Error(`${failed.length} runtime checks failed: ${failed.map(failure => failure.name).join("; ")}`);
}

async function runVaultCompatibility(ctx, check) {
  const sql = sqlState.storage.sql;
  const headers = async () => ({ Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" });
  const payload = (extra = {}) => ({ type: 1, name: "encrypted", login: {}, key: "wrapped-item-key", favorite: false, ...extra });
  async function expect(response, status) {
    const body = await response.text();
    equal(response.status, status, body);
    return body ? JSON.parse(body) : null;
  }
  const save = async (f, body, id) => expect(await f.fetch(id ? `/api/ciphers/${id}` : "/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 200);

  await check("profile and domain POST/PUT aliases persist settings and require a session", async () => {
    for (const method of ["POST", "PUT"]) {
      const f = fixture(ctx);
      const request = async (path, body, authorized = true) => f.fetch(path, {
        method, headers: authorized ? await headers() : { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const profile = await expect(await request("/api/accounts/profile", { name: method }), 200);
      equal(profile.name, method);
      equal(sql.exec("SELECT name FROM users WHERE id=?", USER).one().name, method);
      await expect(await request("/api/accounts/profile", { name: "x".repeat(51) }), 400);
      await expect(await request("/api/accounts/profile", { name: "unauthorized" }, false), 401);
      equal(sql.exec("SELECT name FROM users WHERE id=?", USER).one().name, method);
      const domains = { equivalentDomains: [["example.test", "example.org"]], excludedGlobalEquivalentDomains: [1] };
      await expect(await request("/api/settings/domains", domains), 200);
      await expect(await request("/api/settings/domains", {}, false), 401);
      const stored = sql.exec("SELECT equivalent_domains,excluded_globals FROM users WHERE id=?", USER).one();
      equal(stored.equivalent_domains, JSON.stringify(domains.equivalentDomains));
      equal(stored.excluded_globals, "[1]");
    }
  });
  await check("profile and avatar writes advance a sync revision ahead of the Worker clock", async () => {
    const f = fixture(ctx);
    let revision = "2099-01-01T00:00:00.000Z";
    sql.exec("UPDATE users SET updated_at=? WHERE id=?", revision, USER);
    for (const [path, body] of [
      ["/api/accounts/profile", { name: "Profile" }],
      ["/api/accounts/avatar", { avatarColor: "#abcdef" }],
    ]) {
      await expect(await f.fetch(path, { method: "PUT", headers: await headers(), body: JSON.stringify(body) }), 200);
      const updated = f.db.row("users", USER).updated_at;
      equal(Date.parse(updated), Date.parse(revision) + 1);
      revision = updated;
    }
  });
  await check("device token aliases retain current-device authorization and clear stored tokens", async () => {
    for (const method of ["POST", "PUT"]) {
      const f = fixture(ctx);
      const request = async (id, action, body) => f.fetch(`/api/devices/identifier/${id}/${action}`, {
        method, headers: await headers(), ...(body ? { body: JSON.stringify(body) } : {}),
      });
      await expect(await request("device", "token", { pushToken: " test-push-token " }), 200);
      await expect(await request("other-device", "token", { pushToken: "foreign" }), 400);
      equal(sql.exec("SELECT push_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().push_token, "test-push-token");
      await expect(await request("other-device", "clear-token"), 400);
      await expect(await request("device", "clear-token"), 200);
      equal(sql.exec("SELECT push_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().push_token, null);
    }
  });
  await check("attachment delete aliases retain ownership checks and remove adopted objects", async () => {
    for (const method of ["POST", "DELETE"]) {
      const f = fixture(ctx);
      const path = `/api/ciphers/${CIPHER}/attachment/${FILE}${method === "POST" ? "/delete" : ""}`;
      const foreign = await accessToken({ sub: "other-owner", sstamp: "other" });
      sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('other-owner','device','other',0,'session',?,?)", NOW, NOW);
      // The existing attachment ownership lookup reports a missing/foreign cipher as 500.
      await expect(await f.fetch(path, { method, headers: { Authorization: `Bearer ${foreign}` } }), 500);
      ok(f.bucket.objects.has(ATTACHMENT_KEY), "unauthorized delete removed the object");
      await expect(await f.fetch(path, { method, headers: await headers() }), 200);
      equal(sql.exec("SELECT count(*) AS n FROM attachments WHERE id=?", FILE).one().n, 0);
      equal(f.bucket.objects.has(ATTACHMENT_KEY), false);
    }
    const f = fixture(ctx);
    for (const path of ["trusted", "granted"]) {
      const body = await expect(await f.fetch(`/api/emergency-access/${path}`), 200);
      equal(body.object, "list"); equal(body.data.length, 0);
    }
  });

  await check("failed object deletion retains cleanup jobs and a later operation retries them", async () => {
    const f = fixture(ctx); f.db.pending = null;
    sql.exec("DELETE FROM storage_cleanup_jobs");
    const removeObjects = f.bucket.delete.bind(f.bucket);
    let failed = false;
    f.bucket.delete = async () => { failed = true; throw new Error("simulated R2 deletion outage"); };
    await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { method: "DELETE", headers: await headers() }), 200);
    ok(failed, "attachment deletion did not reach the failing storage backend");
    equal(f.db.attachment, null, "metadata deletion should remain committed");
    sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
    equal(sql.exec("SELECT object_key FROM storage_cleanup_jobs").one().object_key, ATTACHMENT_KEY, "failed deletion must remain queued");

    const second = "00000000-0000-4000-8000-000000000005", secondKey = `${CIPHER}/${second}`;
    sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at) VALUES(?,?,'second-file',3,'encrypted-key',?,?)", second, CIPHER, NOW, NOW);
    f.bucket.objects.set(secondKey, new Uint8Array([10, 20, 30]));
    f.bucket.delete = removeObjects;
    await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${second}`, { method: "DELETE", headers: await headers() }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM attachments WHERE cipher_id=?", CIPHER).one().n, 0);
    equal(f.bucket.objects.has(ATTACHMENT_KEY), false, "retry must remove the first object's retained bytes");
    equal(f.bucket.objects.has(secondKey), false);
    equal(sql.exec("SELECT COUNT(*) AS n FROM storage_cleanup_jobs").one().n, 0, "only successful storage deletion acknowledges jobs");
    ok(f.bucket.objects.has(SEND_KEY), "unrelated adopted storage must remain intact");
  });

  await check("single and bulk archive share guarded writes and reject foreign selections atomically", async () => {
    const f = fixture(ctx), foreign = "00000000-0000-4000-8000-000000000088";
    const second = await save(f, payload({ name: "second-own-item" }));
    sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,'other-owner',1,'{}',?,?)", foreign, NOW, NOW);
    const put = async (path, body) => f.fetch(path, { method: "PUT", headers: await headers(), ...(body ? { body: JSON.stringify(body) } : {}) });
    await expect(await put(`/api/ciphers/${CIPHER}/archive`), 200);
    ok(sql.exec("SELECT archived_at FROM ciphers WHERE id=?", CIPHER).one().archived_at, "single archive did not persist");
    await expect(await put("/api/ciphers/archive", { ids: [CIPHER, second.id] }), 200);
    equal(sql.exec("SELECT count(*) AS n FROM ciphers WHERE user_id=? AND archived_at IS NOT NULL", USER).one().n, 2);
    await expect(await put("/api/ciphers/unarchive", { ids: [CIPHER, second.id] }), 200);
    const before = JSON.stringify(sql.exec("SELECT * FROM ciphers ORDER BY id").toArray());
    const revision = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
    await expect(await put(`/api/ciphers/${foreign}/archive`), 400);
    await expect(await put("/api/ciphers/archive", { ids: [CIPHER, foreign] }), 400);
    equal(JSON.stringify(sql.exec("SELECT * FROM ciphers ORDER BY id").toArray()), before);
    equal(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at, revision);
  });

  await check("new cipher types, false favorite and empty folder IDs survive create and list", async () => {
    const f = fixture(ctx);
    for (const [type, field] of [[6, "bankAccount"], [7, "driversLicense"], [8, "passport"]]) {
      const body = await save(f, { type, name: "encrypted", key: "wrapped", favorite: false, folderId: "", [field]: { encrypted: "opaque", response: { transient: true } } });
      equal(body.type, type); equal(body.favorite, false); equal(body.folderId, null); equal(body[field].encrypted, "opaque"); equal(body[field].response, undefined);
    }
    const list = await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    equal(list.data.length, 4);
    for (const item of list.data) { equal(item.__storedData, undefined); equal(item.userId, undefined); ok(Array.isArray(item.collectionIds), "private collectionIds must be an array"); }
  });
  await check("sealed cipher blobs round-trip identically through create, GET, list and sync", async () => {
    const f = fixture(ctx); const blob = '{ "format_version": 2, "data": "opaque encrypted bytes" }';
    const created = await save(f, { type: 8, data: blob, name: "ignored", passport: { number: "ignored" }, key: "wrapped", reprompt: 1 });
    const detail = await expect(await f.fetch(`/api/ciphers/${created.id}`, { headers: await headers() }), 200);
    const list = await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    const sync = await expect(await f.fetch("/api/sync?excludeDomains=true", { headers: await headers() }), 200);
    for (const item of [created, detail, list.data.find(c => c.id === created.id), sync.ciphers.find(c => c.id === created.id)]) {
      equal(item.data, blob); equal(item.name, null); equal(item.passport, null); equal(item.key, "wrapped"); equal(item.reprompt, 1); equal(item.__storedData, undefined);
    }
    const stored = sql.exec("SELECT data FROM ciphers WHERE id=?", created.id).one().data;
    ok(!stored.includes("ignored"), "sealed writes persisted ignored structured fields");
  });
  await check("sync rejects account, vault revision and session changes after its first read", async () => {
    for (const [column, value, status] of [
      ["key", "2.rewrapped", 409],
      ["updated_at", "2026-01-01T00:00:00.001Z", 409],
      ["session_token", "revoked", 401],
    ]) {
      const f = fixture(ctx);
      const execute = f.db.execute.bind(f.db);
      let changed = false;
      f.db.execute = (query, params) => {
        const result = execute(query, params);
        if (!changed && query === "SELECT * FROM users WHERE id = ?1") {
          changed = true;
          if (column === "session_token") f.db.sessionValid = false;
          else f.db.row("users", USER)[column] = value;
        }
        return result;
      };
      await expect(await f.fetch("/api/sync?excludeDomains=true", { headers: await headers() }), status);
      ok(changed, "fixture did not change data after the snapshot read");
    }
  });
  await check("multiple sealed blobs above 2MB total remain readable as individual SQL rows", async () => {
    const f = fixture(ctx); const blob = JSON.stringify({ format_version: 2, data: "x".repeat(450000) });
    for (let i = 0; i < 5; i++) sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,?,8,?,?,?)", `large-${i}`, USER, JSON.stringify({ name: "", data: blob }), NOW, NOW);
    const response = await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    const large = response.data.filter(item => item.id.startsWith("large-")); equal(large.length, 5);
    for (const item of large) equal(item.data, blob);
  });
  await check("unreadable stored cipher JSON fails GET and list without fabricating empty items", async () => {
    const f = fixture(ctx); f.db.cipher.data = "{unreadable";
    await expect(await f.fetch(`/api/ciphers/${CIPHER}`, { headers: await headers() }), 500);
    await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 500);
  });
  await check("move and soft delete do not decode stored cipher payloads", async () => {
    for (const bulk of [false, true]) {
      const f = fixture(ctx);
      f.db.cipher.data = "{unreadable";
      if (bulk) {
        const folder = "target-folder";
        sql.exec("INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES(?,?,?,?,?)", folder, USER, "encrypted", NOW, NOW);
        const moved = await f.fetch("/api/ciphers/move", {
          method: "PUT", headers: await headers(), body: JSON.stringify({ ids: [CIPHER], folderId: folder }),
        });
        equal(await expect(moved, 200), null);
        equal(f.db.cipher.folder_id, folder);
      }
      const deleted = await f.fetch(bulk ? "/api/ciphers/delete" : `/api/ciphers/${CIPHER}/delete`, {
        method: "PUT", headers: await headers(),
        ...(bulk ? { body: JSON.stringify({ ids: [CIPHER] }) } : {}),
      });
      equal(await expect(deleted, 200), null);
      ok(f.db.cipher.deleted_at, "soft delete did not move the cipher to trash");
      equal(f.db.cipher.data, "{unreadable");
    }
  });
  await check("single and bulk hard delete remove unreadable ciphers after checking ownership", async () => {
    for (const bulk of [false, true]) {
      const f = fixture(ctx);
      const other = "other-cipher";
      f.db.setRow("ciphers", other, { ...f.db.cipher, id: other, user_id: "other-owner" });
      f.db.cipher.data = "{unreadable";
      const auth = await headers();
      const remove = (id, ids) => f.fetch(ids ? "/api/ciphers" : `/api/ciphers/${id}`, {
        method: "DELETE", headers: auth,
        ...(ids ? { body: JSON.stringify({ ids }) } : {}),
      });
      await expect(await remove(other, bulk ? [CIPHER, other] : null), 400);
      ok(f.db.cipher, "rejected selection removed the owned cipher");
      equal(await expect(await remove(CIPHER, bulk ? [CIPHER] : null), 200), null);
      equal(f.db.cipher, null);
      ok(f.db.row("ciphers", other), "hard delete removed another owner's cipher");
      ok(f.bucket.deleted.includes(ATTACHMENT_KEY), "hard delete did not remove the attachment");
    }
  });
  await check("cipher encryption contexts reject other users and stale IDs while preserving legacy matching IDs", async () => {
    const f = fixture(ctx); const current = "0123456789abcdef0123456789abcdef";
    sql.exec("UPDATE users SET user_key_id=? WHERE id=?", current, USER);
    await save(f, payload({ encryptedFor: USER, encryptedByKeyId: current }));
    await expect(await f.fetch("/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(payload({ encryptedByKeyId: "ffffffffffffffffffffffffffffffff" })) }), 409);
    await expect(await f.fetch("/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(payload({ encryptedFor: "other-owner" })) }), 400);
    const legacy = "00000000-0000-4000-8000-000000000099";
    sql.exec("UPDATE users SET user_key_id=? WHERE id=?", legacy, USER);
    await save(f, payload({ encryptedByKeyId: legacy }));
    await expect(await f.fetch("/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(payload({ collectionIds: ["unsupported"] })) }), 400);
  });
  await check("cipher save and import reuse one account snapshot and guard it at commit", async () => {
    for (const importing of [false, true]) {
      const f = fixture(ctx);
      const keyId = "0123456789abcdef0123456789abcdef";
      sql.exec("UPDATE users SET user_key_id=? WHERE id=?", keyId, USER);
      const before = f.db.cipher.data;
      const batch = f.db.batch.bind(f.db);
      let changed = false;
      f.db.batch = async statements => {
        if (!changed && statements.some(statement => statement.sql.startsWith("UPDATE users SET updated_at"))) {
          sql.exec("UPDATE users SET user_key_id=? WHERE id=?", "ffffffffffffffffffffffffffffffff", USER);
          changed = true;
        }
        return batch(statements);
      };
      const cipher = payload({ encryptedByKeyId: keyId, name: "blocked-by-account-change" });
      const response = await f.fetch(importing ? "/api/ciphers/import" : `/api/ciphers/${CIPHER}`, {
        method: "POST", headers: await headers(),
        body: JSON.stringify(importing ? { folders: [], ciphers: [cipher] } : cipher),
      });
      await expect(response, 400);
      ok(changed, "test did not reach the commit after validating the key ID");
      equal(f.db.queries.filter(query => query.startsWith("SELECT key,user_key_id,")).length, 1);
      ok(!f.db.queries.some(query => query.startsWith("SELECT user_key_id FROM users")), "key ID was fetched again");
      equal(f.db.cipher.data, before);
      equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 1);
    }
  });
  await check("same-revision concurrent cipher edits have one transaction winner", async () => {
    const f = fixture(ctx); const batch = f.db.batch.bind(f.db);
    let entered = 0, release; const ready = new Promise(resolve => { release = resolve; });
    f.db.batch = async statements => {
      if (statements.some(s => /^UPDATE ciphers SET cipher_type=/.test(s.sql))) { if (++entered === 1) await ready; else release(); }
      return batch(statements);
    };
    const auth = await headers();
    const responses = await Promise.all(["first", "second"].map(name => f.fetch(`/api/ciphers/${CIPHER}`, { method: "POST", headers: auth, body: JSON.stringify(payload({ name })) })));
    equal(responses.map(r => r.status).sort().join(","), "200,400");
    const winner = await responses.find(r => r.status === 200).json();
    equal(JSON.parse(f.db.cipher.data).name, winner.name);
  });
  await check("a rejected user sync cursor rolls the entire real cipher edit back", async () => {
    const f = fixture(ctx); const before = f.db.cipher.data;
    sql.exec("CREATE TRIGGER reject_vault_cursor BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT,'runtime cursor failure'); END");
    await expect(await f.fetch(`/api/ciphers/${CIPHER}`, { method: "POST", headers: await headers(), body: JSON.stringify(payload({ name: "must-rollback" })) }), 500);
    equal(f.db.cipher.data, before);
  });
  await check("attachments2 changes are atomic and response metadata matches the saved keys", async () => {
    const f = fixture(ctx);
    const response = await save(f, payload({ attachments2: { [FILE]: { fileName: "new-encrypted-name", key: "new-wrapped-key" }, missing: { fileName: "gone", key: "gone" } } }), CIPHER);
    equal(f.db.attachment.file_name, "new-encrypted-name"); equal(f.db.attachment.encrypted_key, "new-wrapped-key");
    equal(response.attachments[0].fileName, "new-encrypted-name"); equal(response.attachments[0].key, "new-wrapped-key");
    equal(response.attachments[0].url, `https://vault.test/attachments/${CIPHER}/${FILE}`);
  });
  await check("attachments2 continues after a same-owner attachment on a different cipher", async () => {
    const f = fixture(ctx);
    const secondFile = "second-file", otherCipher = "other-owned-cipher";
    f.db.setRow("ciphers", otherCipher, { ...f.db.cipher, id: otherCipher });
    f.db.setRow("attachments", secondFile, { ...f.db.attachment, id: secondFile });
    const execute = f.db.execute.bind(f.db);
    let ignored;
    f.db.execute = (query, params) => {
      if (!ignored && query.startsWith("SELECT a.* FROM attachments a JOIN ciphers c")) {
        // The first lookup is for a different cipher regardless of map iteration order.
        ignored = params[0];
        sql.exec("UPDATE attachments SET cipher_id=? WHERE id=?", otherCipher, ignored);
      }
      return execute(query, params);
    };
    const update = { fileName: "new-encrypted-name", key: "new-wrapped-key" };
    const response = await save(f, payload({ attachments2: { [FILE]: update, [secondFile]: update } }), CIPHER);
    ok(ignored, "no attachment was attached to the other cipher");
    const updated = ignored === FILE ? secondFile : FILE;
    equal(f.db.row("attachments", ignored).encrypted_key, "encrypted-key");
    equal(f.db.row("attachments", updated).file_name, update.fileName);
    equal(f.db.row("attachments", updated).encrypted_key, update.key);
    equal(response.attachments.length, 1);
    equal(response.attachments[0].id, updated);
    equal(response.attachments[0].key, update.key);
  });
  await check("attachment lists have stable URLs and authenticated metadata mints a 60-second download capability", async () => {
    const f = fixture(ctx);
    f.env.DOMAIN = " vault.test ";
    const expected = `https://vault.test/attachments/${CIPHER}/${FILE}`;
    const cipher = await expect(await f.fetch(`/api/ciphers/${CIPHER}`, { headers: await headers() }), 200);
    const list = await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    const sync = await expect(await f.fetch("/api/sync?excludeDomains=true", { headers: await headers() }), 200);
    for (const item of [cipher, list.data.find(item => item.id === CIPHER), sync.ciphers.find(item => item.id === CIPHER)]) {
      equal(item.attachments[0].url, expected);
    }
    const metadata = await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { headers: await headers() }), 200);
    const url = new URL(metadata.url); const signed = url.searchParams.get("token"); ok(signed, "metadata did not mint a capability");
    equal(url.origin + url.pathname, expected);
    const segment = signed.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
    const claims = JSON.parse(atob(segment)); const now = Math.floor(Date.now() / 1000);
    ok(claims.exp >= now + 55 && claims.exp <= now + 60, "attachment TTL is not one minute");
    const download = await f.fetch(url.pathname + url.search); equal(download.status, 200); sameBytes(new Uint8Array(await download.arrayBuffer()), [0, 1, 2, 3, 128, 255]);
  });
  await check("import clears source organization/folder IDs and publishes every bounded chunk atomically", async () => {
    const f = fixture(ctx);
    const body = { folders: [{ id: "source-folder", name: "encrypted-folder" }], ciphers: Array.from({ length: 220 }, (_, i) => payload({ name: `encrypted-${i}`, organizationId: "source-organization", folderId: "source-vault-folder", archivedDate: i === 0 ? NOW : null })), folderRelationships: [{ key: 0, value: 0 }] };
    await expect(await f.fetch("/api/ciphers/import", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 221); equal(f.db.batches, 1);
    const imported = sql.exec("SELECT organization_id,folder_id,archived_at FROM ciphers WHERE json_extract(data,'$.name')='encrypted-0'").one();
    equal(imported.organization_id, null); ok(imported.folder_id && imported.folder_id !== "source-folder", "source folder ID was reused"); ok(imported.archived_at.startsWith("2026-01-01"), "archive date was lost");
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers WHERE id!=? AND organization_id IS NOT NULL", CIPHER).one().n, 0);
  });
  await check("a failing late import chunk leaves no earlier imported folders or ciphers", async () => {
    const f = fixture(ctx);
    sql.exec("CREATE TRIGGER reject_import BEFORE INSERT ON ciphers WHEN json_extract(NEW.data,'$.name')='reject-last' BEGIN SELECT RAISE(ABORT,'runtime import failure'); END");
    const body = { folders: [{ name: "encrypted-folder" }], ciphers: [...Array.from({ length: 65 }, (_, i) => payload({ name: `encrypted-${i}` })), payload({ name: "reject-last" })] };
    await expect(await f.fetch("/api/ciphers/import", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 500);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 1); equal(sql.exec("SELECT COUNT(*) AS n FROM folders").one().n, 0);
  });
  await check("an attachment commit with a lost acknowledgement retains its adopted staged bytes", async () => {
    const f = attachmentUploadFixture(ctx); const batch = f.db.batch.bind(f.db);
    f.db.batch = async statements => { const rows = await batch(statements); if (statements.some(s => /^INSERT INTO attachments /.test(s.sql))) throw new Error("simulated lost D1 acknowledgement"); return rows; };
    await expect(await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) }), 500);
    ok(f.db.attachment.storage_key, "publication did not commit before the simulated lost response");
    sameBytes(f.bucket.objects.get(f.db.attachment.storage_key), [0, 1, 2, 3, 4, 5]);
    ok(!f.bucket.deleted.includes(f.db.attachment.storage_key), "lost acknowledgement cleanup deleted the adopted object");
  });
  await check("a same-stamp account upgrade fences an in-flight attachment upload", async () => {
    const f = attachmentUploadFixture(ctx); f.bucket.afterPut = () => sql.exec("UPDATE users SET key='upgraded-wrap',security_version=2 WHERE id=?", USER);
    await expect(await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) }), 400);
    equal(f.db.attachment, null); ok(f.db.pending, "failed generation check removed the reservation");
    equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 0);
  });
  await check("concurrent attachment attempts adopt one pointer and cleanup cannot delete the winner", async () => {
    const f = attachmentUploadFixture(ctx); const put = f.bucket.put.bind(f.bucket);
    let entered = 0, release; const ready = new Promise(resolve => { release = resolve; });
    f.bucket.put = async (...args) => { const object = await put(...args); if (++entered === 1) await ready; else release(); return object; };
    const path = attachmentPath("azure-upload", await attachmentToken());
    const responses = await Promise.all([1, 2].map(() => f.fetch(path, { method: "PUT", body: byteStream(6) })));
    equal(responses.map(r => r.status).sort().join(","), "201,400");
    const adopted = f.db.attachment.storage_key; sameBytes(f.bucket.objects.get(adopted), [0, 1, 2, 3, 4, 5]);
    equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 1); ok(!f.bucket.deleted.includes(adopted), "a losing attempt deleted the winner");
  });
  async function replaceAttachment(f, bytes) {
    const form = new FormData(); form.append("data", new Blob([bytes]), "encrypted-name");
    return f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { method: "POST", headers: { Authorization: `Bearer ${await accessToken()}` }, body: form });
  }
  function pauseAttachmentBatch(f, prefix) {
    const batch = f.db.batch.bind(f.db);
    let reached, resume, paused = false;
    const entered = new Promise(resolve => { reached = resolve; });
    const resumeBatch = new Promise(resolve => { resume = resolve; });
    f.db.batch = async statements => {
      if (!paused && statements.some(statement => statement.sql.startsWith(prefix))) {
        paused = true;
        reached();
        await resumeBatch;
      }
      return batch(statements);
    };
    return { entered, resume };
  }
  async function reserveAttachment(f) {
    return f.fetch(`/api/ciphers/${CIPHER}/attachment/v2`, {
      method: "POST",
      headers: await headers(),
      body: JSON.stringify({ key: "wrapped-key", fileName: "encrypted-name", fileSize: 600 }),
    });
  }
  await check("v2 attachment uploads reject declarations and streams over remaining quota", async () => {
    for (const capability of [true, false]) {
      const f = attachmentUploadFixture(ctx);
      f.env.ATTACHMENT_TOTAL_LIMIT_KB = "1";
      await expect(await reserveAttachment(f), 200);
      const path = attachmentPath("azure-upload", await attachmentToken());
      const upload = size => capability
        ? f.fetch(path, { method: "PUT", body: byteStream(size) })
        : replaceAttachment(f, new Uint8Array(size));

      // Another reservation uses 600 of 1024 bytes. The upload excludes its own reservation.
      f.db.pending.file_size_bytes = 425;
      const declaredTooLarge = await expect(await upload(424), 400);
      equal(declaredTooLarge.msg, "Invalid query parameters: Attachment storage limit reached");
      equal(f.bucket.deleted.length, 0, "a rejected declaration started a staged upload");
      f.db.pending.file_size_bytes = 424;
      const streamTooLarge = await expect(await upload(425), 400);
      equal(streamTooLarge.msg, "Invalid request: File size exceeds limit");
      equal(f.db.pending.file_size_bytes, 424);
      equal(f.db.attachment, null);

      await expect(await upload(424), capability ? 201 : 200);
      equal(f.db.pending, null);
      equal(f.db.attachment.file_size_bytes, 424);
    }
  });
  await check("attachment reservations recheck quota at commit", async () => {
    const f = attachmentUploadFixture(ctx);
    f.db.pending = null;
    f.env.ATTACHMENT_TOTAL_LIMIT_KB = "1";
    const { entered, resume } = pauseAttachmentBatch(f, "INSERT INTO attachments_pending");
    const first = reserveAttachment(f);
    try {
      await Promise.race([entered, first.then(response => { throw new Error(`Reservation missed its commit: ${response.status}`); })]);
      await expect(await reserveAttachment(f), 200);
      resume();
      const rejected = await expect(await first, 400);
      equal(rejected.msg, "Invalid query parameters: Attachment storage limit reached");
      const pending = sql.exec("SELECT COUNT(*) AS n, SUM(file_size_bytes) AS bytes FROM attachments_pending").one();
      equal(pending.n, 1);
      equal(pending.bytes, 600);
    } finally {
      resume();
      await first;
    }
  });
  await check("attachment uploads recheck quota at commit and discard rejected staged objects", async () => {
    for (const mode of ["capability", "multipart", "replacement"]) {
      const f = mode === "replacement" ? fixture(ctx) : attachmentUploadFixture(ctx);
      if (mode === "replacement") f.db.pending = null;
      f.env.ATTACHMENT_TOTAL_LIMIT_KB = "1";
      const original = JSON.stringify([f.db.attachment, f.db.pending]);
      const stage = async () => {
        if (mode === "capability") {
          return f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(600) });
        }
        return replaceAttachment(f, new Uint8Array(600));
      };
      const prefix = mode === "replacement" ? "UPDATE attachments SET file_size_bytes=" : "INSERT INTO attachments ";
      const { entered, resume } = pauseAttachmentBatch(f, prefix);
      const upload = stage();
      try {
        await Promise.race([entered, upload.then(response => { throw new Error(`${mode} upload missed its commit: ${response.status}`); })]);
        const staged = [...f.bucket.objects.keys()].find(key => key.startsWith("attachments/"));
        ok(staged, `${mode} upload did not stage the file`);
        await expect(await reserveAttachment(f), 200);
        const revision = f.db.row("users", USER).updated_at;
        resume();
        const rejected = await expect(await upload, 400);
        equal(rejected.msg, "Invalid query parameters: Attachment storage limit reached");
        equal(JSON.stringify([f.db.attachment, f.db.pending]), original);
        equal(f.db.row("users", USER).updated_at, revision);
        ok(f.bucket.deleted.includes(staged), `${mode} upload left a rejected staged object`);
        if (mode === "replacement") sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
      } finally {
        resume();
        await upload;
      }
    }
  });
  await check("Bearer multipart replaces a ready attachment with a new adopted object pointer", async () => {
    const f = fixture(ctx); f.db.pending = null;
    await expect(await replaceAttachment(f, "newest"), 200);
    ok(f.db.attachment.storage_key, "replacement did not adopt a staged key");
    equal(new TextDecoder().decode(f.bucket.objects.get(f.db.attachment.storage_key)), "newest");
    const downloaded = await f.fetch(attachmentPath("download", await attachmentToken())); equal(downloaded.status, 200); equal(new TextDecoder().decode(await downloaded.arrayBuffer()), "newest");
  });
  await check("failed ready attachment replacement preserves the committed metadata and old bytes", async () => {
    const f = fixture(ctx); f.db.pending = null; const before = JSON.stringify(f.db.attachment); f.db.failBatch = true;
    await expect(await replaceAttachment(f, "newest"), 500);
    equal(JSON.stringify(f.db.attachment), before); sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
    equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 0);
  });
  await check("a losing ready attachment replacement cannot overwrite or delete the winner", async () => {
    const f = fixture(ctx); f.db.pending = null;
    const put = f.bucket.put.bind(f.bucket); let reached, release, calls = 0;
    const gate = new Promise(resolve => { reached = resolve; }); const resume = new Promise(resolve => { release = resolve; });
    f.bucket.put = async (...args) => { if (++calls === 1) { reached(); await resume; } return put(...args); };
    const losing = replaceAttachment(f, "loser!");
    try {
      await Promise.race([gate, losing.then(async response => { throw new Error(`Replacement missed R2 gate: ${response.status} ${await response.clone().text()}`); })]);
      await expect(await replaceAttachment(f, "winner"), 200); release(); await expect(await losing, 400);
      const adopted = f.db.attachment.storage_key; equal(new TextDecoder().decode(f.bucket.objects.get(adopted)), "winner");
      ok(!f.bucket.deleted.includes(adopted), "losing replacement erased adopted bytes");
      equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 1);
    } finally { release(); await losing; }
  });
  await check("a legacy download capability cannot write a ready attachment through Azure PUT", async () => {
    const f = fixture(ctx); f.db.pending = null; const before = JSON.stringify(f.db.attachment); const signed = await attachmentToken();
    equal((await f.fetch(attachmentPath("download", signed))).status, 200);
    await expect(await f.fetch(attachmentPath("azure-upload", signed), { method: "PUT", body: byteStream(6) }), 404);
    equal(JSON.stringify(f.db.attachment), before); sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
  });
}

export class SqlRuntime {
  constructor(ctx) { this.ctx = ctx; }
  async fetch() {
    sqlState = this.ctx;
    const pending = [];
    await runSuite({ waitUntil(promise) { pending.push(promise); } });
    await Promise.all(pending);
    return new Response("Runtime suite passed");
  }
}
export default { async test(_controller, bindings) {
  const response = await bindings.SQL.get(bindings.SQL.idFromName("runtime")).fetch("https://test/");
  if (!response.ok) throw new Error(await response.text());
} };
