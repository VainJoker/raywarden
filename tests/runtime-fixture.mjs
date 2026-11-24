import RustWorker from "./index.js";
import { schema, reset } from "./runtime-schema.mjs";
import { equal, ok } from "./runtime-tools.mjs";
import { toBase64Url as base64url } from "./runtime-tools.mjs";

export { base64url };

export const SECRET = "runtime-test-only-access-secret";
export const USER = "00000000-0000-4000-8000-000000000001";
export const CIPHER = "00000000-0000-4000-8000-000000000002";
export const FILE = "00000000-0000-4000-8000-000000000003";
export const SEND = "00000000-0000-4000-8000-000000000004";
export const NOW = "2026-01-01T00:00:00.000Z";
export const ORIGIN = "https://client.test";
export const ATTACHMENT_KEY = `${CIPHER}/${FILE}`;
export const SEND_KEY = `sends/${SEND}/${FILE}`;
export const encoder = new TextEncoder();

// Capture every column so failure-path tests also catch unexpected side effects.
export function snapshotTables(sql, tables) {
  return JSON.stringify(Object.fromEntries(tables.map(table => [
    table, sql.exec(`SELECT * FROM ${table} ORDER BY rowid`).toArray(),
  ])));
}

// Match workerd's D1PreparedStatement.bind contract before native SQLite:
// booleans become integers; BigInt/undefined are rejected rather than masked.
function d1Binding(value) {
  if (typeof value === "boolean") return Number(value);
  if (value === null || typeof value === "number" || typeof value === "string" || value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
  if (Array.isArray(value) && value.every(byte => typeof byte === "number" && byte >= 0 && byte < 256)) return new Uint8Array(value).buffer;
  const error = new Error(`D1_TYPE_ERROR: Type '${typeof value}' is not supported`);
  throw error;
}

// The SDK binding adapter executes production SQL in workerd's native SQLite.
// It has no access to an application database or to the network.
class D1Database {
  constructor(storage, reportSqlFailure, { empty = false } = {}) {
    this.storage = storage;
    this.reportSqlFailure = reportSqlFailure;
    storage.sql.exec(reset + schema);
    this.batches = 0; this.queries = []; this.failBatch = false;
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
    let cursor;
    try { cursor = this.storage.sql.exec(sql, ...params.map(v => v === undefined ? null : v)); }
    catch (error) { this.reportSqlFailure({ sql, message: error.message }); throw error; }
    const results = cursor.toArray();
    const changes = this.storage.sql.exec("SELECT changes() AS n").one().n;
    return { success: true, results, meta: { changes } };
  }
  prepare(sql) {
    const db = this;
    const statement = (params = []) => ({
      sql, params,
      bind(...values) {
        try { return statement(values.map(d1Binding)); }
        catch (error) { db.reportSqlFailure({ message: error.message }); throw error; }
      },
      async first(column) { const row = db.execute(sql, params).results[0] ?? null; return column && row ? row[column] : row; },
      async run() { return db.execute(sql, params); },
      async all() { return db.execute(sql, params); },
    });
    return statement();
  }
  async batch(statements) {
    this.batches++;
    if (this.failBatch) throw new Error("fixture transaction rejected");
    return this.storage.transactionSync(() => statements.map(s => this.execute(s.sql, s.params)));
  }
  beforeNextBatch(matches, action) {
    const batch = this.batch;
    let reached = false;
    this.batch = async statements => {
      if (matches(statements)) {
        reached = true;
        this.batch = batch;
        await action();
      }
      return batch.call(this, statements);
    };
    return () => reached;
  }
  row(table, id) {
    const row = this.storage.sql.exec(`SELECT * FROM ${table} WHERE id=?`, id).toArray()[0];
    if (!row) return null;
    return new Proxy(row, { set: (target, column, value) => {
      this.storage.sql.exec(`UPDATE ${table} SET ${column}=? WHERE id=?`, value, id);
      target[column] = value; return true;
    } });
  }
  setRow(table, id, row) {
    if (!row) { this.storage.sql.exec(`DELETE FROM ${table} WHERE id=?`, id); return; }
    const columns = new Set(this.storage.sql.exec(`PRAGMA table_info(${table})`).toArray().map(c => c.name));
    const keys = Object.keys(row).filter(key => columns.has(key));
    this.storage.sql.exec(`INSERT INTO ${table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')}) ON CONFLICT(id) DO UPDATE SET ${keys.map(k => `${k}=excluded.${k}`).join(',')}`, ...keys.map(k => row[k]));
  }
  get cipher() { return this.row("ciphers", CIPHER); }
  set cipher(value) { this.setRow("ciphers", CIPHER, value); }
  get attachment() { return this.row("attachments", FILE); }
  set attachment(value) { this.setRow("attachments", FILE, value); }
  get pending() { return this.row("attachments_pending", FILE); }
  set pending(value) { this.setRow("attachments_pending", FILE, value); }
  get send() { return this.row("sends", SEND); }
  set send(value) { this.setRow("sends", SEND, value); }
  get sessionValid() { return this.storage.sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token === "session"; }
  set sessionValid(value) { this.storage.sql.exec("UPDATE devices SET session_token=? WHERE user_id=? AND device_id='device'", value ? "session" : "revoked", USER); }
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

export class DurableObjectNamespace {
  constructor(handler) { this.handler = handler; }
  idFromName(name) { return { name }; }
  get(id) { return { fetch: (request) => this.handler(request, id.name) }; }
}

export function captureNotifications(fixture, capture = update => update) {
  const messages = [];
  fixture.env.notifydo = new DurableObjectNamespace(async (request, name) => {
    equal(name, "global", "notification instance");
    messages.push(capture(await request.json()));
    return new Response(null, { status: 204 });
  });
  return messages;
}

export class KvNamespace {
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

export function createRuntimeFixtures(state, ctx) {
  const { storage } = state;
  let lastSqlFailure;
  const reportSqlFailure = failure => { lastSqlFailure = failure; };

  function fixture(options = {}) {
    lastSqlFailure = undefined;
    const db = new D1Database(storage, reportSqlFailure, options);
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
  function attachmentUploadFixture() {
    const f = fixture();
    f.db.attachment = null;
    f.bucket.objects.delete(ATTACHMENT_KEY);
    storage.sql.exec("DELETE FROM storage_cleanup_jobs");
    return f;
  }

  function kvFixture(upload = false) {
    const f = upload ? attachmentUploadFixture() : fixture(); const kv = new KvNamespace();
    delete f.env.ATTACHMENTS_BUCKET;
    f.env.ATTACHMENTS_KV = kv;
    return { ...f, kv };
  }
  return { fixture, attachmentUploadFixture, kvFixture, get lastSqlFailure() { return lastSqlFailure; } };
}

export async function token(claims, secret = SECRET) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(encoder.encode('{"alg":"HS256","typ":"JWT"}'));
  const body = base64url(encoder.encode(JSON.stringify({ iat: now, nbf: now - 1, exp: now + 300, ...claims })));
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return `${header}.${body}.${base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(`${header}.${body}`))))}`;
}
export const attachmentToken = (claims = {}, secret) => token({ sub: USER, cipher_id: CIPHER, attachment_id: FILE, device: "device", ...claims }, secret);
export const sendToken = (scope = "send.download", claims = {}) => token({ sub: scope === "send.upload" ? USER : SEND, aud: "raywarden.send", scope, send_id: SEND, file_id: FILE, access_stamp: "send-stamp", sstamp: "owner-stamp", device: "device", session_token: "session", ...claims });
export const accessToken = (claims = {}) => token({ sub: USER, token_use: "access", sstamp: "owner-stamp", session_token: "session", device: "device", ...claims });
export const attachmentPath = (suffix, signed) => `/api/ciphers/${CIPHER}/attachment/${FILE}/${suffix}?token=${signed}`;
export function byteStream(size, fail = false) {
  let offset = 0;
  return new ReadableStream({ pull(controller) {
    if (offset === size) { if (fail) controller.error(new Error("fixture interrupted stream")); else controller.close(); return; }
    const chunk = new Uint8Array(Math.min(65536, size - offset));
    for (let i = 0; i < chunk.length; i++) chunk[i] = (offset + i) % 251;
    offset += chunk.length;
    controller.enqueue(chunk);
  } });
}
