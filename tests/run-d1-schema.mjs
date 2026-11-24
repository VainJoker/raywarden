import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHmac } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { parseJsonc } from "../scripts/deploy.mjs";
import { expectStatus } from "./runtime-assertions.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const entry = resolve(root, "build/index.js");
if (!existsSync(entry)) throw new Error("Missing compiled Worker; run just build first");
const source = parseJsonc(readFileSync(join(root, "wrangler.jsonc"), "utf8"));
const local = source.env.local;
const directory = mkdtempSync(join(tmpdir(), "raywarden-d1-schema-"));
const configPath = join(directory, "wrangler.json");
const bindingsPath = join(directory, "bindings.json");
const migrationsDir = join(directory, "migrations");
const persistTo = join(directory, "state");
const migrations = readdirSync(join(root, "sql/migrations")).filter(name => name.endsWith(".sql")).sort();
const oldKey = "fixture-cipher/fixture-attachment";
const oldBytes = "old ciphertext";
const newBytes = "new ciphertext";
const releaseId = "b".repeat(64);
const accessSecret = "fixture-schema-access-secret";
process.env.WRANGLER_SEND_METRICS = "false";
process.env.WRANGLER_LOG_PATH = join(directory, "logs");

// Use only fresh, synthetic, local bindings and ignore repository .dev.vars.
const config = {
  name: "raywarden-d1-schema-test", main: entry, workers_dev: false,
  compatibility_date: source.compatibility_date, compatibility_flags: source.compatibility_flags,
  keep_vars: false, vars: { ...local.vars, RAYWARDEN_RELEASE_ID: releaseId },
  d1_databases: [{ binding: "DB", database_id: "00000000-0000-4000-8000-00000000d100", database_name: "raywarden-schema-test", migrations_dir: "migrations" }],
  r2_buckets: [{ binding: "ATTACHMENTS_BUCKET", bucket_name: "raywarden-schema-test" }],
  durable_objects: local.durable_objects, migrations: local.migrations, ratelimits: local.ratelimits,
};
const run = promisify(execFile);
const { getPlatformProxy, unstable_dev } = await import("wrangler");

async function migrate() {
  await run(process.execPath, [join(root, "node_modules/wrangler/bin/wrangler.js"),
    "d1", "migrations", "apply", "DB", "--config", configPath, "--local", "--persist-to", persistTo],
  { cwd: directory, timeout: 120_000, env: { ...process.env, CI: "true" } });
}

async function withBindings(action) {
  const proxy = await getPlatformProxy({ configPath: bindingsPath, envFiles: [], persist: { path: join(persistTo, "v3") }, remoteBindings: false });
  try { return await action(proxy.env); } finally { await proxy.dispose(); }
}

async function history(db) {
  return (await db.prepare("SELECT name FROM d1_migrations ORDER BY id").all()).results.map(row => row.name);
}

async function seedFixture({ DB, ATTACHMENTS_BUCKET }) {
  assert.deepEqual(await history(DB), migrations);
  await DB.batch([
    DB.prepare(`INSERT INTO users (id,email,master_password_hash,key,private_key,public_key,security_stamp,created_at,updated_at)
      VALUES('fixture-user','owner@example.test','hash','2.key','2.private','public','stamp','2026-01-01','2026-01-01')`),
    DB.prepare(`INSERT INTO devices (user_id,device_id,name,device_type,session_token,created_at,updated_at)
      VALUES('fixture-user','fixture-device','schema fixture',0,'session','2026-01-01','2026-01-01')`),
    DB.prepare(`INSERT INTO ciphers (id,user_id,cipher_type,data,created_at,updated_at)
      VALUES('fixture-cipher','fixture-user',1,'{}','2026-01-01','2026-01-01')`),
    DB.prepare(`INSERT INTO attachments (id,cipher_id,file_name,file_size_bytes,encrypted_key,storage_key,created_at,updated_at)
      VALUES('fixture-attachment','fixture-cipher','opaque-name',?1,'opaque-key',?2,'2026-01-01','2026-01-01')`).bind(oldBytes.length, oldKey),
    DB.prepare("INSERT INTO jwt_keys(id,access_secret,refresh_secret) VALUES('global',?1,'fixture-schema-refresh-secret')").bind(accessSecret),
  ]);
  await ATTACHMENTS_BUCKET.put(oldKey, oldBytes);
}

function bearer() {
  const now = Math.floor(Date.now() / 1000);
  const json = value => Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = json({ alg: "HS256", typ: "JWT" });
  const claims = json({ sub: "fixture-user", iat: now, nbf: now, exp: now + 300, sstamp: "stamp", session_token: "session", token_use: "access", device: "fixture-device" });
  const signature = createHmac("sha256", accessSecret).update(`${header}.${claims}`).digest("base64url");
  return `Bearer ${header}.${claims}.${signature}`;
}

async function verifyWorker(worker) {
  const alive = await worker.fetch("/api/alive");
  await expectStatus(alive, 200, "Worker readiness");
  assert.match(await alive.json(), /^\d{4}-\d\d-\d\dT/);
  assert.equal(alive.headers.get("X-Raywarden-Release-Id"), releaseId);

  const path = "/api/ciphers/fixture-cipher/attachment/fixture-attachment";
  const headers = { Authorization: bearer() };
  const download = async expected => {
    const metadata = await worker.fetch(path, { headers });
    await expectStatus(metadata, 200, "attachment metadata");
    const target = new URL((await metadata.json()).url);
    const response = await worker.fetch(target.pathname + target.search);
    await expectStatus(response, 200, "attachment download");
    assert.equal(await response.text(), expected);
  };
  await download(oldBytes);
  const boundary = "raywarden-schema-attachment";
  const body = [
    `--${boundary}`,
    'Content-Disposition: form-data; name="key"',
    "",
    "replacement-opaque-key",
    `--${boundary}`,
    'Content-Disposition: form-data; name="data"; filename="encrypted.bin"',
    "Content-Type: application/octet-stream",
    "",
    newBytes,
    `--${boundary}--`,
    "",
  ].join("\r\n");
  const updated = await worker.fetch(path, {
    method: "POST", headers: { ...headers, "Content-Type": `multipart/form-data; boundary=${boundary}` }, body,
  });
  await expectStatus(updated, 200, "attachment replacement");
  await updated.text();
  await download(newBytes);
}

try {
  mkdirSync(migrationsDir);
  writeFileSync(configPath, JSON.stringify(config));
  const { durable_objects: _durableObjects, migrations: _workerMigrations, ...bindingsConfig } = config;
  writeFileSync(bindingsPath, JSON.stringify(bindingsConfig));
  for (const name of migrations) {
    copyFileSync(join(root, "sql/migrations", name), join(migrationsDir, name));
  }
  await migrate();
  await withBindings(seedFixture);
  // Reapplying the baseline must preserve seeded data and migration history.
  await migrate();
  await withBindings(async ({ DB }) => {
    assert.deepEqual(await history(DB), migrations);
    assert.equal(await DB.prepare("SELECT storage_key FROM attachments WHERE id='fixture-attachment'").first("storage_key"), oldKey);
    assert.equal(await DB.prepare("SELECT COUNT(*) AS count FROM pragma_foreign_key_check").first("count"), 0);
  });

  const worker = await unstable_dev(entry, {
    config: configPath, envFiles: [], ip: "127.0.0.1", port: 0,
    local: true, persistTo, inspect: false,
    experimental: { forceLocal: true, disableDevRegistry: true, disableExperimentalWarning: true, enableContainers: false, watch: false, showInteractiveDevSession: false },
  });
  try { await verifyWorker(worker); } finally { await worker.stop(); }

  await withBindings(async ({ DB, ATTACHMENTS_BUCKET }) => {
    const storageKey = await DB.prepare("SELECT storage_key FROM attachments WHERE id='fixture-attachment'").first("storage_key");
    assert.ok(storageKey && storageKey !== oldKey, "replacement must publish a fresh object key");
    assert.equal(await (await ATTACHMENTS_BUCKET.get(storageKey)).text(), newBytes);
    assert.equal(await ATTACHMENTS_BUCKET.get(oldKey), null);
    assert.equal(await DB.prepare("SELECT COUNT(*) AS count FROM storage_upload_stages").first("count"), 0);
    assert.equal(await DB.prepare("SELECT COUNT(*) AS count FROM storage_cleanup_jobs").first("count"), 0);
  });
  console.log("Validated fresh D1 schema, repeat migration, attachment reads, staged replacement and R2 cleanup with native bindings");
} catch (error) {
  if (error.stdout) console.error(error.stdout);
  if (error.stderr) console.error(error.stderr);
  throw error;
} finally {
  rmSync(directory, { recursive: true, force: true });
}
