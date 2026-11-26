import {
  assertDownloadSecurityHeaders,
  bearerJsonHeaders,
  equal,
  expectJson,
  expectJsonOrEmpty,
  expectStatus,
  oauthToken,
  ok,
  sameBytes,
} from "./runtime-tools.mjs";
import {
  ATTACHMENT_KEY,
  CIPHER,
  FILE,
  NOW,
  ORIGIN,
  SEND,
  SEND_KEY,
  USER,
  attachmentPath,
  attachmentToken,
  byteStream,
  captureNotifications,
  encoder,
  sendToken,
  snapshotTables,
} from "./runtime-fixture.mjs";
import RustWorker from "./index.js";

export const vaultChecks = [runVaultChecks, runPersonalVaultChecks, runStorageChecks];

async function runVaultChecks({ fixture, check, sql, accessToken }) {
  const headers = async () => bearerJsonHeaders(await accessToken());
  const payload = (extra = {}) => ({ type: 1, name: "encrypted", login: {}, key: "wrapped-item-key", favorite: false, ...extra });
  const save = async (f, body, id) => expectJsonOrEmpty(await f.fetch(id ? `/api/ciphers/${id}` : "/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 200);

  await check("D1 error envelopes preserve vault conflict classification", async () => {
    const conflict = "bad JSON path: RAY_VAULT_WRITE_CONFLICT";
    for (const [error, status, code] of [
      [new Error(conflict), 400, 5],
      [new Error(`D1_ERROR: ${conflict}`, { cause: new Error(conflict) }), 400, 5],
      [new Error(`D1_ERROR: ${conflict}`), 400, 5],
      [new Error("D1_ERROR: no such table: fixture_private_table: SQLITE_ERROR"), 500, 9001],
    ]) {
      const f = fixture();
      const batch = f.db.batch.bind(f.db);
      let injected = 0;
      f.db.batch = async statements => {
        if (statements.some(statement => statement.sql.includes("RAY_VAULT_WRITE_CONFLICT"))) {
          injected++;
          throw error;
        }
        return batch(statements);
      };
      const result = await expectJsonOrEmpty(await f.fetch("/api/folders", {
        method: "POST", headers: await headers(), body: JSON.stringify({ name: "folder" }),
      }), status);
      equal(result.code, code);
      if (status === 500) {
        equal(result.message, "Database operation failed (D1: SQLITE_ERROR)");
        equal(JSON.stringify(result).includes("fixture_private_table"), false);
      }
      equal(injected, 1, "expected the failure at the guarded folder batch");
      equal(sql.exec("SELECT COUNT(*) AS n FROM folders WHERE user_id=?", USER).one().n, 0);
    }
  });

  await check("single and bulk archive share guarded writes and reject foreign selections atomically", async () => {
    const f = fixture(), foreign = "00000000-0000-4000-8000-000000000088";
    const second = await save(f, payload({ name: "second-own-item" }));
    sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,'other-owner',1,'{}',?,?)", foreign, NOW, NOW);
    const put = async (path, body) => f.fetch(path, { method: "PUT", headers: await headers(), ...(body ? { body: JSON.stringify(body) } : {}) });
    await expectJsonOrEmpty(await put(`/api/ciphers/${CIPHER}/archive`), 200);
    ok(sql.exec("SELECT archived_at FROM ciphers WHERE id=?", CIPHER).one().archived_at, "single archive did not persist");
    await expectJsonOrEmpty(await put("/api/ciphers/archive", { ids: [CIPHER, second.id] }), 200);
    equal(sql.exec("SELECT count(*) AS n FROM ciphers WHERE user_id=? AND archived_at IS NOT NULL", USER).one().n, 2);
    await expectJsonOrEmpty(await put("/api/ciphers/unarchive", { ids: [CIPHER, second.id] }), 200);
    const before = JSON.stringify(sql.exec("SELECT * FROM ciphers ORDER BY id").toArray());
    const revision = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
    await expectJsonOrEmpty(await put(`/api/ciphers/${foreign}/archive`), 400);
    await expectJsonOrEmpty(await put("/api/ciphers/archive", { ids: [CIPHER, foreign] }), 400);
    equal(JSON.stringify(sql.exec("SELECT * FROM ciphers ORDER BY id").toArray()), before);
    equal(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at, revision);
  });

  await check("new cipher types, false favorite and empty folder IDs survive create and list", async () => {
    const f = fixture();
    for (const [type, field] of [[6, "bankAccount"], [7, "driversLicense"], [8, "passport"]]) {
      const body = await save(f, { type, name: "encrypted", key: "wrapped", favorite: false, folderId: "", [field]: { encrypted: "opaque", response: { transient: true } } });
      equal(body.type, type); equal(body.favorite, false); equal(body.folderId, null); equal(body[field].encrypted, "opaque"); equal(body[field].response, undefined);
    }
    const list = await expectJsonOrEmpty(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    equal(list.data.length, 4);
    for (const item of list.data) { equal(item.__storedData, undefined); equal(item.userId, undefined); ok(Array.isArray(item.collectionIds), "private collectionIds must be an array"); }
  });
  await check("sealed cipher blobs round-trip identically through create, GET, list and sync", async () => {
    const f = fixture(); const blob = '{ "format_version": 2, "data": "opaque encrypted bytes" }';
    const created = await save(f, { type: 8, data: blob, name: "ignored", passport: { number: "ignored" }, key: "wrapped", reprompt: 1 });
    const detail = await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${created.id}`, { headers: await headers() }), 200);
    const list = await expectJsonOrEmpty(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    const sync = await expectJsonOrEmpty(await f.fetch("/api/sync?excludeDomains=true", { headers: await headers() }), 200);
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
      const f = fixture();
      const changed = f.db.afterNextQuery(query => query === "SELECT * FROM users WHERE id = ?1", () => {
        if (column === "session_token") f.db.sessionValid = false;
        else f.db.row("users", USER)[column] = value;
      });
      await expectJsonOrEmpty(await f.fetch("/api/sync?excludeDomains=true", { headers: await headers() }), status);
      ok(changed(), "fixture did not change data after the snapshot read");
    }
  });
  await check("large cipher lists and sync preserve items and attachments within D1 size limits", async () => {
    const f = fixture(); const blob = JSON.stringify({ format_version: 2, data: "x".repeat(450000) });
    for (let i = 0; i < 10; i++) sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,?,8,?,?,?)", `large-${i}`, USER, JSON.stringify({ name: "", data: blob }), NOW, NOW);
    const encryptedName = "x".repeat(19000);
    for (let i = 0; i < 110; i++) sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?)", `large-file-${i}`, CIPHER, encryptedName, 6, NOW, NOW);
    const execute = f.db.execute.bind(f.db);
    f.db.execute = (query, params) => {
      const result = execute(query, params);
      const sizes = result.results.map(row => encoder.encode(JSON.stringify(row)).length);
      ok(sizes.every(size => size < 2_000_000), "D1 row exceeds the byte budget");
      ok(sizes.reduce((total, size) => total + size, 0) < 4_000_000, "D1 result exceeds the page budget");
      return result;
    };
    for (const [path, name] of [["/api/ciphers", "data"], ["/api/sync?excludeDomains=true", "ciphers"]]) {
      const response = await expectJsonOrEmpty(await f.fetch(path, { headers: await headers() }), 200);
      const items = response[name];
      const large = items.filter(item => item.id.startsWith("large-"));
      equal(large.length, 10);
      for (const item of large) equal(item.data, blob);
      const attached = items.find(item => item.id === CIPHER).attachments;
      equal(attached.length, 111);
      equal(attached.at(-1).id, "large-file-109");
      equal(attached.at(-1).fileName, encryptedName);
      equal(attached.at(-1).storageKey, undefined);
    }
  });
  await check("Excessive single-Cipher attachment metadata returns a complete 413 error", async () => {
    const f = fixture(), name = "x".repeat(1000000);
    for (let i = 0; i < 17; i++) sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?)", `oversized-file-${i}`, CIPHER, name, 6, NOW, NOW);
    const response = await expectJsonOrEmpty(await f.fetch("/api/ciphers", { headers: await headers() }), 413);
    ok(JSON.stringify(response).includes("Cipher attachment metadata exceeds the server size limit"), "missing size rejection");
    equal(response.object, "error");

    // Deleting attachments on an already-oversized cipher must not deadlock on 413.
    await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/oversized-file-16`, { method: "DELETE", headers: await headers() }), 200);
    await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/oversized-file-15`, { method: "DELETE", headers: await headers() }), 200);
    await expectJsonOrEmpty(await f.fetch("/api/ciphers", { headers: await headers() }), 200);

    // Reserving an attachment that would push metadata over 16 MiB is rejected with 413.
    const overReserve = await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/v2`, {
      method: "POST", headers: await headers(), body: JSON.stringify({ key: "k", fileName: "x".repeat(2000000), fileSize: 6 }),
    }), 413);
    ok(JSON.stringify(overReserve).includes("Cipher attachment metadata exceeds the server size limit"));
  });
  await check("cipher keyset pagination, attachment2 key rotation, and concurrent edit fencing", async () => {
    const f = fixture();
    for (let i = 0; i < 205; i++) sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,?,1,?,?,?)", `small-${i}`, USER, '{"name":"encrypted"}', NOW, NOW);
    const expected = sql.exec("SELECT id FROM ciphers WHERE user_id=? ORDER BY updated_at DESC, rowid", USER).toArray().map(r => r.id);
    const listing = await expectJsonOrEmpty(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    equal(JSON.stringify(listing.data.map(r => r.id)), JSON.stringify(expected));

    const fRot = fixture(), update = { fileName: "rotated-name", key: "rotated-key" };
    const saved = await expectJsonOrEmpty(await fRot.fetch(`/api/ciphers/${CIPHER}`, {
      method: "PUT", headers: await headers(), body: JSON.stringify({ type: 1, name: "updated", login: {}, attachments2: { [FILE]: update } }),
    }), 200);
    equal(saved.attachments[0].key, "rotated-key");

    const fRace = fixture(), auth = await headers();
    const responses = await fRace.db.beforeBothBatches(
      s => s.some(st => /^UPDATE ciphers SET cipher_type=/.test(st.sql)),
      idx => fRace.fetch(`/api/ciphers/${CIPHER}`, { method: "POST", headers: auth, body: JSON.stringify(payload({ name: `n-${idx}` })) }),
    );
    equal(responses.map(r => r.status).sort().join(","), "200,400");
  });
  await check("attachment lists have stable URLs and authenticated metadata mints a 60-second download capability", async () => {
    const f = fixture();
    f.env.DOMAIN = " vault.test ";
    const expected = `https://vault.test/attachments/${CIPHER}/${FILE}`;
    const cipher = await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}`, { headers: await headers() }), 200);
    const list = await expectJsonOrEmpty(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    const sync = await expectJsonOrEmpty(await f.fetch("/api/sync?excludeDomains=true", { headers: await headers() }), 200);
    for (const item of [cipher, list.data.find(item => item.id === CIPHER), sync.ciphers.find(item => item.id === CIPHER)]) {
      equal(item.attachments[0].url, expected);
    }
    const metadata = await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { headers: await headers() }), 200);
    const url = new URL(metadata.url); const signed = url.searchParams.get("token"); ok(signed, "metadata did not mint a capability");
    equal(url.origin + url.pathname, expected);
    const segment = signed.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
    const claims = JSON.parse(atob(segment)); const now = Math.floor(Date.now() / 1000);
    ok(claims.exp >= now + 55 && claims.exp <= now + 60, "attachment TTL is not one minute");
    const download = await f.fetch(url.pathname + url.search); equal(download.status, 200); sameBytes(new Uint8Array(await download.arrayBuffer()), [0, 1, 2, 3, 128, 255]);
  });
  await check("sync and cipher responses retain attachment metadata when configured storage is invalid", async () => {
    const f = fixture();
    const auth = { headers: await headers() };
    const read = async path => expectJsonOrEmpty(await f.fetch(path, auth), 200);
    const metadata = async () => {
      const detail = await read(`/api/ciphers/${CIPHER}`);
      const list = await read("/api/ciphers");
      const sync = await read("/api/sync?excludeDomains=true");
      return [detail, list.data.find(item => item.id === CIPHER), sync.ciphers.find(item => item.id === CIPHER)]
        .map(item => item.attachments ?? null);
    };
    const revision = f.db.row("users", USER).updated_at;
    const expected = await metadata();
    for (const attachments of expected) equal(attachments[0].id, FILE);

    const downloadToken = await attachmentToken();
    const uploadToken = await attachmentToken({ scope: "attachment.upload" });
    const fileOperations = async status => {
      await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, auth), status);
      await expectJsonOrEmpty(await f.fetch(attachmentPath("download", downloadToken)), status);
      await expectJsonOrEmpty(await f.fetch(attachmentPath("azure-upload", uploadToken), { method: "PUT", body: byteStream(6) }), status);
    };
    f.env.ATTACHMENTS_BUCKET = {};
    equal(JSON.stringify(await metadata()), JSON.stringify(expected), "malformed R2");
    await fileOperations(500);

    delete f.env.ATTACHMENTS_BUCKET;
    for (const attachments of await metadata()) equal(attachments, null);
    await fileOperations(400);
    equal(f.db.row("users", USER).updated_at, revision);
    equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages").one().n, 0);
  });
  await check("large import preserves personal folder links and archive state without copying source IDs", async () => {
    const f = fixture();
    const body = { folders: [{ id: "source-folder", name: "encrypted-folder" }], ciphers: Array.from({ length: 220 }, (_, i) => payload({ name: `encrypted-${i}`, organizationId: "source-organization", folderId: "source-vault-folder", archivedDate: i === 0 ? NOW : null })), folderRelationships: [{ key: 0, value: 0 }] };
    await expectJsonOrEmpty(await f.fetch("/api/ciphers/import", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 221);
    const imported = sql.exec("SELECT organization_id,folder_id,archived_at FROM ciphers WHERE json_extract(data,'$.name')='encrypted-0'").one();
    equal(imported.organization_id, null); ok(imported.folder_id && imported.folder_id !== "source-folder", "source folder ID was reused"); ok(imported.archived_at.startsWith("2026-01-01"), "archive date was lost");
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers WHERE id!=? AND organization_id IS NOT NULL", CIPHER).one().n, 0);
  });
  await check("a failing late import chunk leaves no earlier imported folders or ciphers", async () => {
    const f = fixture();
    sql.exec("CREATE TRIGGER reject_import BEFORE INSERT ON ciphers WHEN json_extract(NEW.data,'$.name')='reject-last' BEGIN SELECT RAISE(ABORT,'runtime import failure'); END");
    const body = { folders: [{ name: "encrypted-folder" }], ciphers: [...Array.from({ length: 65 }, (_, i) => payload({ name: `encrypted-${i}` })), payload({ name: "reject-last" })] };
    await expectJsonOrEmpty(await f.fetch("/api/ciphers/import", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 500);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 1); equal(sql.exec("SELECT COUNT(*) AS n FROM folders").one().n, 0);
  });
}

/** Two independently authenticated sessions using real client-side crypto.
 * Runs production WASM/SQL with isolated object-storage bindings. This is a
 * server round trip, not an official-client or real-cloud acceptance test.
 */
async function runPersonalVaultChecks({ fixture, check }) {
  const encoder = new TextEncoder(), decoder = new TextDecoder();
  const json = async response => expectJson(await response, 200);
  const base64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const unbase64 = text => Uint8Array.from(atob(text), char => char.charCodeAt(0));
  const rawKey = () => crypto.getRandomValues(new Uint8Array(64));
  async function seal(raw, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const aes = await crypto.subtle.importKey("raw", raw.slice(0, 32), "AES-CBC", false, ["encrypt"]);
    const mac = await crypto.subtle.importKey("raw", raw.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aes, encoder.encode(plaintext)));
    const authenticated = new Uint8Array(iv.length + encrypted.length); authenticated.set(iv); authenticated.set(encrypted, iv.length);
    return `2.${base64(iv)}|${base64(encrypted)}|${base64(await crypto.subtle.sign("HMAC", mac, authenticated))}`;
  }
  async function open(raw, ciphertext) {
    equal(ciphertext.slice(0, 2), "2.", "encryption type");
    const [iv, encrypted, signature] = ciphertext.slice(2).split("|").map(unbase64);
    const authenticated = new Uint8Array(iv.length + encrypted.length); authenticated.set(iv); authenticated.set(encrypted, iv.length);
    const mac = await crypto.subtle.importKey("raw", raw.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    equal(await crypto.subtle.verify("HMAC", mac, signature, authenticated), true, "ciphertext authentication");
    const aes = await crypto.subtle.importKey("raw", raw.slice(0, 32), "AES-CBC", false, ["decrypt"]);
    return decoder.decode(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aes, encrypted));
  }
  const pathOf = value => { const url = new URL(value, "https://vault.test"); return url.pathname + url.search; };
  const request = (f, tokens, path, body, method = "POST") => f.fetch(path, {
    method, headers: bearerJsonHeaders(tokens.access_token), ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const login = (f, password, device) => json(oauthToken(f, {
    grant_type: "password", username: "personal@example.test", password,
    deviceIdentifier: device, deviceName: device, deviceType: "14",
  }, { "Bitwarden-Client-Version": "2026.10.1", "device-type": "14" }));
  const sync = (f, tokens) => json(request(f, tokens, "/api/sync?excludeDomains=true", undefined, "GET"));
  async function bootstrap() {
    const f = fixture({ empty: true });
    f.env.ALLOWED_EMAILS = "personal@example.test";
    f.env.OWNER_SETUP_TOKEN = "isolated-personal-vault-owner-authorization";
    const wrapping = rawKey(), userKey = rawKey();
    const authentication = base64(crypto.getRandomValues(new Uint8Array(32)));
    const wrapped = await seal(wrapping, base64(userKey));
    await expectStatus(await f.fetch("/api/accounts/register", { method: "POST", headers: {
      "Content-Type": "application/json", "X-Raywarden-Setup-Token": f.env.OWNER_SETUP_TOKEN,
    }, body: JSON.stringify({ email: f.env.ALLOWED_EMAILS, masterPasswordHash: authentication, key: wrapped,
      keys: { publicKey: "isolated-public-key", encryptedPrivateKey: await seal(userKey, "isolated-private-key") }, kdf: 0, kdfIterations: 600000 }) }), 200);
    const first = await login(f, authentication, "personal-first-device");
    const second = await login(f, authentication, "personal-second-device");
    equal(first.access_token === second.access_token, false, "independent sessions");
    return { f, first, second, userKey, authentication };
  }

  await check("two login sessions decrypt each other's edits and old ciphertext after password rewrapping", async () => {
    const { f, first, second, userKey, authentication } = await bootstrap();
    const folder = await json(request(f, first, "/api/folders", { name: await seal(userKey, "Personal folder") }));
    const item = await json(request(f, first, "/api/ciphers", { type: 1, name: await seal(userKey, "Personal login"),
      folderId: folder.id, login: { username: await seal(userKey, "roundtrip-user"), password: await seal(userKey, "roundtrip-password") } }));
    let snapshot = await sync(f, second), remote = snapshot.ciphers.find(cipher => cipher.id === item.id);
    equal(await open(userKey, remote.login.password), "roundtrip-password");
    equal(await open(userKey, snapshot.folders[0].name), "Personal folder");
    equal(snapshot.policiesNew.length, 0);
    await json(request(f, second, `/api/ciphers/${item.id}`, { ...remote, name: await seal(userKey, "Edited on second device"), lastKnownRevisionDate: remote.revisionDate }, "PUT"));
    remote = (await sync(f, first)).ciphers.find(cipher => cipher.id === item.id);
    equal(await open(userKey, remote.name), "Edited on second device");
    equal(await open(userKey, remote.login.username), "roundtrip-user");
    const nextAuthentication = base64(crypto.getRandomValues(new Uint8Array(32))), newWrapping = rawKey();
    await expectStatus(await request(f, second, "/api/accounts/password", { masterPasswordHash: authentication,
      newMasterPasswordHash: nextAuthentication, key: await seal(newWrapping, base64(userKey)) }), 200);
    for (const old of [first, second]) await expectStatus(await request(f, old, "/api/accounts/profile", undefined, "GET"), 401);
    const renewed = await login(f, nextAuthentication, "personal-first-device");
    equal(await open(newWrapping, renewed.Key), base64(userKey), "rewrapped user key");
    snapshot = await sync(f, renewed);
    equal(await open(userKey, snapshot.ciphers[0].login.password), "roundtrip-password");
    equal(await open(userKey, snapshot.ciphers[0].name), "Edited on second device");
    await expectStatus(await f.fetch("/api/sync"), 401);
  });

  await check("another session downloads encrypted attachments and anonymous recipients decrypt text and file Sends", async () => {
    const { f, first, second, userKey } = await bootstrap();
    const item = await json(request(f, first, "/api/ciphers", { type: 1, name: await seal(userKey, "With file"), login: {} }));
    const fileKey = rawKey(), ciphertext = await seal(fileKey, "roundtrip attachment bytes");
    const reserved = await json(request(f, first, `/api/ciphers/${item.id}/attachment/v2`, {
      key: await seal(userKey, base64(fileKey)), fileName: await seal(userKey, "example.txt"), fileSize: encoder.encode(ciphertext).length,
    }));
    await expectStatus(await f.fetch(pathOf(reserved.url), { method: "PUT", body: encoder.encode(ciphertext) }), 201);
    const remote = (await sync(f, second)).ciphers.find(cipher => cipher.id === item.id);
    const attachment = remote.attachments[0];
    equal(await open(userKey, attachment.fileName), "example.txt");
    const metadata = await json(request(f, second, `/api/ciphers/${item.id}/attachment/${attachment.id}`, undefined, "GET"));
    const attachmentResponse = await expectStatus(await f.fetch(pathOf(metadata.url)), 200);
    assertDownloadSecurityHeaders(attachmentResponse);
    const downloaded = decoder.decode(await attachmentResponse.arrayBuffer());
    equal(await open(unbase64(await open(userKey, attachment.key)), downloaded), "roundtrip attachment bytes");
    await expectStatus(await f.fetch(`/api/ciphers/${item.id}/attachment/${attachment.id}`), 401);
    const sendKey = rawKey(), deletionDate = new Date(Date.now() + 86400000).toISOString();
    const textSend = await json(request(f, first, "/api/sends", { type: 0, name: await seal(sendKey, "Shared text"),
      key: await seal(userKey, base64(sendKey)), deletionDate, text: { text: await seal(sendKey, "Anonymous text"), hidden: false } }));
    const received = await json(f.fetch(`/api/sends/access/${textSend.accessId}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }));
    equal(await open(sendKey, received.text.text), "Anonymous text");
    const encryptedFile = encoder.encode(await seal(sendKey, "Anonymous file bytes"));
    const fileSend = await json(request(f, first, "/api/sends/file/v2", { type: 1, name: await seal(sendKey, "Shared file"),
      key: await seal(userKey, base64(sendKey)), deletionDate, fileLength: encryptedFile.length, file: { fileName: await seal(sendKey, "shared.txt") } }));
    await expectStatus(await f.fetch(pathOf(fileSend.url), { method: "PUT", body: encryptedFile }), 201);
    const shared = fileSend.sendResponse;
    const granted = await json(f.fetch(`/api/sends/${shared.id}/access/file/${shared.file.id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }));
    const sendResponse = await expectStatus(await f.fetch(pathOf(granted.url)), 200);
    assertDownloadSecurityHeaders(sendResponse, 'attachment; filename="send-file"');
    const bytes = decoder.decode(await sendResponse.arrayBuffer());
    equal(await open(sendKey, bytes), "Anonymous file bytes");
    equal((await sync(f, second)).sends.length, 2);
  });
}

async function runStorageChecks({ fixture, attachmentUploadFixture, check, ctx, sql, accessToken }) {
  const headers = async () => bearerJsonHeaders(await accessToken());
  const uploadCap = () => attachmentToken({ scope: "attachment.upload" });
  async function inertDownload(f, path, bytes, disposition) {
    for (const [method, range, status] of [["GET", null, 200], ["HEAD", null, 200], ["GET", "bytes=1-5", 206], ["HEAD", "bytes=1-5", 206], ["GET", "bytes=999-", 416]]) {
      const response = await f.fetch(path, { method, headers: range ? { Range: range } : {} });
      equal(response.status, status, `${method} ${range ?? "full"}`);
      assertDownloadSecurityHeaders(response, disposition);
      if (status === 206) equal(response.headers.get("Content-Range"), `bytes 1-5/${bytes.length}`);
      if (status === 416) equal(response.headers.get("Content-Range"), `bytes */${bytes.length}`);
      const expected = method === "HEAD" || status === 416 ? [] : status === 206 ? bytes.subarray(1, 6) : bytes;
      sameBytes(new Uint8Array(await response.arrayBuffer()), expected);
    }
  }

  await check("scheduled cleanup advances only affected revisions and drains deleted objects", async () => {
    const f = fixture();
    const old = "2020-01-01T00:00:00.000Z", future = "2090-01-01T00:00:00.000Z";
    const retained = "retained-cipher", staleUpload = "stale-upload", currentUpload = "current-upload";
    f.db.cipher.deleted_at = old;
    f.db.setRow("ciphers", retained, { ...f.db.cipher, id: retained, user_id: "other-owner", deleted_at: null });
    f.db.setRow("attachments_pending", staleUpload, { ...f.db.pending, id: staleUpload, cipher_id: retained, created_at: old });
    f.db.setRow("attachments_pending", currentUpload, { ...f.db.pending, id: currentUpload, cipher_id: retained, created_at: future });
    f.bucket.objects.set(`${retained}/${staleUpload}`, new Uint8Array([1]));
    sql.exec("UPDATE users SET updated_at=?", future);
    sql.exec("INSERT INTO global_domains_cache VALUES(1, 4000000000)");
    const runScheduled = () => new RustWorker(ctx, f.env).scheduled({ cron: "0 0 * * *", scheduledTime: Date.now() });
    await runScheduled();

    equal(f.db.cipher, null);
    ok(f.db.row("ciphers", retained), "cleanup removed a live cipher");
    equal(f.db.row("attachments_pending", staleUpload), null);
    ok(f.db.row("attachments_pending", currentUpload), "cleanup removed a current upload");
    equal(f.bucket.deleted.sort().join(","), [ATTACHMENT_KEY, `${retained}/${staleUpload}`].sort().join(","));
    equal(sql.exec("SELECT COUNT(*) AS n FROM storage_cleanup_jobs").one().n, 0);
    equal(Date.parse(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at), Date.parse(future) + 1);
    equal(sql.exec("SELECT updated_at FROM users WHERE id='other-owner'").one().updated_at, future);
  });
  await check("signed attachment GET preserves bytes and native R2 stream", async () => {
    const f = fixture();
    const response = await f.fetch(attachmentPath("download", await attachmentToken()), { headers: { Origin: ORIGIN } });
    equal(response.status, 200);
    equal(response.headers.get("Content-Length"), "6");
    assertDownloadSecurityHeaders(response);
    equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    equal(response.body, f.bucket.lastBody, "native download stream identity");
    sameBytes(new Uint8Array(await response.arrayBuffer()), [0, 1, 2, 3, 128, 255]);
  });
  await check("attachment HEAD and Range contracts", async () => {
    const f = fixture();
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
    for (const signed of [
      await attachmentToken({}, "wrong-secret"),
      await attachmentToken({ attachment_id: "other" }),
      await attachmentToken({ exp: 1 }),
      await attachmentToken({ scope: "attachment.upload" }),
    ]) {
      const f = fixture();
      equal((await f.fetch(attachmentPath("download", signed))).status, 401); equal(f.bucket.gets, 0);
    }
    const fUpload = attachmentUploadFixture();
    const downloadOnly = await attachmentToken({ scope: "attachment.download" });
    equal((await fUpload.fetch(attachmentPath("azure-upload", downloadOnly), { method: "PUT", body: byteStream(6) })).status, 401);
    const f = fixture(); f.db.cipher.user_id = "other-owner";
    equal((await f.fetch(attachmentPath("download", await attachmentToken()))).status, 404);
  });
  await check("attachment metadata rejects missing, foreign, deleted and organization ciphers", async () => {
    const headers = { Authorization: `Bearer ${await accessToken()}` };
    for (const [id, changes, status] of [
      ["missing-cipher", {}, 404],
      [CIPHER, { user_id: "other-owner" }, 404],
      [CIPHER, { deleted_at: NOW }, 400],
      [CIPHER, { organization_id: "organization" }, 400],
    ]) {
      const f = fixture();
      Object.assign(f.db.cipher, changes);
      for (const method of ["GET", "DELETE"]) {
        const response = await f.fetch(`/api/ciphers/${id}/attachment/${FILE}`, { method, headers });
        equal(response.status, status, await response.text());
      }
      ok(f.db.attachment, "rejected request removed attachment metadata");
      ok(f.bucket.objects.has(ATTACHMENT_KEY), "rejected request removed the object");
    }
  });
  await check("both attachment upload routes publish bytes and notify the committed revision", async () => {
    for (const useCapability of [true, false]) {
      const f = attachmentUploadFixture();
      const future = "2099-01-01T00:00:00.000Z";
      sql.exec("UPDATE users SET updated_at=? WHERE id=?", future, USER);
      const messages = captureNotifications(f);
      let response;
      if (useCapability) {
        response = await f.fetch(attachmentPath("azure-upload", await uploadCap()), { method: "PUT", body: byteStream(6), headers: { Origin: ORIGIN } });
        equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
      } else {
        const form = new FormData();
        form.append("data", new Blob(["sample"]), "encrypted-name");
        response = await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, {
          method: "POST", body: form, headers: { Authorization: `Bearer ${await accessToken()}` },
        });
      }
      equal(response.status, useCapability ? 201 : 200, await response.text());
      equal(f.db.pending, null);
      sameBytes(f.bucket.objects.get(f.db.attachment.storage_key), useCapability ? [0, 1, 2, 3, 4, 5] : encoder.encode("sample"));
      equal(messages.length, 1);
    }
  });
  await check("R2 multipart streaming, interrupted stream abort, and inert MIME download headers", async () => {
    const f = attachmentUploadFixture(); const size = 8 * 1024 * 1024 + 257; f.db.pending.file_size_bytes = size;
    equal((await f.fetch(attachmentPath("azure-upload", await uploadCap()), { method: "PUT", body: byteStream(size), headers: { "Content-Type": "text/html" } })).status, 201);
    equal(f.bucket.completed, 1);
    const bytes = f.bucket.objects.get(f.db.attachment.storage_key); equal(bytes.length, size);
    const response = await f.fetch(attachmentPath("download", await attachmentToken()));
    assertDownloadSecurityHeaders(response); equal(response.body, f.bucket.lastBody);
    sameBytes(new Uint8Array(await response.arrayBuffer()), bytes);

    const fAbort = attachmentUploadFixture(); fAbort.db.pending.file_size_bytes = 10 * 1024 * 1024;
    const aborted = await fAbort.fetch(attachmentPath("azure-upload", await uploadCap()), { method: "PUT", body: byteStream(8 * 1024 * 1024 + 131072, true) });
    equal(aborted.status, 400);
    equal((await aborted.json()).message, "Invalid request: Invalid upload body");
    equal(fAbort.bucket.aborted, 1); ok(fAbort.db.pending);

    const htmlBytes = encoder.encode("<html>harmless file</html>");
    const fSend = fixture(); fSend.db.send.upload_state = 1; fSend.db.send.file_size_bytes = htmlBytes.length;
    equal((await fSend.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", headers: { "Content-Type": "text/html; charset=utf-8" }, body: htmlBytes })).status, 201);
    await inertDownload(fSend, `/api/sends/${SEND}/${FILE}?t=${await sendToken()}`, htmlBytes, 'attachment; filename="send-file"');
  });
  await check("disabled, pending and rotated Sends revoke outstanding download capabilities", async () => {
    for (const patch of [{ is_disabled: 1 }, { upload_state: 1 }, { access_stamp: "rotated" }, { deletes_at: NOW }]) {
      const f = fixture(); Object.assign(f.db.send, patch);
      equal((await f.fetch(`/api/sends/${SEND}/${FILE}?t=${await sendToken()}`)).status, 404); equal(f.bucket.gets, 0);
    }
  });
  await check("Send upload enforces live session, exact fileLength, and multipart size above 2MiB", async () => {
    const fRevoked = fixture(); fRevoked.db.send.upload_state = 1; fRevoked.db.sessionValid = false;
    equal((await fRevoked.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(6) })).status, 401);

    const fShort = fixture(); fShort.db.send.upload_state = 1;
    const path = `/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`;
    await expectStatus(await fShort.fetch(path, { method: "PUT", body: byteStream(5) }), 400);
    await expectStatus(await fShort.fetch(path, { method: "PUT", body: byteStream(6) }), 201);

    const size = 3 * 1024 * 1024 + 17;
    const fMulti = fixture(); fMulti.db.send.upload_state = 1; fMulti.db.send.file_size_bytes = size;
    const form = new FormData();
    form.append("data", new Blob([new Uint8Array(size).fill(173)]), "encrypted");
    equal((await fMulti.fetch(`/api/sends/${SEND}/file/${FILE}`, { method: "POST", body: form, headers: { Authorization: `Bearer ${await accessToken()}` } })).status, 201);
  });
  await check("attachment delete aliases retain ownership checks, remove objects, and retry queued deletions", async () => {
    for (const method of ["POST", "DELETE"]) {
      const f = fixture();
      const path = `/api/ciphers/${CIPHER}/attachment/${FILE}${method === "POST" ? "/delete" : ""}`;
      const foreign = await accessToken({ sub: "other-owner", sstamp: "other" });
      sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('other-owner','device','other',0,'session',?,?)", NOW, NOW);
      await expectJsonOrEmpty(await f.fetch(path, { method, headers: { Authorization: `Bearer ${foreign}` } }), 404);
      await expectJsonOrEmpty(await f.fetch(path, { method, headers: await headers() }), 200);
      equal(f.bucket.objects.has(ATTACHMENT_KEY), false);
    }

    const fRetry = fixture(); fRetry.db.pending = null;
    sql.exec("DELETE FROM storage_cleanup_jobs");
    const removeObjects = fRetry.bucket.delete.bind(fRetry.bucket);
    fRetry.bucket.delete = async () => { throw new Error("simulated R2 deletion outage"); };
    await expectJsonOrEmpty(await fRetry.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { method: "DELETE", headers: await headers() }), 200);
    equal(sql.exec("SELECT object_key FROM storage_cleanup_jobs").one().object_key, ATTACHMENT_KEY);
    fRetry.bucket.delete = removeObjects;
    sql.exec("INSERT INTO global_domains_cache VALUES(1,4000000000)");
    await new RustWorker(ctx, fRetry.env).scheduled({ cron: "0 0 * * *", scheduledTime: Date.now() });
    equal(fRetry.bucket.objects.has(ATTACHMENT_KEY), false);
    equal(sql.exec("SELECT COUNT(*) AS n FROM storage_cleanup_jobs").one().n, 0);
  });
  await check("concurrent attachment uploads, quota enforcement, and ready attachment replacement", async () => {
    const fRace = attachmentUploadFixture(); const put = fRace.bucket.put.bind(fRace.bucket);
    let entered = 0, release; const ready = new Promise(resolve => { release = resolve; });
    fRace.bucket.put = async (...args) => { const object = await put(...args); if (++entered === 1) await ready; else release(); return object; };
    const path = attachmentPath("azure-upload", await uploadCap());
    const responses = await Promise.all([1, 2].map(() => fRace.fetch(path, { method: "PUT", body: byteStream(6) })));
    equal(responses.map(r => r.status).sort().join(","), "201,400");
    sameBytes(fRace.bucket.objects.get(fRace.db.attachment.storage_key), [0, 1, 2, 3, 4, 5]);

    const fQuota = attachmentUploadFixture();
    fQuota.env.ATTACHMENT_TOTAL_LIMIT_KB = "1";
    await expectJsonOrEmpty(await fQuota.fetch(`/api/ciphers/${CIPHER}/attachment/v2`, {
      method: "POST", headers: await headers(),
      body: JSON.stringify({ key: "wrapped-key", fileName: "encrypted-name", fileSize: 600 }),
    }), 200);
    fQuota.db.pending.file_size_bytes = 425;
    equal((await fQuota.fetch(attachmentPath("azure-upload", await uploadCap()), { method: "PUT", body: byteStream(424) })).status, 400);
    fQuota.db.pending.file_size_bytes = 424;
    equal((await fQuota.fetch(attachmentPath("azure-upload", await uploadCap()), { method: "PUT", body: byteStream(424) })).status, 201);

    const fReplace = fixture(); fReplace.db.pending = null;
    const form = new FormData();
    form.append("data", new Blob(["replacement bytes"]), "encrypted-name");
    form.append("key", "replacement-wrapped-key");
    await expectJsonOrEmpty(await fReplace.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, {
      method: "POST", headers: { Authorization: `Bearer ${await accessToken()}` }, body: form,
    }), 200);
    equal(fReplace.bucket.objects.has(ATTACHMENT_KEY), false);
    equal(new TextDecoder().decode(fReplace.bucket.objects.get(fReplace.db.attachment.storage_key)), "replacement bytes");
  });
}
