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
  DurableObjectNamespace,
  FILE,
  KvNamespace,
  NOW,
  ORIGIN,
  SEND,
  SEND_KEY,
  USER,
  attachmentPath,
  attachmentToken,
  byteStream,
  encoder,
  sendToken,
} from "./runtime-fixture.mjs";
import RustWorker from "./index.js";

export async function runVaultTests(context) {
  await runVaultChecks(context);
  await runPersonalVaultChecks(context);
  await runStorageChecks(context);
}

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
      if (status === 500) equal(result.message, "Internal server error");
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
      await expectJsonOrEmpty(await f.fetch("/api/sync?excludeDomains=true", { headers: await headers() }), status);
      ok(changed, "fixture did not change data after the snapshot read");
    }
  });
  await check("byte-bounded Cipher pages and separately batched attachments preserve complete projections", async () => {
    const f = fixture(); const blob = JSON.stringify({ format_version: 2, data: "x".repeat(450000) });
    for (let i = 0; i < 10; i++) sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,?,8,?,?,?)", `large-${i}`, USER, JSON.stringify({ name: "", data: blob }), NOW, NOW);
    const encryptedName = "x".repeat(19000);
    for (let i = 0; i < 110; i++) sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?)", `large-file-${i}`, CIPHER, encryptedName, 6, NOW, NOW);
    const execute = f.db.execute.bind(f.db);
    let cipherPages = 0, attachmentPages = 0;
    f.db.execute = (query, params) => {
      const result = execute(query, params);
      if (query.startsWith("WITH filtered") && query.includes("FROM ciphers WHERE")) {
        cipherPages++;
        ok(result.results.reduce((bytes, row) => bytes + row.data.length, 0) < 4000000, "Cipher D1 page exceeds byte budget");
      }
      if (query.startsWith("WITH filtered") && query.includes("FROM attachments WHERE")) attachmentPages++;
      ok(!query.includes("json_group_array"), "list must not aggregate an entire attachment set in D1");
      return result;
    };
    for (const [path, name] of [["/api/ciphers", "data"], ["/api/sync?excludeDomains=true", "ciphers"]]) {
      const start = cipherPages;
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
      equal(cipherPages - start, 2);
    }
    ok(attachmentPages >= 2, "projection did not load separate attachment rows");
  });
  await check("Excessive single-Cipher attachment metadata returns a complete 413 error", async () => {
    const f = fixture(), name = "x".repeat(1000000);
    for (let i = 0; i < 17; i++) sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?)", `oversized-file-${i}`, CIPHER, name, 6, NOW, NOW);
    const response = await expectJsonOrEmpty(await f.fetch("/api/ciphers", { headers: await headers() }), 413);
    ok(JSON.stringify(response).includes("Cipher attachment metadata exceeds the server size limit"), "missing size rejection");
    equal(response.data, null);

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
  await check("Cipher keyset pages preserve equal-revision ties and reject a concurrent revision change", async () => {
    const f = fixture();
    for (let i = 0; i < 205; i++) {
      sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,?,1,?,?,?)", `small-${i}`, USER, '{"name":"encrypted"}', NOW, NOW);
    }
    const path = "/api/ciphers";
    const expected = sql.exec("SELECT id FROM ciphers WHERE user_id=? ORDER BY updated_at DESC, rowid", USER).toArray().map(row => row.id);
    const listing = await expectJsonOrEmpty(await f.fetch(path, { headers: await headers() }), 200);
    equal(JSON.stringify(listing.data.map(row => row.id)), JSON.stringify(expected));
    for (const endpoint of [path, "/api/sync?excludeDomains=true"]) {
      const execute = f.db.execute.bind(f.db);
      let reads = 0;
      f.db.execute = (query, params) => {
        const result = execute(query, params);
        if (query.startsWith("WITH filtered") && query.includes("FROM ciphers WHERE") && ++reads === 1) {
          const revision = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
          const changedAt = new Date(Date.parse(revision) + 1).toISOString();
          sql.exec("UPDATE ciphers SET data=?,updated_at=? WHERE id='small-204'", '{"name":"concurrent"}', changedAt);
          sql.exec("UPDATE users SET updated_at=? WHERE id=?", changedAt, USER);
        }
        return result;
      };
      await expectJsonOrEmpty(await f.fetch(endpoint, { headers: await headers() }), 409);
      equal(reads, 2);
      f.db.execute = execute;
    }
  });
  await check("Cipher attachment key updates use one scoped read and retain snapshot guards", async () => {
    const f = fixture(), updates = {};
    for (let i = 0; i < 55; i++) {
      const id = `rotate-${i}`;
      sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", id, CIPHER, "old-name", 6, "old-key", NOW, NOW);
      updates[id] = { fileName: "rotated-name", key: "rotated-key" };
    }
    const other = "not-selected-cipher";
    sql.exec("INSERT INTO ciphers(id,user_id,cipher_type,data,created_at,updated_at) VALUES(?,?,1,?,?,?)", other, USER, '{"name":"encrypted"}', NOW, NOW);
    sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", "other-attachment", other, "old-name", 6, "old-key", NOW, NOW);
    updates["other-attachment"] = { fileName: "not-applied", key: "not-applied" };
    const call = async () => f.fetch(`/api/ciphers/${CIPHER}`, { method: "PUT", headers: await headers(), body: JSON.stringify({type: 1, name: "updated", login: {}, attachments2: updates}) });
    const readUpdates = sql => sql.startsWith("WITH filtered") && sql.includes("FROM attachments WHERE") && sql.includes("AND id IN");
    await expectJsonOrEmpty(await call(), 200);
    equal(f.db.queries.filter(readUpdates).length, 1);
    equal(sql.exec("SELECT COUNT(*) AS n FROM attachments WHERE encrypted_key='rotated-key'").one().n, 55);
    equal(f.db.row("attachments", "other-attachment").encrypted_key, "old-key");

    updates["rotate-0"] = { fileName: "race", key: "race" };
    const execute = f.db.execute.bind(f.db);
    let changed = false;
    f.db.execute = (query, params) => {
      const result = execute(query, params);
      if (!changed && readUpdates(query)) {
        changed = true;
        sql.exec("UPDATE attachments SET encrypted_key='concurrent-key' WHERE id='rotate-0'");
      }
      return result;
    };
    await expectJsonOrEmpty(await call(), 400);
    ok(changed, "fixture did not change the attachment after the selected rows were read");
    equal(f.db.row("attachments", "rotate-0").encrypted_key, "concurrent-key");
  });
  await check("unreadable stored cipher JSON fails GET and list without fabricating empty items", async () => {
    const f = fixture(); f.db.cipher.data = "{unreadable";
    await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}`, { headers: await headers() }), 500);
    await expectJsonOrEmpty(await f.fetch("/api/ciphers", { headers: await headers() }), 500);
  });
  await check("move and soft delete do not decode stored cipher payloads", async () => {
    for (const bulk of [false, true]) {
      const f = fixture();
      f.db.cipher.data = "{unreadable";
      if (bulk) {
        const folder = "target-folder";
        sql.exec("INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES(?,?,?,?,?)", folder, USER, "encrypted", NOW, NOW);
        const moved = await f.fetch("/api/ciphers/move", {
          method: "PUT", headers: await headers(), body: JSON.stringify({ ids: [CIPHER], folderId: folder }),
        });
        equal(await expectJsonOrEmpty(moved, 200), null);
        equal(f.db.cipher.folder_id, folder);
      }
      const deleted = await f.fetch(bulk ? "/api/ciphers/delete" : `/api/ciphers/${CIPHER}/delete`, {
        method: "PUT", headers: await headers(),
        ...(bulk ? { body: JSON.stringify({ ids: [CIPHER] }) } : {}),
      });
      equal(await expectJsonOrEmpty(deleted, 200), null);
      ok(f.db.cipher.deleted_at, "soft delete did not move the cipher to trash");
      equal(f.db.cipher.data, "{unreadable");
    }
  });
  await check("single and bulk hard delete remove unreadable ciphers after checking ownership", async () => {
    for (const bulk of [false, true]) {
      const f = fixture();
      const other = "other-cipher";
      f.db.setRow("ciphers", other, { ...f.db.cipher, id: other, user_id: "other-owner" });
      f.db.cipher.data = "{unreadable";
      const auth = await headers();
      const remove = (id, ids) => f.fetch(ids ? "/api/ciphers" : `/api/ciphers/${id}`, {
        method: "DELETE", headers: auth,
        ...(ids ? { body: JSON.stringify({ ids }) } : {}),
      });
      await expectJsonOrEmpty(await remove(other, bulk ? [CIPHER, other] : null), 400);
      ok(f.db.cipher, "rejected selection removed the owned cipher");
      equal(await expectJsonOrEmpty(await remove(CIPHER, bulk ? [CIPHER] : null), 200), null);
      equal(f.db.cipher, null);
      ok(f.db.row("ciphers", other), "hard delete removed another owner's cipher");
      ok(f.bucket.deleted.includes(ATTACHMENT_KEY), "hard delete did not remove the attachment");
    }
  });
  await check("cipher encryption contexts reject other users and stale IDs while preserving legacy matching IDs", async () => {
    const f = fixture(); const current = "0123456789abcdef0123456789abcdef";
    sql.exec("UPDATE users SET user_key_id=? WHERE id=?", current, USER);
    await save(f, payload({ encryptedFor: USER, encryptedByKeyId: current }));
    await expectJsonOrEmpty(await f.fetch("/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(payload({ encryptedByKeyId: "ffffffffffffffffffffffffffffffff" })) }), 409);
    await expectJsonOrEmpty(await f.fetch("/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(payload({ encryptedFor: "other-owner" })) }), 400);
    const legacy = "00000000-0000-4000-8000-000000000099";
    sql.exec("UPDATE users SET user_key_id=? WHERE id=?", legacy, USER);
    await save(f, payload({ encryptedByKeyId: legacy }));
    await expectJsonOrEmpty(await f.fetch("/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(payload({ collectionIds: ["unsupported"] })) }), 400);
  });
  await check("cipher save and import reuse one account snapshot and guard it at commit", async () => {
    for (const importing of [false, true]) {
      const f = fixture();
      const keyId = "0123456789abcdef0123456789abcdef";
      sql.exec("UPDATE users SET user_key_id=? WHERE id=?", keyId, USER);
      const before = f.db.cipher.data;
      const changed = f.db.beforeNextBatch(
        statements => statements.some(statement => statement.sql.startsWith("UPDATE users SET updated_at")),
        () => sql.exec("UPDATE users SET user_key_id=? WHERE id=?", "ffffffffffffffffffffffffffffffff", USER),
      );
      const cipher = payload({ encryptedByKeyId: keyId, name: "blocked-by-account-change" });
      const response = await f.fetch(importing ? "/api/ciphers/import" : `/api/ciphers/${CIPHER}`, {
        method: "POST", headers: await headers(),
        body: JSON.stringify(importing ? { folders: [], ciphers: [cipher] } : cipher),
      });
      await expectJsonOrEmpty(response, 400);
      ok(changed(), "test did not reach the commit after validating the key ID");
      equal(f.db.queries.filter(query => query.startsWith("SELECT key,user_key_id,")).length, 1);
      ok(!f.db.queries.some(query => query.startsWith("SELECT user_key_id FROM users")), "key ID was fetched again");
      equal(f.db.cipher.data, before);
      equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 1);
    }
  });
  await check("same-revision concurrent cipher edits have one transaction winner", async () => {
    const f = fixture(); const batch = f.db.batch.bind(f.db);
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
    const f = fixture(); const before = f.db.cipher.data;
    sql.exec("CREATE TRIGGER reject_vault_cursor BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT,'runtime cursor failure'); END");
    await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}`, { method: "POST", headers: await headers(), body: JSON.stringify(payload({ name: "must-rollback" })) }), 500);
    equal(f.db.cipher.data, before);
  });
  await check("attachments2 changes are atomic and response metadata matches the saved keys", async () => {
    const f = fixture();
    const response = await save(f, payload({ attachments2: { [FILE]: { fileName: "new-encrypted-name", key: "new-wrapped-key" }, missing: { fileName: "gone", key: "gone" } } }), CIPHER);
    equal(f.db.attachment.file_name, "new-encrypted-name"); equal(f.db.attachment.encrypted_key, "new-wrapped-key");
    equal(response.attachments[0].fileName, "new-encrypted-name"); equal(response.attachments[0].key, "new-wrapped-key");
    equal(response.attachments[0].url, `https://vault.test/attachments/${CIPHER}/${FILE}`);
  });
  await check("attachments2 continues after a same-owner attachment on a different cipher", async () => {
    const f = fixture();
    const secondFile = "second-file", otherCipher = "other-owned-cipher";
    f.db.setRow("ciphers", otherCipher, { ...f.db.cipher, id: otherCipher });
    f.db.setRow("attachments", secondFile, { ...f.db.attachment, id: secondFile });
    const execute = f.db.execute.bind(f.db);
    const ignored = FILE;
    let moved = false;
    f.db.execute = (query, params) => {
      if (!moved && query.startsWith("WITH filtered") && query.includes("FROM attachments WHERE cipher_id=? AND id IN")) {
        moved = true;
        sql.exec("UPDATE attachments SET cipher_id=? WHERE id=?", otherCipher, ignored);
      }
      return execute(query, params);
    };
    const update = { fileName: "new-encrypted-name", key: "new-wrapped-key" };
    const response = await save(f, payload({ attachments2: { [FILE]: update, [secondFile]: update } }), CIPHER);
    ok(moved, "no attachment was attached to the other cipher");
    const updated = secondFile;
    equal(f.db.row("attachments", ignored).encrypted_key, "encrypted-key");
    equal(f.db.row("attachments", updated).file_name, update.fileName);
    equal(f.db.row("attachments", updated).encrypted_key, update.key);
    equal(response.attachments.length, 1);
    equal(response.attachments[0].id, updated);
    equal(response.attachments[0].key, update.key);
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

    const token = await attachmentToken();
    const fileOperations = async status => {
      await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, auth), status);
      await expectJsonOrEmpty(await f.fetch(attachmentPath("download", token)), status);
      await expectJsonOrEmpty(await f.fetch(attachmentPath("azure-upload", token), { method: "PUT", body: byteStream(6) }), status);
    };
    const fallback = new KvNamespace();
    f.env.ATTACHMENTS_BUCKET = {};
    f.env.ATTACHMENTS_KV = fallback;
    equal(JSON.stringify(await metadata()), JSON.stringify(expected), "malformed R2 with configured KV");
    await fileOperations(500);
    equal(fallback.gets + fallback.puts, 0, "invalid R2 must not use the fallback");

    delete f.env.ATTACHMENTS_BUCKET;
    f.env.ATTACHMENTS_KV = { get() {} };
    equal(JSON.stringify(await metadata()), JSON.stringify(expected), "malformed KV");
    await fileOperations(500);

    delete f.env.ATTACHMENTS_KV;
    for (const attachments of await metadata()) equal(attachments, null);
    await fileOperations(400);
    equal(f.db.row("users", USER).updated_at, revision);
    equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages").one().n, 0);
  });
  await check("import clears source organization/folder IDs and publishes every bounded chunk atomically", async () => {
    const f = fixture();
    const body = { folders: [{ id: "source-folder", name: "encrypted-folder" }], ciphers: Array.from({ length: 220 }, (_, i) => payload({ name: `encrypted-${i}`, organizationId: "source-organization", folderId: "source-vault-folder", archivedDate: i === 0 ? NOW : null })), folderRelationships: [{ key: 0, value: 0 }] };
    await expectJsonOrEmpty(await f.fetch("/api/ciphers/import", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 221); equal(f.db.batches, 1);
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
    return { f, first, second, userKey, wrapping, authentication };
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

async function runStorageChecks({ fixture, attachmentUploadFixture, kvFixture, check, ctx, sql, accessToken }) {
  const headers = async () => bearerJsonHeaders(await accessToken());
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
  await check("attachment metadata treats foreign and missing attachment IDs alike", async () => {
    const f = fixture(), foreignCipher = "foreign-cipher";
    f.db.setRow("ciphers", foreignCipher, { ...f.db.cipher, id: foreignCipher, user_id: "other-owner" });
    f.db.attachment.cipher_id = foreignCipher;
    const headers = { Authorization: `Bearer ${await accessToken()}` };
    for (const [method, suffix] of [["GET", ""], ["DELETE", ""], ["POST", "/delete"]]) {
      const bodies = [];
      for (const file of [FILE, "missing-attachment"]) {
        const response = await f.fetch(`/api/ciphers/${CIPHER}/attachment/${file}${suffix}`, { method, headers });
        const body = await response.text();
        equal(response.status, 404, body);
        bodies.push(body);
      }
      equal(bodies[0], bodies[1], "attachment not-found responses");
    }
    equal(f.db.attachment.cipher_id, foreignCipher);
    ok(f.bucket.objects.has(ATTACHMENT_KEY), "rejected request removed the object");
  });
  await check("Azure attachment PUT streams and atomically publishes metadata", async () => {
    const f = attachmentUploadFixture();
    const response = await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6), headers: { Origin: ORIGIN } });
    equal(response.status, 201, await response.clone().text()); equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    sameBytes(f.bucket.objects.get(f.db.attachment.storage_key), [0, 1, 2, 3, 4, 5]); equal(f.db.pending, null); equal(f.db.batches, 1);
  });
  await check("attachment uploads publish the committed revision for both authorization paths", async () => {
    for (const useCapability of [true, false]) {
      const f = attachmentUploadFixture();
      const future = "2099-01-01T00:00:00.000Z";
      sql.exec("UPDATE users SET updated_at=? WHERE id=?", future, USER);
      const messages = [];
      f.env.notifydo = new DurableObjectNamespace(async request => {
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
    const f = attachmentUploadFixture(); f.db.failBatch = true;
    equal((await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) })).status, 500);
    equal(f.bucket.objects.has(ATTACHMENT_KEY), false); ok(f.bucket.deleted.some(key => key.startsWith(`attachments/${CIPHER}/${FILE}/`)), "failed staged object was not deleted"); ok(f.db.pending, "pending metadata was removed on failure");
  });
  await check("R2 multipart accepts a streamed file beyond Axum's default body limit", async () => {
    const f = attachmentUploadFixture(); const size = 8 * 1024 * 1024 + 257; f.db.pending.file_size_bytes = size;
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
    const f = attachmentUploadFixture(); f.db.pending.file_size_bytes = 10 * 1024 * 1024;
    equal((await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(8 * 1024 * 1024 + 131072, true) })).status, 400);
    equal(f.bucket.created, 1); equal(f.bucket.aborted, 1); equal(f.bucket.uploads.size, 0); equal(f.bucket.objects.has(ATTACHMENT_KEY), false); ok(f.db.pending, "pending reservation was not preserved");
  });
  await check("interrupted Send and attachment uploads keep runtime details out of public errors", async () => {
    for (const [kind, backend] of [["attachment", "r2"], ["attachment", "kv"], ["send", "r2"], ["send", "kv"]]) {
      const f = kind === "attachment"
        ? (backend === "r2" ? attachmentUploadFixture() : kvFixture(true))
        : (backend === "r2" ? fixture() : kvFixture());
      const path = kind === "attachment"
        ? attachmentPath("azure-upload", await attachmentToken())
        : `/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`;
      if (kind === "send") f.db.send.upload_state = 1;
      const response = await f.fetch(path, { method: "PUT", body: byteStream(3, true) });
      equal(response.status, 400, `${kind} ${backend}`);
      const error = await response.json();
      equal(error.code, 5);
      equal(error.message, "Invalid request: Invalid upload body");
    }
  });
  await check("Send GET, HEAD and Range use the compiled Rust routes", async () => {
    const f = fixture(); const path = `/api/sends/${SEND}/${FILE}?t=${await sendToken()}`;
    const disposition = 'attachment; filename="send-file"';
    const head = await f.fetch(path, { method: "HEAD" }); equal(head.status, 200); assertDownloadSecurityHeaders(head, disposition); equal(head.headers.get("Content-Length"), "6"); equal((await head.arrayBuffer()).byteLength, 0);
    const response = await f.fetch(path, { headers: { Range: "bytes=2-4" } }); equal(response.status, 206); assertDownloadSecurityHeaders(response, disposition); sameBytes(new Uint8Array(await response.arrayBuffer()), [2, 3, 128]);
  });
  await check("disabled, pending and rotated Sends revoke outstanding download capabilities", async () => {
    for (const patch of [{ is_disabled: 1 }, { upload_state: 1 }, { access_stamp: "rotated" }, { deletes_at: NOW }]) {
      const f = fixture(); Object.assign(f.db.send, patch);
      equal((await f.fetch(`/api/sends/${SEND}/${FILE}?t=${await sendToken()}`)).status, 404); equal(f.bucket.gets, 0);
    }
  });
  await check("Send Azure upload validates the session and finalizes metadata once", async () => {
    const f = fixture(); f.db.send.upload_state = 1;
    equal((await f.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(6) })).status, 201);
    equal(f.db.send.upload_state, 0); sameBytes(f.bucket.objects.get(f.db.send.storage_key), [0, 1, 2, 3, 4, 5]); equal(f.db.batches, 1);
  });
  await check("revoked Send upload session rejects before reserving or storing bytes", async () => {
    const f = fixture(); f.db.send.upload_state = 1; f.db.sessionValid = false;
    let puts = 0;
    f.bucket.afterPut = () => { puts++; };
    equal((await f.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(6) })).status, 401);
    equal(f.db.send.upload_state, 1);
    equal(f.db.queries.some(query => query.includes("INSERT INTO storage_upload_stages")), false);
    equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages").one().n, 0);
    equal(puts, 0, "no staged object was written");
    equal(f.bucket.created, 0, "no multipart upload was opened");
  });
  await check("session revocation during Send upload prevents publication and cleans the object", async () => {
    const f = fixture(); f.db.send.upload_state = 1; f.bucket.afterPut = () => { f.db.sessionValid = false; };
    equal((await f.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(6) })).status, 401);
    equal(f.db.send.upload_state, 1); sameBytes(f.bucket.objects.get(SEND_KEY), [0, 1, 2, 3, 128, 255]); ok(f.bucket.deleted.some(key => key.startsWith(`${SEND_KEY}/`)), "revoked staged upload was not cleaned");
  });
  await check("short Send upload cleans the object and unlocks its reservation for retry", async () => {
    const f = fixture(); f.db.send.upload_state = 1;
    equal((await f.fetch(`/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`, { method: "PUT", body: byteStream(5) })).status, 400);
    equal(f.db.send.upload_state, 1); sameBytes(f.bucket.objects.get(SEND_KEY), [0, 1, 2, 3, 128, 255]); ok(f.bucket.deleted.some(key => key.startsWith(`${SEND_KEY}/`)), "failed Send staged object was not cleaned");
  });
  await check("Axum Multipart accepts a Send file above 2MiB and rejects trailing fields before publication", async () => {
    const size = 3 * 1024 * 1024 + 17;
    for (const extra of [false, true]) {
      const f = fixture(); f.db.send.upload_state = 1; f.db.send.file_size_bytes = size;
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
    const f = kvFixture();
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
    const f = kvFixture(true); const signed = await attachmentToken();
    equal((await f.fetch(attachmentPath("azure-upload", signed), { method: "PUT", body: byteStream(6), headers: { "Content-Type": "application/x-encrypted" } })).status, 201);
    const object = f.kv.objects.get(f.db.attachment.storage_key); sameBytes(new Uint8Array(object.value), [0, 1, 2, 3, 4, 5]); equal(object.metadata.size, 6); equal(object.metadata.httpMetadata.contentType, "application/x-encrypted");
    const response = await f.fetch(attachmentPath("download", signed)); equal(response.status, 200); assertDownloadSecurityHeaders(response); sameBytes(new Uint8Array(await response.arrayBuffer()), [0, 1, 2, 3, 4, 5]);
  });
  await check("R2 and KV historical document MIME metadata cannot make attachments or Sends executable", async () => {
    const bytes = encoder.encode("<html>harmless historical file</html>");
    for (const backend of ["R2", "KV"]) {
      for (const kind of ["attachment", "send"]) {
        const f = backend === "KV" ? kvFixture() : fixture();
        const key = kind === "attachment" ? ATTACHMENT_KEY : SEND_KEY;
        if (backend === "KV") f.kv.objects.set(key, { value: bytes.buffer, metadata: { size: bytes.length, httpMetadata: { contentType: "text/html; charset=utf-8" } } });
        else { f.bucket.objects.set(key, bytes); f.bucket.httpMetadata.set(key, { contentType: "text/html; charset=utf-8" }); }
        let path;
        if (kind === "attachment") {
          f.db.attachment.file_name = 'encrypted-name"; unsafe="ignored';
          const metadata = await expectJson(
            await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { headers: await headers() }),
            200, "attachment metadata",
          );
          const url = new URL(metadata.url);
          path = url.pathname + url.search;
        } else {
          path = `/api/sends/${SEND}/${FILE}?t=${await sendToken()}`;
        }
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
        const f = backend === "KV" ? kvFixture(kind === "attachment") : kind === "attachment" ? attachmentUploadFixture() : fixture();
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
    const f = kvFixture(true); const maximum = 25 * 1024 * 1024; f.db.pending.file_size_bytes = maximum;
    const response = await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(maximum + 1) });
    equal(response.status, 400); equal(f.kv.puts, 0); equal(f.kv.objects.has(ATTACHMENT_KEY), false); equal(f.db.batches, 0); ok(f.db.pending, "oversized upload removed its pending reservation");
  });
  await check("attachment delete aliases retain ownership checks and remove adopted objects", async () => {
    for (const method of ["POST", "DELETE"]) {
      const f = fixture();
      const path = `/api/ciphers/${CIPHER}/attachment/${FILE}${method === "POST" ? "/delete" : ""}`;
      const foreign = await accessToken({ sub: "other-owner", sstamp: "other" });
      sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES('other-owner','device','other',0,'session',?,?)", NOW, NOW);
      await expectJsonOrEmpty(await f.fetch(path, { method, headers: { Authorization: `Bearer ${foreign}` } }), 404);
      ok(f.bucket.objects.has(ATTACHMENT_KEY), "unauthorized delete removed the object");
      await expectJsonOrEmpty(await f.fetch(path, { method, headers: await headers() }), 200);
      equal(sql.exec("SELECT count(*) AS n FROM attachments WHERE id=?", FILE).one().n, 0);
      equal(f.bucket.objects.has(ATTACHMENT_KEY), false);
    }
    const f = fixture();
    for (const path of ["trusted", "granted"]) {
      const body = await expectJsonOrEmpty(await f.fetch(`/api/emergency-access/${path}`), 200);
      equal(body.object, "list"); equal(body.data.length, 0);
    }
  });

  await check("invalid storage bindings reject downloads and never acknowledge cleanup against the fallback", async () => {
    const f = fixture();
    const path = attachmentPath("download", await attachmentToken());
    const kv = new KvNamespace();
    f.env.ATTACHMENTS_BUCKET = {};
    f.env.ATTACHMENTS_KV = kv;
    const r2Error = await expectJsonOrEmpty(await f.fetch(path), 500);
    equal(r2Error.code, 0);
    equal(kv.gets, 0, "KV must not mask an invalid R2 binding");

    delete f.env.ATTACHMENTS_BUCKET;
    f.env.ATTACHMENTS_KV = { get() {} };
    const kvError = await expectJsonOrEmpty(await f.fetch(path), 500);
    equal(kvError.code, 0);
    delete f.env.ATTACHMENTS_KV;
    await expectJsonOrEmpty(await f.fetch(path), 400);

    f.env.ATTACHMENTS_BUCKET = {};
    f.env.ATTACHMENTS_KV = kv;
    await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { method: "DELETE", headers: await headers() }), 200);
    equal(kv.deleted.length, 0);
    ok(f.bucket.objects.has(ATTACHMENT_KEY), "malformed R2 must not acknowledge object deletion");
    equal(sql.exec("SELECT object_key FROM storage_cleanup_jobs").one().object_key, ATTACHMENT_KEY);

    f.env.ATTACHMENTS_BUCKET = f.bucket;
    sql.exec("INSERT INTO global_domains_cache VALUES(1,4000000000)");
    await new RustWorker(ctx, f.env).scheduled({ cron: "0 0 * * *", scheduledTime: Date.now() });
    equal(f.bucket.objects.has(ATTACHMENT_KEY), false);
    equal(sql.exec("SELECT count(*) AS n FROM storage_cleanup_jobs").one().n, 0);
  });
  await check("failed object deletion retains cleanup jobs and a later operation retries them", async () => {
    const f = fixture(); f.db.pending = null;
    sql.exec("DELETE FROM storage_cleanup_jobs");
    const removeObjects = f.bucket.delete.bind(f.bucket);
    let failed = false;
    f.bucket.delete = async () => { failed = true; throw new Error("simulated R2 deletion outage"); };
    await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { method: "DELETE", headers: await headers() }), 200);
    ok(failed, "attachment deletion did not reach the failing storage backend");
    equal(f.db.attachment, null, "metadata deletion should remain committed");
    sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
    equal(sql.exec("SELECT object_key FROM storage_cleanup_jobs").one().object_key, ATTACHMENT_KEY, "failed deletion must remain queued");

    const second = "00000000-0000-4000-8000-000000000005", secondKey = `${CIPHER}/${second}`;
    sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at) VALUES(?,?,'second-file',3,'encrypted-key',?,?)", second, CIPHER, NOW, NOW);
    f.bucket.objects.set(secondKey, new Uint8Array([10, 20, 30]));
    f.bucket.delete = removeObjects;
    await expectJsonOrEmpty(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${second}`, { method: "DELETE", headers: await headers() }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM attachments WHERE cipher_id=?", CIPHER).one().n, 0);
    equal(f.bucket.objects.has(ATTACHMENT_KEY), false, "retry must remove the first object's retained bytes");
    equal(f.bucket.objects.has(secondKey), false);
    equal(sql.exec("SELECT COUNT(*) AS n FROM storage_cleanup_jobs").one().n, 0, "only successful storage deletion acknowledges jobs");
    ok(f.bucket.objects.has(SEND_KEY), "unrelated adopted storage must remain intact");
  });

  await check("an attachment commit with a lost acknowledgement retains its adopted staged bytes", async () => {
    const f = attachmentUploadFixture(); const batch = f.db.batch.bind(f.db);
    f.db.batch = async statements => { const rows = await batch(statements); if (statements.some(s => /^INSERT INTO attachments /.test(s.sql))) throw new Error("simulated lost D1 acknowledgement"); return rows; };
    await expectJsonOrEmpty(await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) }), 500);
    ok(f.db.attachment.storage_key, "publication did not commit before the simulated lost response");
    sameBytes(f.bucket.objects.get(f.db.attachment.storage_key), [0, 1, 2, 3, 4, 5]);
    ok(!f.bucket.deleted.includes(f.db.attachment.storage_key), "lost acknowledgement cleanup deleted the adopted object");
    equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages").one().n, 0);
  });
  await check("staged Send and attachment files survive a D1 outage for maintenance to reclaim", async () => {
    for (const kind of ["attachment", "send"]) {
      const attachment = kind === "attachment";
      const f = attachment ? attachmentUploadFixture() : fixture();
      if (!attachment) f.db.send.upload_state = 1;
      const prefix = attachment ? `attachments/${CIPHER}/${FILE}/` : `${SEND_KEY}/`;
      let unavailable = false, key;
      f.bucket.afterPut = () => {
        key = [...f.bucket.objects.keys()].find(value => value.startsWith(prefix));
        ok(key, `${kind} did not write staged bytes`);
        equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages WHERE object_key=?", key).one().n, 1);
        unavailable = true;
      };
      const batch = f.db.batch.bind(f.db), execute = f.db.execute.bind(f.db);
      f.db.batch = statements => {
        if (unavailable) throw new Error("fixture publication database unavailable");
        return batch(statements);
      };
      f.db.execute = (query, params) => {
        if (unavailable && query.startsWith("DELETE FROM storage_upload_stages")) {
          throw new Error("fixture cleanup database unavailable");
        }
        return execute(query, params);
      };
      const path = attachment ? attachmentPath("azure-upload", await attachmentToken()) :
        `/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`;
      await expectJsonOrEmpty(await f.fetch(path, { method: "PUT", body: byteStream(6) }), 500);
      equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages WHERE object_key=?", key).one().n, 1);
      equal(sql.exec("SELECT count(*) AS n FROM storage_cleanup_jobs WHERE object_key=?", key).one().n, 0);
      equal(attachment ? f.db.attachment : f.db.send.storage_key, null);

      unavailable = false;
      sql.exec("INSERT INTO global_domains_cache VALUES(1,4000000000)");
      const maintain = () => new RustWorker(ctx, f.env).scheduled({ cron: "0 0 * * *", scheduledTime: Date.now() });
      await maintain();
      ok(f.bucket.objects.has(key), "maintenance removed a live staging lease");
      sql.exec("UPDATE storage_upload_stages SET expires_at='2020-01-01T00:00:00.000Z' WHERE object_key=?", key);
      await maintain();
      equal(f.bucket.objects.has(key), false, kind);
      equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages WHERE object_key=?", key).one().n, 0);
      equal(sql.exec("SELECT count(*) AS n FROM storage_cleanup_jobs WHERE object_key=?", key).one().n, 0);
    }
  });
  await check("expired upload stages cannot publish a file pointer", async () => {
    for (const kind of ["attachment", "send"]) {
      const attachment = kind === "attachment";
      const f = attachment ? attachmentUploadFixture() : fixture();
      if (!attachment) f.db.send.upload_state = 1;
      const prefix = attachment ? `attachments/${CIPHER}/${FILE}/` : `${SEND_KEY}/`;
      f.bucket.afterPut = () => sql.exec("UPDATE storage_upload_stages SET expires_at='2020-01-01T00:00:00.000Z'");
      const path = attachment ? attachmentPath("azure-upload", await attachmentToken()) :
        `/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}`;
      await expectJsonOrEmpty(await f.fetch(path, { method: "PUT", body: byteStream(6) }), 400);
      equal(attachment ? f.db.attachment : f.db.send.storage_key, null);
      equal([...f.bucket.objects.keys()].some(key => key.startsWith(prefix)), false);
      equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages").one().n, 0);
      equal(sql.exec("SELECT count(*) AS n FROM storage_cleanup_jobs WHERE object_key LIKE ?", `${prefix}%`).one().n, 0);
    }
  });
  await check("unconfirmed file writes retain their stage until maintenance can remove late bytes", async () => {
    for (const mode of ["R2 PUT", "KV PUT", "R2 multipart completion"]) {
      const kv = mode === "KV PUT", multipart = mode === "R2 multipart completion";
      const f = kv ? kvFixture() : attachmentUploadFixture();
      const storage = kv ? f.kv : f.bucket;
      const size = multipart ? 8 * 1024 * 1024 + 1 : 6;
      if (kv) f.db.send.upload_state = 1;
      else f.db.pending.file_size_bytes = size;
      let key, finishWrite;
      if (multipart) {
        const resume = storage.resumeMultipartUpload.bind(storage);
        storage.resumeMultipartUpload = (objectKey, id) => ({
          ...resume(objectKey, id),
          async complete() {
            key = objectKey;
            finishWrite = () => storage.objects.set(objectKey, Uint8Array.of(1));
            throw new Error("fixture multipart completion outcome unknown");
          },
        });
      } else {
        const put = storage.put.bind(storage);
        storage.put = async (objectKey, data, options) => {
          key = objectKey;
          const bytes = data.slice(0);
          finishWrite = () => put(objectKey, bytes, options);
          throw new Error("fixture PUT outcome unknown");
        };
      }
      const path = kv ? `/api/sends/${SEND}/file/${FILE}/azure-upload?token=${await sendToken("send.upload")}` :
        attachmentPath("azure-upload", await attachmentToken());
      const error = await expectJsonOrEmpty(await f.fetch(path, { method: "PUT", body: byteStream(size) }), 500);
      equal(error.code, 9001, mode);
      if (multipart) {
        equal(f.bucket.created, 1, mode);
        equal(f.bucket.aborted, 1, mode);
        equal(f.bucket.uploads.size, 0, mode);
        equal(f.db.batches, 0, mode);
        ok(f.db.pending, "pending reservation was not preserved");
      }
      ok(key, mode);
      equal(storage.deleted.includes(key), false, mode);
      equal(storage.objects.has(key), false, mode);
      equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages WHERE object_key=?", key).one().n, 1, mode);
      equal(sql.exec("SELECT count(*) AS n FROM storage_cleanup_jobs WHERE object_key=?", key).one().n, 0, mode);
      equal(kv ? f.db.send.storage_key : f.db.attachment, null, mode);

      await finishWrite();
      ok(storage.objects.has(key), mode);
      sql.exec("INSERT INTO global_domains_cache VALUES(1,4000000000)");
      const maintain = () => new RustWorker(ctx, f.env).scheduled({ cron: "0 0 * * *", scheduledTime: Date.now() });
      await maintain();
      ok(storage.objects.has(key), mode);
      sql.exec("UPDATE storage_upload_stages SET expires_at='2020-01-01T00:00:00.000Z' WHERE object_key=?", key);
      await maintain();
      equal(storage.objects.has(key), false, mode);
      equal(sql.exec("SELECT count(*) AS n FROM storage_upload_stages WHERE object_key=?", key).one().n, 0, mode);
      equal(sql.exec("SELECT count(*) AS n FROM storage_cleanup_jobs WHERE object_key=?", key).one().n, 0, mode);
    }
  });
  await check("a same-stamp account upgrade fences an in-flight attachment upload", async () => {
    const f = attachmentUploadFixture(); f.bucket.afterPut = () => sql.exec("UPDATE users SET key='upgraded-wrap',security_version=2 WHERE id=?", USER);
    await expectJsonOrEmpty(await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) }), 400);
    equal(f.db.attachment, null); ok(f.db.pending, "failed generation check removed the reservation");
    equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 0);
  });
  await check("concurrent attachment attempts adopt one pointer and cleanup cannot delete the winner", async () => {
    const f = attachmentUploadFixture(); const put = f.bucket.put.bind(f.bucket);
    let entered = 0, release; const ready = new Promise(resolve => { release = resolve; });
    f.bucket.put = async (...args) => { const object = await put(...args); if (++entered === 1) await ready; else release(); return object; };
    const path = attachmentPath("azure-upload", await attachmentToken());
    const responses = await Promise.all([1, 2].map(() => f.fetch(path, { method: "PUT", body: byteStream(6) })));
    equal(responses.map(r => r.status).sort().join(","), "201,400");
    const adopted = f.db.attachment.storage_key; sameBytes(f.bucket.objects.get(adopted), [0, 1, 2, 3, 4, 5]);
    equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 1); ok(!f.bucket.deleted.includes(adopted), "a losing attempt deleted the winner");
  });
  async function replaceAttachment(f, bytes, key) {
    const form = new FormData();
    form.append("data", new Blob([bytes]), "encrypted-name");
    if (key !== undefined) form.append("key", key);
    return f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { method: "POST", headers: { Authorization: `Bearer ${await accessToken()}` }, body: form });
  }
  function pauseAttachmentBatch(f, prefix) {
    const entered = Promise.withResolvers();
    const resume = Promise.withResolvers();
    f.db.beforeNextBatch(statements => statements.some(statement => statement.sql.startsWith(prefix)), () => {
      entered.resolve();
      return resume.promise;
    });
    return { entered: entered.promise, resume: resume.resolve };
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
      const f = attachmentUploadFixture();
      f.env.ATTACHMENT_TOTAL_LIMIT_KB = "1";
      await expectJsonOrEmpty(await reserveAttachment(f), 200);
      const path = attachmentPath("azure-upload", await attachmentToken());
      const upload = size => capability
        ? f.fetch(path, { method: "PUT", body: byteStream(size) })
        : replaceAttachment(f, new Uint8Array(size));

      // Another reservation uses 600 of 1024 bytes. The upload excludes its own reservation.
      f.db.pending.file_size_bytes = 425;
      const declaredTooLarge = await expectJsonOrEmpty(await upload(424), 400);
      equal(declaredTooLarge.msg, "Invalid query parameters: Attachment storage limit reached");
      equal(f.bucket.deleted.length, 0, "a rejected declaration started a staged upload");
      f.db.pending.file_size_bytes = 424;
      const streamTooLarge = await expectJsonOrEmpty(await upload(425), 400);
      equal(streamTooLarge.msg, "Invalid request: File size exceeds limit");
      equal(f.db.pending.file_size_bytes, 424);
      equal(f.db.attachment, null);

      await expectJsonOrEmpty(await upload(424), capability ? 201 : 200);
      equal(f.db.pending, null);
      equal(f.db.attachment.file_size_bytes, 424);
    }
  });
  await check("attachment reservations recheck quota at commit", async () => {
    const f = attachmentUploadFixture();
    f.db.pending = null;
    f.env.ATTACHMENT_TOTAL_LIMIT_KB = "1";
    const { entered, resume } = pauseAttachmentBatch(f, "INSERT INTO attachments_pending");
    const first = reserveAttachment(f);
    try {
      await Promise.race([entered, first.then(response => { throw new Error(`Reservation missed its commit: ${response.status}`); })]);
      await expectJsonOrEmpty(await reserveAttachment(f), 200);
      resume();
      const rejected = await expectJsonOrEmpty(await first, 400);
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
      const f = mode === "replacement" ? fixture() : attachmentUploadFixture();
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
        await expectJsonOrEmpty(await reserveAttachment(f), 200);
        const revision = f.db.row("users", USER).updated_at;
        resume();
        const rejected = await expectJsonOrEmpty(await upload, 400);
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
    const f = fixture(); f.db.pending = null;
    const bytes = "replacement bytes";
    const key = "replacement-wrapped-key";
    await expectJsonOrEmpty(await replaceAttachment(f, bytes, key), 200);

    const attachment = f.db.attachment;
    ok(attachment.storage_key, "replacement did not adopt a staged key");
    equal(attachment.file_size_bytes, bytes.length);
    equal(attachment.encrypted_key, key);
    equal(f.db.pending, null);
    equal(f.bucket.objects.has(ATTACHMENT_KEY), false, "replacement left the old object");
    equal(new TextDecoder().decode(f.bucket.objects.get(attachment.storage_key)), bytes);

    const downloaded = await f.fetch(attachmentPath("download", await attachmentToken()));
    equal(downloaded.status, 200);
    equal(new TextDecoder().decode(await downloaded.arrayBuffer()), bytes);
  });
  await check("failed ready attachment replacement preserves the committed metadata and old bytes", async () => {
    const f = fixture(); f.db.pending = null; const before = JSON.stringify(f.db.attachment); f.db.failBatch = true;
    await expectJsonOrEmpty(await replaceAttachment(f, "newest"), 500);
    equal(JSON.stringify(f.db.attachment), before); sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
    equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 0);
  });
  await check("a losing ready attachment replacement cannot overwrite or delete the winner", async () => {
    const f = fixture(); f.db.pending = null;
    const put = f.bucket.put.bind(f.bucket); let reached, release, calls = 0;
    const gate = new Promise(resolve => { reached = resolve; }); const resume = new Promise(resolve => { release = resolve; });
    f.bucket.put = async (...args) => { if (++calls === 1) { reached(); await resume; } return put(...args); };
    const losing = replaceAttachment(f, "loser!");
    try {
      await Promise.race([gate, losing.then(async response => { throw new Error(`Replacement missed R2 gate: ${response.status} ${await response.clone().text()}`); })]);
      await expectJsonOrEmpty(await replaceAttachment(f, "winner"), 200); release(); await expectJsonOrEmpty(await losing, 400);
      const adopted = f.db.attachment.storage_key; equal(new TextDecoder().decode(f.bucket.objects.get(adopted)), "winner");
      ok(!f.bucket.deleted.includes(adopted), "losing replacement erased adopted bytes");
      equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 1);
    } finally { release(); await losing; }
  });
  await check("a legacy download capability cannot write a ready attachment through Azure PUT", async () => {
    const f = fixture(); f.db.pending = null; const before = JSON.stringify(f.db.attachment); const signed = await attachmentToken();
    equal((await f.fetch(attachmentPath("download", signed))).status, 200);
    await expectJsonOrEmpty(await f.fetch(attachmentPath("azure-upload", signed), { method: "PUT", body: byteStream(6) }), 404);
    equal(JSON.stringify(f.db.attachment), before); sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
  });
}
