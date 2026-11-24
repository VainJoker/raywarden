import { bearerJsonHeaders, equal, expectJsonOrEmpty as expect, ok, sameBytes } from "./runtime-assertions.mjs";
import { ATTACHMENT_KEY, CIPHER, FILE, NOW, USER, KvNamespace, attachmentPath, attachmentToken, byteStream } from "./runtime-fixture.mjs";

export async function runVaultChecks({ fixture, check, sql, accessToken }) {
  const headers = async () => bearerJsonHeaders(await accessToken());
  const payload = (extra = {}) => ({ type: 1, name: "encrypted", login: {}, key: "wrapped-item-key", favorite: false, ...extra });
  const save = async (f, body, id) => expect(await f.fetch(id ? `/api/ciphers/${id}` : "/api/ciphers", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 200);

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
      const result = await expect(await f.fetch("/api/folders", {
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
    const f = fixture();
    for (const [type, field] of [[6, "bankAccount"], [7, "driversLicense"], [8, "passport"]]) {
      const body = await save(f, { type, name: "encrypted", key: "wrapped", favorite: false, folderId: "", [field]: { encrypted: "opaque", response: { transient: true } } });
      equal(body.type, type); equal(body.favorite, false); equal(body.folderId, null); equal(body[field].encrypted, "opaque"); equal(body[field].response, undefined);
    }
    const list = await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 200);
    equal(list.data.length, 4);
    for (const item of list.data) { equal(item.__storedData, undefined); equal(item.userId, undefined); ok(Array.isArray(item.collectionIds), "private collectionIds must be an array"); }
  });
  await check("sealed cipher blobs round-trip identically through create, GET, list and sync", async () => {
    const f = fixture(); const blob = '{ "format_version": 2, "data": "opaque encrypted bytes" }';
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
      await expect(await f.fetch("/api/sync?excludeDomains=true", { headers: await headers() }), status);
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
      const response = await expect(await f.fetch(path, { headers: await headers() }), 200);
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
    const response = await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 413);
    ok(JSON.stringify(response).includes("Cipher attachment metadata exceeds the server size limit"), "missing size rejection");
    equal(response.data, null);

    // Deleting attachments on an already-oversized cipher must not deadlock on 413.
    await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/oversized-file-16`, { method: "DELETE", headers: await headers() }), 200);
    await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/oversized-file-15`, { method: "DELETE", headers: await headers() }), 200);
    await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 200);

    // Reserving an attachment that would push metadata over 16 MiB is rejected with 413.
    const overReserve = await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/v2`, {
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
    const listing = await expect(await f.fetch(path, { headers: await headers() }), 200);
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
      await expect(await f.fetch(endpoint, { headers: await headers() }), 409);
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
    await expect(await call(), 200);
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
    await expect(await call(), 400);
    ok(changed, "fixture did not change the attachment after the selected rows were read");
    equal(f.db.row("attachments", "rotate-0").encrypted_key, "concurrent-key");
  });
  await check("unreadable stored cipher JSON fails GET and list without fabricating empty items", async () => {
    const f = fixture(); f.db.cipher.data = "{unreadable";
    await expect(await f.fetch(`/api/ciphers/${CIPHER}`, { headers: await headers() }), 500);
    await expect(await f.fetch("/api/ciphers", { headers: await headers() }), 500);
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
      const f = fixture();
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
    const f = fixture(); const current = "0123456789abcdef0123456789abcdef";
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
      await expect(response, 400);
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
    await expect(await f.fetch(`/api/ciphers/${CIPHER}`, { method: "POST", headers: await headers(), body: JSON.stringify(payload({ name: "must-rollback" })) }), 500);
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
  await check("sync and cipher responses retain attachment metadata when configured storage is invalid", async () => {
    const f = fixture();
    const auth = { headers: await headers() };
    const read = async path => expect(await f.fetch(path, auth), 200);
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
      await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, auth), status);
      await expect(await f.fetch(attachmentPath("download", token)), status);
      await expect(await f.fetch(attachmentPath("azure-upload", token), { method: "PUT", body: byteStream(6) }), status);
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
    await expect(await f.fetch("/api/ciphers/import", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 221); equal(f.db.batches, 1);
    const imported = sql.exec("SELECT organization_id,folder_id,archived_at FROM ciphers WHERE json_extract(data,'$.name')='encrypted-0'").one();
    equal(imported.organization_id, null); ok(imported.folder_id && imported.folder_id !== "source-folder", "source folder ID was reused"); ok(imported.archived_at.startsWith("2026-01-01"), "archive date was lost");
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers WHERE id!=? AND organization_id IS NOT NULL", CIPHER).one().n, 0);
  });
  await check("a failing late import chunk leaves no earlier imported folders or ciphers", async () => {
    const f = fixture();
    sql.exec("CREATE TRIGGER reject_import BEFORE INSERT ON ciphers WHEN json_extract(NEW.data,'$.name')='reject-last' BEGIN SELECT RAISE(ABORT,'runtime import failure'); END");
    const body = { folders: [{ name: "encrypted-folder" }], ciphers: [...Array.from({ length: 65 }, (_, i) => payload({ name: `encrypted-${i}` })), payload({ name: "reject-last" })] };
    await expect(await f.fetch("/api/ciphers/import", { method: "POST", headers: await headers(), body: JSON.stringify(body) }), 500);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers").one().n, 1); equal(sql.exec("SELECT COUNT(*) AS n FROM folders").one().n, 0);
  });
}
