import { captureNotifications } from "./runtime-fixture.mjs";
// Compiled Rust HTTP behavior over workerd's native SQLite adapter and fixture
// object storage. SQL below seeds data or schedules real transactional races.
import { bearerJsonHeaders, equal, expectJson, expectStatus, ok } from "./runtime-assertions.mjs";

export async function runSendCompatibility({ fixture, check, accessToken, USER, FILE, SEND, sql }) {
  const row = (id = SEND) => sql.exec("SELECT * FROM sends WHERE id=?", id).one();
  const count = (id = SEND) => row(id).access_count;
  const owner = async () => bearerJsonHeaders(await accessToken());
  const payload = (extra = {}) => ({ type: 0, name: "encrypted-send", key: "wrapped-key",
    text: { text: "encrypted-content", hidden: false }, deletionDate: new Date(Date.now() + 86400000).toISOString(), ...extra });
  const create = async (f, extra = {}) => expectJson(await f.fetch("/api/sends", {
    method: "POST", headers: await owner(), body: JSON.stringify(payload(extra)),
  }), 200);
  async function accessId(f, id = SEND) {
    return (await expectJson(await f.fetch(`/api/sends/${id}`, { headers: await owner() }), 200)).accessId;
  }
  async function issue(f, id, extra = {}) {
    return f.fetch("/identity/connect/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "send_access", send_id: id, ...extra }).toString() });
  }
  const access = (f, token, path = "/api/sends/access") => f.fetch(path, {
    method: "POST", headers: bearerJsonHeaders(token), body: "{}",
  });
  async function upload(f, bytes, extra = false, route = `/api/sends/${SEND}/file/${FILE}`) {
    const form = new FormData();
    form.append("data", new Blob([bytes]), "encrypted");
    if (extra) form.append("file", new Blob(["unexpected"]), "encrypted");
    return f.fetch(route, { method: "POST", headers: { Authorization: `Bearer ${await accessToken()}` }, body: form });
  }

  await check("Send bearer routes challenge missing and invalid capabilities without labeling D1 errors", async () => {
    const f = fixture();
    const issued = await expectJson(await issue(f, await accessId(f)), 200);
    const paths = ["/api/sends/access", `/api/sends/access/file/${FILE}`];
    const post = (path, authorization) => f.fetch(path, {
      method: "POST", headers: authorization === undefined ? {} : { Authorization: authorization },
    });
    const challenge = response => response.headers.get("WWW-Authenticate");
    for (const path of paths) {
      for (const authorization of [undefined, "Bearer", "Bearer\ttoken"]) {
        const missing = await post(path, authorization);
        equal(challenge(missing), "Bearer");
        equal((await expectJson(missing, 401)).message, "Unauthorized: Send access token required");
      }
      const invalid = await post(path, "Bearer invalid");
      equal(challenge(invalid), 'Bearer error="invalid_token"');
      equal((await expectJson(invalid, 401)).code, 4);
      await expectJson(await post(path, `bEaReR   ${issued.access_token}`), 200);
    }

    const queryProof = await f.fetch(`/api/sends/${SEND}/${FILE}?t=invalid`);
    equal(challenge(queryProof), null);
    await expectJson(queryProof, 401);

    const execute = f.db.execute.bind(f.db);
    f.db.execute = (query, params) => {
      if (query.startsWith("SELECT * FROM sends WHERE id = ?1")) throw new Error("fixture Send query unavailable");
      return execute(query, params);
    };
    for (const path of paths) {
      const failure = await post(path, `Bearer ${issued.access_token}`);
      equal(challenge(failure), null);
      equal((await expectJson(failure, 500)).message, "Internal server error");
    }
  });

  await check("Send creation and counted access notify with the committed owner revision", async () => {
    const f = fixture(), messages = captureNotifications(f);
    const future = "2099-01-01T00:00:00.000Z";
    sql.exec("UPDATE users SET updated_at=? WHERE id=?", future, USER);
    let previousRevision = Date.parse(future);
    function assertRevision(id, type) {
      equal(messages.length, 1);
      const message = messages.shift();
      equal(message.selector.user_id, USER);
      const frame = atob(message.message);
      ok(frame.includes(`\xa4Type${String.fromCharCode(type)}`), "unexpected Send update type");
      // MessagePack fixstr "RevisionDate", then the 64-bit timestamp extension.
      const marker = "\xacRevisionDate\xd7\xff";
      const index = frame.indexOf(marker);
      ok(index >= 0, "notification is missing the revision timestamp");
      const offset = index + marker.length;
      const value = Uint8Array.from(frame.slice(offset, offset + 8), char => char.charCodeAt(0));
      const millis = Date.parse(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at);
      equal(millis, previousRevision + 1, "committed owner revision");
      const timestamp = (BigInt(millis % 1000) * 1_000_000n << 34n) | BigInt(Math.floor(millis / 1000));
      equal(new DataView(value.buffer).getBigUint64(0), timestamp, "notified revision");
      ok(Date.parse(row(id).updated_at) < millis, "resource revision must keep its own clock");
      previousRevision = millis;
    }

    const send = await create(f);
    equal(send.revisionDate, row(send.id).updated_at);
    assertRevision(send.id, 12);
    const issued = await expectJson(await issue(f, send.accessId), 200);
    await expectJson(await access(f, issued.access_token), 200);
    equal(count(send.id), 1);
    assertRevision(send.id, 13);

    await expectJson(await f.fetch(`/api/sends/${SEND}/access/file/${FILE}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
    }), 200);
    equal(count(), 1);
    assertRevision(SEND, 13);
  });

  await check("a failed creator email lookup leaves the Send readable and publishes no update", async () => {
    for (const [mode, text, legacy] of [["legacy text", true, true], ["bearer text", true, false], ["bearer file", false, false]]) {
      const f = fixture();
      const send = text ? await create(f, { maxAccessCount: 1 }) : {
        id: SEND, accessId: await accessId(f),
      };
      const token = legacy ? null : (await expectJson(await issue(f, send.accessId), 200)).access_token;
      const read = () => token ? access(f, token) : f.fetch(`/api/sends/access/${send.accessId}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
      });
      const messages = captureNotifications(f);
      const before = "2099-01-01T00:00:00.000Z";
      sql.exec("UPDATE users SET updated_at=? WHERE id=?", before, USER);
      const revision = () => sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
      const execute = f.db.execute.bind(f.db);
      let emailReads = 0, failEmailRead = true;
      f.db.execute = (query, params) => {
        if (query.includes("SELECT email FROM users WHERE id=?1")) {
          emailReads++;
          if (failEmailRead) throw new Error("D1_ERROR: fixture creator lookup unavailable");
        }
        return execute(query, params);
      };

      const failure = await expectJson(await read(), 500);
      equal(failure.code, 1, mode);
      equal(failure.message, "Internal server error", mode);
      equal(emailReads, 1, mode);
      equal(count(send.id), 0, mode);
      equal(revision(), before, mode);
      equal(messages.length, 0, mode);

      failEmailRead = false;
      const retry = await expectJson(await read(), 200);
      equal(retry.creatorIdentifier, "owner@example.test", mode);
      if (text) equal(retry.text.text, "encrypted-content", mode);
      else equal(retry.file.id, FILE, mode);
      equal(count(send.id), text ? 1 : 0, mode);
      equal(Date.parse(revision()), Date.parse(before) + 1, mode);
      equal(messages.length, 1, mode);
      if (text) {
        failEmailRead = true;
        await expectJson(await read(), 404);
        equal(emailReads, 2, mode);
        equal(count(send.id), 1, mode);
        equal(messages.length, 1, mode);
      }
    }
  });

  await check("Send issuance does not count; five concurrent actual text reads enforce max two", async () => {
    const f = fixture();
    const send = await create(f, { maxAccessCount: 2, hideEmail: true });
    const before = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
    const issued = await expectJson(await issue(f, send.accessId), 200);
    equal(count(send.id), 0, "issuance count");
    equal(sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at, before, "issuance cursor");
    const responses = await Promise.all(Array.from({ length: 5 }, () => access(f, issued.access_token)));
    equal(responses.filter(response => response.status === 200).length, 2, "successful actual reads");
    equal(responses.filter(response => response.status === 404).length, 3, "denied actual reads");
    equal(count(send.id), 2);
    const viewed = await responses.find(response => response.status === 200).json();
    equal(viewed.id, send.accessId); equal(viewed.creatorIdentifier, null);
    equal(viewed.text.text, "encrypted-content"); equal(viewed.key, undefined);
  });

  await check("Send file metadata, invalid file IDs, grants and raw reads have separate counts", async () => {
    const f = fixture();
    sql.exec("UPDATE sends SET max_access_count=1 WHERE id=?", SEND);
    const id = await accessId(f);
    const issued = await expectJson(await issue(f, id), 200);
    equal(count(), 0);
    await expectJson(await access(f, issued.access_token), 200); equal(count(), 0);
    await expectJson(await access(f, issued.access_token, "/api/sends/access/file/wrong-file"), 404); equal(count(), 0);
    const grant = await expectJson(await access(f, issued.access_token, `/api/sends/access/file/${FILE}`), 200);
    equal(count(), 1);
    await expectJson(await access(f, issued.access_token, `/api/sends/access/file/${FILE}`), 404);
    const head = f.bucket.head.bind(f.bucket);
    let storageLookups = 0;
    f.bucket.head = async () => { storageLookups++; throw new Error("fixture storage unavailable"); };
    await expectJson(await access(f, issued.access_token, `/api/sends/access/file/${FILE}`), 404);
    equal(storageLookups, 0, "an exhausted bearer grant should not query storage");
    f.bucket.head = head;
    await expectJson(await access(f, issued.access_token), 200); equal(count(), 1);
    const path = new URL(grant.url).pathname + new URL(grant.url).search;
    for (const method of ["GET", "HEAD"]) {
      const response = await f.fetch(path, { method });
      equal(response.status, 200); equal((await response.arrayBuffer()).byteLength, method === "HEAD" ? 0 : 6);
    }
    equal(count(), 1, "raw URL reads do not count again");
  });

  await check("missing Send bytes never consume a file grant", async () => {
    const f = fixture();
    f.bucket.objects.delete(`sends/${SEND}/${FILE}`);
    const issued = await expectJson(await issue(f, await accessId(f)), 200);
    await expectJson(await access(f, issued.access_token, `/api/sends/access/file/${FILE}`), 404);
    equal(count(), 0);
  });

  await check("a failed Send owner cursor rolls the actual public count back", async () => {
    const f = fixture();
    const send = await create(f, { maxAccessCount: 1 });
    const issued = await expectJson(await issue(f, send.accessId), 200);
    sql.exec("CREATE TRIGGER send_runtime_revision_failure BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT,'synthetic Send cursor failure'); END");
    equal((await access(f, issued.access_token)).status, 500);
    equal(count(send.id), 0);
  });

  await check("failed replacement and extra Send fields retain the ready file", async () => {
    const f = fixture(); const original = JSON.stringify(row());
    const key = `sends/${SEND}/${FILE}`;
    equal((await upload(f, "short")).status, 400);
    const put = f.bucket.put.bind(f.bucket), written = [];
    f.bucket.put = async (key, ...args) => { written.push(key); return put(key, ...args); };
    equal((await upload(f, "valid!", true)).status, 400);
    equal(written.length, 1, "invalid multipart writes one staged object");
    ok(written[0].startsWith(`${key}/`), "multipart write did not use a staged key");
    equal(f.bucket.deleted.filter(key => key === written[0]).length, 1, "the written stage is cleaned once");
    equal(JSON.stringify(row()), original, "metadata unchanged after invalid replacements");
    equal(f.bucket.objects.get(key).join(","), "0,1,2,3,128,255", "original file remains");
    equal([...f.bucket.objects.keys()].filter(key => key.startsWith("sends/")).length, 1);
  });

  await check("zero-byte Send replacement publishes its staged object and removes the old bytes", async () => {
    const f = fixture(), oldKey = `sends/${SEND}/${FILE}`;
    sql.exec("UPDATE sends SET file_size_bytes=0 WHERE id=?", SEND);
    const response = await upload(f, "");
    await expectStatus(response, 201);
    const published = row(), adopted = published.storage_key;
    equal(published.upload_state, 0, "empty file is published");
    equal(published.file_size_bytes, 0, "published size remains zero");
    ok(adopted?.startsWith(`${oldKey}/`), "empty upload did not adopt a new staged key");
    ok(f.bucket.objects.has(adopted), "published empty object is missing");
    equal(f.bucket.objects.get(adopted).length, 0, "published object is empty");
    ok(f.bucket.deleted.includes(oldKey), "old file was not cleaned after empty replacement");
    equal(f.bucket.objects.has(oldKey), false, "old bytes remain after replacement");
    equal([...f.bucket.objects.keys()].filter(key => key.startsWith("sends/")).length, 1);
  });

  await check("losing concurrent Send replacement cannot erase the winner", async () => {
    const f = fixture();
    let reached, release;
    const gate = new Promise(resolve => { reached = resolve; });
    const resume = new Promise(resolve => { release = resolve; });
    const put = f.bucket.put.bind(f.bucket); let calls = 0;
    f.bucket.put = async (...args) => { if (++calls === 1) { reached(); await resume; } return put(...args); };
    const losing = upload(f, "loser!");
    try {
      await Promise.race([gate, losing.then(async response => { throw new Error(`Upload missed R2 gate: ${response.status} ${await response.text()}`); })]);
      equal((await upload(f, "winner")).status, 201);
      release(); equal((await losing).status, 400);
      const adopted = row().storage_key;
      equal(new TextDecoder().decode(f.bucket.objects.get(adopted)), "winner");
      equal([...f.bucket.objects.keys()].filter(key => key.startsWith("sends/")).length, 1);
    } finally { release(); await losing; }
  });

  await check("lost Send commit response preserves the adopted staged object", async () => {
    const f = fixture(); const batch = f.db.batch.bind(f.db); let fail = true;
    f.db.batch = async statements => {
      const result = await batch(statements);
      if (fail && statements.some(statement => /^UPDATE sends SET upload_state=0,file_size_bytes=/.test(statement.sql.trim()))) {
        fail = false; throw new Error("synthetic lost Send commit response");
      }
      return result;
    };
    equal((await upload(f, "newest")).status, 500);
    const adopted = row().storage_key;
    ok(adopted, "staged pointer was not committed");
    equal(row().upload_state, 0); equal(new TextDecoder().decode(f.bucket.objects.get(adopted)), "newest");
    ok(!f.bucket.deleted.includes(adopted), "adopted bytes were deleted after an ambiguous response");
  });

  await check("same-stamp account envelope changes reject an in-flight Send upload", async () => {
    const f = fixture(); const before = JSON.stringify(row());
    f.bucket.afterPut = () => sql.exec("UPDATE users SET key='upgraded-key',security_version=2 WHERE id=?", USER);
    equal((await upload(f, "newest", false, `/sends/${SEND}/file/${FILE}`)).status, 400);
    equal(JSON.stringify(row()), before);
    equal(f.bucket.objects.get(`sends/${SEND}/${FILE}`).join(","), "0,1,2,3,128,255");
  });

  await check("a session reset fences a Send create already paused at its real transaction", async () => {
    const f = fixture(); const batch = f.db.batch.bind(f.db);
    let reached, release;
    const gate = new Promise(resolve => { reached = resolve; });
    const resume = new Promise(resolve => { release = resolve; });
    f.db.batch = async statements => {
      if (statements.some(statement => /^INSERT INTO sends/.test(statement.sql.trim()))) { reached(); await resume; }
      return batch(statements);
    };
    const pending = f.fetch("/api/sends", { method: "POST", headers: await owner(), body: JSON.stringify(payload()) });
    try {
      await Promise.race([gate, pending.then(async response => { throw new Error(`Create missed transaction gate: ${response.status} ${await response.text()}`); })]);
      sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
      release(); equal((await pending).status, 401);
      equal(sql.exec("SELECT COUNT(*) AS n FROM sends").one().n, 1, "stale Send was not inserted");
    } finally { release(); await pending; }
  });

  await check("an owner Send update cannot overwrite a concurrent actual content access", async () => {
    const f = fixture(); const send = await create(f, { maxAccessCount: 2 });
    const issued = await expectJson(await issue(f, send.accessId), 200);
    const batch = f.db.batch.bind(f.db); let reached, release;
    const gate = new Promise(resolve => { reached = resolve; });
    const resume = new Promise(resolve => { release = resolve; });
    f.db.batch = async statements => {
      if (statements.some(statement => /^UPDATE sends SET\s+name=/.test(statement.sql.trim()))) { reached(); await resume; }
      return batch(statements);
    };
    const pending = f.fetch(`/api/sends/${send.id}`, { method: "PUT", headers: await owner(),
      body: JSON.stringify(payload({ name: "must-not-overwrite", maxAccessCount: 2 })) });
    try {
      await Promise.race([gate, pending.then(async response => { throw new Error(`Update missed transaction gate: ${response.status} ${await response.text()}`); })]);
      await expectJson(await access(f, issued.access_token), 200);
      release(); equal((await pending).status, 400);
      equal(row(send.id).name, "encrypted-send"); equal(count(send.id), 1);
    } finally { release(); await pending; }
  });
}
