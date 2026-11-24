import { captureNotifications } from "./runtime-fixture.mjs";
import { bearerJsonHeaders, equal, expectJson, expectStatus, ok } from "./runtime-tools.mjs";

export async function runSendTests(context) {
  await runSendChecks(context);
  await runSendParityChecks(context);
}

// Compiled Rust HTTP behavior over workerd's native SQLite adapter and fixture
// object storage. SQL below seeds data or schedules real transactional races.

async function runSendChecks({ fixture, check, accessToken, USER, FILE, SEND, sql }) {
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

/** Reference Send settings and personal Cipher selectors through real WASM. */

async function runSendParityChecks({ fixture, check, sql, accessToken, USER, FILE, SEND, CIPHER }) {
  const owner = async () => bearerJsonHeaders(await accessToken());
  const payload = (extra = {}) => ({ type: 0, name: "encrypted-name", key: "wrapped-key", text: { text: "encrypted-text" },
    deletionDate: new Date(Date.now() + 86400000).toISOString(), ...extra });
  const filePayload = () => payload({ type: 1, text: undefined, file: { fileName: "encrypted" }, fileLength: 6 });
  const post = async (f, path, body, method = "POST") => f.fetch(path, { method, headers: await owner(), body: JSON.stringify(body) });
  const state = f => JSON.stringify({
    tables: Object.fromEntries(["users", "sends", "ciphers", "folders", "attachments", "attachments_pending", "storage_cleanup_jobs"]
      .map(table => [table, sql.exec(`SELECT * FROM ${table} ORDER BY rowid`).toArray()])),
    objects: [...f.bucket.objects].map(([key, bytes]) => [key, [...bytes]]).sort(([a], [b]) => a.localeCompare(b)),
    created: f.bucket.created, deleted: f.bucket.deleted,
  });
  const unchanged = (f, expected) => equal(state(f) === expected, true, "failed request changed database or object storage");
  const jwt = token => JSON.parse(atob(token.split(".")[1].replaceAll("-", "+").replaceAll("_", "/")));
  const tokenIn = url => { const parsed = new URL(url); return parsed.searchParams.get("token") ?? parsed.searchParams.get("t"); };
  const pathIn = url => { const parsed = new URL(url); return parsed.pathname + parsed.search; };
  const accessId = async f => (await expectJson(await f.fetch(`/api/sends/${SEND}`, { headers: await owner() }), 200)).accessId;
  const issue = async f => expectJson(await f.fetch("/identity/connect/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "send_access", send_id: await accessId(f) }) }), 200);
  const grant = async (f, token) => f.fetch(`/api/sends/access/file/${FILE}`, { method: "POST",
    headers: bearerJsonHeaders(token), body: "{}" });
  const legacyGrant = f => f.fetch(`/api/sends/${SEND}/access/file/${FILE}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  async function multipart(f, path) {
    const form = new FormData();
    form.append("data", new Blob(["new123"]), "encrypted");
    return f.fetch(path, { method: "POST", headers: { Authorization: `Bearer ${await accessToken()}` }, body: form });
  }

  await check("Send file reservations use the whole quota and roll back excess requests", async () => {
    const f = fixture();
    f.env.USER_SEND_LIMIT_KB = "1";
    f.db.setRow("sends", "other-send", { ...f.db.send, id: "other-send", user_id: "other-owner", file_size_bytes: 1024 });
    const reserve = fileLength => post(f, "/api/sends/file/v2", { ...filePayload(), fileLength });
    const upload = await expectJson(await reserve(1018), 200);
    equal(sql.exec("SELECT SUM(file_size_bytes) AS bytes FROM sends WHERE user_id=?", USER).one().bytes, 1024);
    const before = state(f);
    const denied = await expectStatus(await reserve(1), 400);
    equal((await denied.text()).includes("The vault changed during this request. Please retry."), true);
    unchanged(f, before);

    await expectStatus(await f.fetch(`/api/sends/${upload.sendResponse.id}`, { method: "DELETE", headers: await owner() }), 200);
    f.env.SEND_MAX_BYTES = "1018";
    const next = await expectJson(await reserve(6), 200);
    await expectStatus(await multipart(f, `/api/sends/${next.sendResponse.id}/file/${next.sendResponse.file.id}`), 201);
    f.env.SEND_MAX_BYTES = "1012";
    await expectStatus(await reserve(1012), 200);

    delete f.env.USER_SEND_LIMIT_KB;
    f.env.SEND_MAX_BYTES = String(100 * 1024 * 1024);
    await expectStatus(await reserve(96 * 1024 * 1024), 200);
  });

  await check("Invalid Send quota fails closed before reservations and staged writes", async () => {
    for (const value of ["", "-1", "invalid", "9223372036854775807", 1]) {
      const f = fixture(); f.env.USER_SEND_LIMIT_KB = value;
      const before = state(f);
      await expectStatus(await post(f, "/api/sends/file/v2", filePayload()), 500);
      unchanged(f, before);
      equal(sql.exec("SELECT COUNT(*) AS n FROM storage_upload_stages").one().n, 0);
    }
    const f = fixture(); f.env.USER_SEND_LIMIT_KB = "0";
    const before = state(f);
    await expectStatus(await post(f, "/api/sends/file/v2", filePayload()), 400);
    unchanged(f, before);

    delete f.env.USER_SEND_LIMIT_KB;
    const reservation = await expectJson(await post(f, "/api/sends/file/v2", filePayload()), 200);
    f.env.USER_SEND_LIMIT_KB = "invalid";
    const reserved = state(f);
    await expectStatus(await f.fetch(pathIn(reservation.url), { method: "PUT", body: "new123" }), 500);
    unchanged(f, reserved);
    equal(sql.exec("SELECT COUNT(*) AS n FROM storage_upload_stages").one().n, 0);
  });

  await check("Only one concurrent Send reservation commits when both cannot fit", async () => {
    const f = fixture();
    f.env.USER_SEND_LIMIT_KB = "1";
    const revision = "2090-01-01T00:00:00.000Z";
    sql.exec("UPDATE users SET updated_at=? WHERE id=?", revision, USER);
    let pause, release;
    const entered = new Promise(resolve => { pause = resolve; });
    const resume = new Promise(resolve => { release = resolve; });
    const batch = f.db.batch.bind(f.db);
    let firstBatch = true;
    f.db.batch = async statements => {
      if (firstBatch) {
        firstBatch = false;
        pause();
        await resume;
      }
      return batch(statements);
    };
    const reserve = () => post(f, "/api/sends/file/v2", { ...filePayload(), fileLength: 600 });
    const first = reserve();
    try {
      await Promise.race([entered, first.then(response => { throw new Error(`Reservation missed its commit: ${response.status}`); })]);
      await expectStatus(await reserve(), 200);
    } finally {
      release();
    }
    await expectStatus(await first, 400);
    equal(sql.exec("SELECT SUM(file_size_bytes) AS bytes FROM sends WHERE user_id=?", USER).one().bytes, 606);
    equal(sql.exec("SELECT COUNT(*) AS count FROM sends WHERE user_id=? AND upload_state=1", USER).one().count, 1);
    const current = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
    equal(Date.parse(current), Date.parse(revision) + 1, "only the successful reservation advances the cursor");
  });

  await check("Send file TTL config reaches upload and both download grant protocols without changing OAuth access lifetime", async () => {
    const f = fixture(); f.env.SEND_TTL_SECS = "17";
    const upload = await expectJson(await post(f, "/api/sends/file/v2", filePayload()), 200);
    const uploadClaims = jwt(tokenIn(upload.url));
    equal(uploadClaims.exp - uploadClaims.iat, 17); equal(uploadClaims.scope, "send.upload");
    const issued = await issue(f), accessClaims = jwt(issued.access_token);
    equal(issued.expires_in, 300); equal(accessClaims.exp - accessClaims.iat, 300); equal(accessClaims.scope, "send.access");
    for (const request of [() => grant(f, issued.access_token), () => legacyGrant(f)]) {
      const download = await expectJson(await request(), 200), claims = jwt(tokenIn(download.url));
      equal(claims.exp - claims.iat, 17); equal(claims.scope, "send.download");
      equal((await expectStatus(await f.fetch(pathIn(download.url)), 200)).status, 200);
      const expired = await accessToken({ ...claims, exp: Math.floor(Date.now() / 1000) - 1 });
      const expiredUrl = new URL(download.url); expiredUrl.searchParams.set("t", expired);
      await expectStatus(await f.fetch(pathIn(expiredUrl.href)), 401);
    }
    await expectStatus(await f.fetch(pathIn(upload.url), { method: "PUT", body: "new123" }), 201);
    const download = await expectJson(await legacyGrant(f), 200);
    sql.exec("UPDATE sends SET is_disabled=1 WHERE id=?", SEND);
    await expectStatus(await f.fetch(pathIn(download.url)), 404);
  });

  await check("invalid Send TTL rejects reservations, all upload variants and grants before any related write", async () => {
    for (const ttl of ["0", "-1", "9223372036854775807", "253402300799"]) {
      const f = fixture();
      const pending = await expectJson(await post(f, "/api/sends/file/v2", filePayload()), 200);
      f.env.SEND_TTL_SECS = ttl;
      const issued = await issue(f), before = state(f);
      await expectStatus(await post(f, "/api/sends/file/v2", filePayload()), 500); unchanged(f, before);
      for (const path of [`/api/sends/${SEND}/file/${FILE}`, `/sends/${SEND}/file/${FILE}`]) {
        await expectStatus(await multipart(f, path), 500); unchanged(f, before);
      }
      await expectStatus(await f.fetch(pathIn(pending.url), { method: "PUT", body: "new123" }), 500); unchanged(f, before);
      await expectStatus(await grant(f, issued.access_token), 500); unchanged(f, before);
      await expectStatus(await legacyGrant(f), 500); unchanged(f, before);
    }
  });

  await check("Send file TTL uses reference defaults for absent, malformed and integer-overflow bindings", async () => {
    for (const ttl of [undefined, "invalid", "18446744073709551616"]) {
      const f = fixture();
      if (ttl !== undefined) f.env.SEND_TTL_SECS = ttl;
      const upload = await expectJson(await post(f, "/api/sends/file/v2", filePayload()), 200);
      const claims = jwt(tokenIn(upload.url)); equal(claims.exp - claims.iat, 300);
    }
  });

  await check("Send text limits count UTF-8 JSON consistently for create and update after stripping response metadata", async () => {
    const f = fixture(), text = { text: "é€🙂", hidden: false };
    const bytes = new TextEncoder().encode(JSON.stringify(text)).length;
    f.env.SEND_TEXT_MAX_BYTES = String(bytes);
    const body = payload({ text: { ...text, response: "temporary-client-response" } });
    const send = await expectJson(await post(f, "/api/sends", body), 200);
    const stored = JSON.parse(sql.exec("SELECT data FROM sends WHERE id=?", send.id).one().data);
    equal(stored.text, text.text); equal(stored.hidden, false); equal(Object.hasOwn(stored, "response"), false);
    f.env.SEND_TEXT_MAX_BYTES = String(bytes - 1);
    const before = state(f);
    await expectStatus(await post(f, "/api/sends", body), 400); unchanged(f, before);
    await expectStatus(await post(f, `/api/sends/${send.id}`, { ...body, name: "changed-name" }, "PUT"), 400); unchanged(f, before);
    f.env.SEND_TEXT_MAX_BYTES = String(bytes);
    await expectStatus(await post(f, `/api/sends/${send.id}`, { ...body, name: "changed-name" }, "PUT"), 200);
    equal(sql.exec("SELECT name FROM sends WHERE id=?", send.id).one().name, "changed-name");
  });

  await check("Send text zero, invalid and oversized limits retain deterministic WASM and D1 boundaries", async () => {
    {
      const f = fixture(); f.env.SEND_TEXT_MAX_BYTES = "0";
      const before = state(f);
      await expectStatus(await post(f, "/api/sends", payload()), 400); unchanged(f, before);
      await expectStatus(await post(f, "/api/sends/file/v2", filePayload()), 200);
    }
    for (const limit of ["invalid", "-1", "18446744073709551616"]) {
      const f = fixture(); f.env.SEND_TEXT_MAX_BYTES = limit;
      await expectStatus(await post(f, "/api/sends", payload()), 200);
    }
    const f = fixture(); f.env.SEND_TEXT_MAX_BYTES = "18446744073709551615";
    const text = { text: "x".repeat(1_900_000 - new TextEncoder().encode('{"text":""}').length) };
    const send = await expectJson(await post(f, "/api/sends", payload({ text })), 200);
    equal(new TextEncoder().encode(sql.exec("SELECT data FROM sends WHERE id=?", send.id).one().data).length, 1_900_000);
    const count = sql.exec("SELECT COUNT(*) AS n FROM sends").one().n;
    await expectStatus(await post(f, "/api/sends", payload({ text: { text: text.text + "x" } })), 400);
    equal(sql.exec("SELECT COUNT(*) AS n FROM sends").one().n, count);
  });

  await check("personal purge rejects either organization selector and conflicting aliases without deleting personal data", async () => {
    for (const query of ["organizationId=organization", "organizationID=organization", "organizationId=&organizationID=organization", "organizationId=organization&organizationId=", "organization%49d=%20"]) {
      const f = fixture(), before = state(f);
      await expectStatus(await post(f, `/api/ciphers/purge?${query}`, { masterPasswordHash: "hash" }), 400);
      unchanged(f, before);
    }
    const f = fixture();
    await expectStatus(await post(f, "/api/ciphers/purge?organizationId=&organizationID=", { masterPasswordHash: "hash" }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers WHERE user_id=?", USER).one().n, 0);
  });

  await check("both move methods interpret an empty folder ID as clearing the personal folder", async () => {
    for (const method of ["POST", "PUT"]) {
      const f = fixture();
      sql.exec("INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES('send-parity-folder',?,'encrypted','old','old')", USER);
      sql.exec("UPDATE ciphers SET folder_id='send-parity-folder' WHERE id=?", CIPHER);
      await expectStatus(await post(f, "/api/ciphers/move", { ids: [CIPHER], folderId: "" }, method), 200);
      equal(sql.exec("SELECT folder_id FROM ciphers WHERE id=?", CIPHER).one().folder_id, null);
      const before = state(f);
      await expectStatus(await post(f, "/api/ciphers/move", { ids: [CIPHER], folderId: "not-owned" }, method), 400);
      unchanged(f, before);
    }
  });
}
