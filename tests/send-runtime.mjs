// Compiled Rust HTTP behavior over workerd's native SQLite adapter and fixture
// object storage. SQL below seeds data or schedules real transactional races.
function equal(actual, expected, label = "value") {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
}
function ok(value, label) { if (!value) throw new Error(label); }

export async function runSendCompatibility({ fixture, check, accessToken, USER, FILE, SEND, sql }) {
  const row = (id = SEND) => sql.exec("SELECT * FROM sends WHERE id=?", id).one();
  const count = (id = SEND) => row(id).access_count;
  async function expect(response, status) {
    equal(response.status, status, await response.clone().text());
    return response.json();
  }
  const owner = async () => ({ Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" });
  const payload = (extra = {}) => ({ type: 0, name: "encrypted-send", key: "wrapped-key",
    text: { text: "encrypted-content", hidden: false }, deletionDate: new Date(Date.now() + 86400000).toISOString(), ...extra });
  const create = async (f, extra = {}) => expect(await f.fetch("/api/sends", {
    method: "POST", headers: await owner(), body: JSON.stringify(payload(extra)),
  }), 200);
  async function accessId(f, id = SEND) {
    return (await expect(await f.fetch(`/api/sends/${id}`, { headers: await owner() }), 200)).accessId;
  }
  async function issue(f, id, extra = {}) {
    return f.fetch("/identity/connect/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "send_access", send_id: id, ...extra }).toString() });
  }
  const access = (f, token, path = "/api/sends/access") => f.fetch(path, {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: "{}",
  });
  async function upload(f, bytes, extra = false, route = `/api/sends/${SEND}/file/${FILE}`) {
    const form = new FormData();
    form.append("data", new Blob([bytes]), "encrypted");
    if (extra) form.append("file", new Blob(["unexpected"]), "encrypted");
    return f.fetch(route, { method: "POST", headers: { Authorization: `Bearer ${await accessToken()}` }, body: form });
  }

  await check("Send issuance does not count; five concurrent actual text reads enforce max two", async () => {
    const f = fixture();
    const send = await create(f, { maxAccessCount: 2, hideEmail: true });
    const before = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
    const issued = await expect(await issue(f, send.accessId), 200);
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
    const issued = await expect(await issue(f, id), 200);
    equal(count(), 0);
    await expect(await access(f, issued.access_token), 200); equal(count(), 0);
    await expect(await access(f, issued.access_token, "/api/sends/access/file/wrong-file"), 404); equal(count(), 0);
    const grant = await expect(await access(f, issued.access_token, `/api/sends/access/file/${FILE}`), 200);
    equal(count(), 1);
    await expect(await access(f, issued.access_token, `/api/sends/access/file/${FILE}`), 404);
    await expect(await access(f, issued.access_token), 200); equal(count(), 1);
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
    const issued = await expect(await issue(f, await accessId(f)), 200);
    await expect(await access(f, issued.access_token, `/api/sends/access/file/${FILE}`), 404);
    equal(count(), 0);
  });

  await check("a failed Send owner cursor rolls the actual public count back", async () => {
    const f = fixture();
    const send = await create(f, { maxAccessCount: 1 });
    const issued = await expect(await issue(f, send.accessId), 200);
    sql.exec("CREATE TRIGGER send_runtime_revision_failure BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT,'synthetic Send cursor failure'); END");
    equal((await access(f, issued.access_token)).status, 500);
    equal(count(send.id), 0);
  });

  await check("failed replacement and extra Send fields retain the ready file", async () => {
    const f = fixture(); const original = JSON.stringify(row());
    const key = `sends/${SEND}/${FILE}`;
    equal((await upload(f, "short")).status, 400);
    equal((await upload(f, "valid!", true)).status, 400);
    equal(JSON.stringify(row()), original, "metadata unchanged after invalid replacements");
    equal(f.bucket.objects.get(key).join(","), "0,1,2,3,128,255", "original file remains");
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
      if (fail && statements.some(statement => /^UPDATE sends SET pending=0,file_size=/.test(statement.sql.trim()))) {
        fail = false; throw new Error("synthetic lost Send commit response");
      }
      return result;
    };
    equal((await upload(f, "newest")).status, 500);
    const adopted = row().storage_key;
    ok(adopted, "staged pointer was not committed");
    equal(row().pending, 0); equal(new TextDecoder().decode(f.bucket.objects.get(adopted)), "newest");
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
    const issued = await expect(await issue(f, send.accessId), 200);
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
      await expect(await access(f, issued.access_token), 200);
      release(); equal((await pending).status, 400);
      equal(row(send.id).name, "encrypted-send"); equal(count(send.id), 1);
    } finally { release(); await pending; }
  });
}
