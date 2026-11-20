/** Reference Send settings and personal Cipher selectors through real WASM. */
export async function runSendParityCompatibility({ fixture, check, sql, accessToken, USER, FILE, SEND, CIPHER }) {
  const equal = (actual, expected, label = "value") => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const status = async (response, expected) => {
    if (response.status !== expected) throw new Error(`Expected ${expected}, received ${response.status}: ${await response.text()}`);
    return response;
  };
  const owner = async () => ({ Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" });
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
  const accessId = async f => (await (await status(await f.fetch(`/api/sends/${SEND}`, { headers: await owner() }), 200)).json()).accessId;
  const issue = async f => (await status(await f.fetch("/identity/connect/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "send_access", send_id: await accessId(f) }) }), 200)).json();
  const grant = async (f, token) => f.fetch(`/api/sends/access/file/${FILE}`, { method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: "{}" });
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
    const upload = await (await status(await reserve(1018), 200)).json();
    equal(sql.exec("SELECT SUM(file_size_bytes) AS bytes FROM sends WHERE user_id=?", USER).one().bytes, 1024);
    const before = state(f);
    const denied = await status(await reserve(1), 400);
    equal((await denied.text()).includes("The vault changed during this request. Please retry."), true);
    unchanged(f, before);

    await status(await f.fetch(`/api/sends/${upload.sendResponse.id}`, { method: "DELETE", headers: await owner() }), 200);
    f.env.SEND_MAX_BYTES = "1018";
    const next = await (await status(await reserve(6), 200)).json();
    await status(await multipart(f, `/api/sends/${next.sendResponse.id}/file/${next.sendResponse.file.id}`), 201);
    f.env.SEND_MAX_BYTES = "1012";
    await status(await reserve(1012), 200);
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
      await status(await reserve(), 200);
    } finally {
      release();
    }
    await status(await first, 400);
    equal(sql.exec("SELECT SUM(file_size_bytes) AS bytes FROM sends WHERE user_id=?", USER).one().bytes, 606);
    equal(sql.exec("SELECT COUNT(*) AS count FROM sends WHERE user_id=? AND upload_state=1", USER).one().count, 1);
    const current = sql.exec("SELECT updated_at FROM users WHERE id=?", USER).one().updated_at;
    equal(Date.parse(current), Date.parse(revision) + 1, "only the successful reservation advances the cursor");
  });

  await check("Send file TTL config reaches upload and both download grant protocols without changing OAuth access lifetime", async () => {
    const f = fixture(); f.env.SEND_TTL_SECS = "17";
    const upload = await (await status(await post(f, "/api/sends/file/v2", filePayload()), 200)).json();
    const uploadClaims = jwt(tokenIn(upload.url));
    equal(uploadClaims.exp - uploadClaims.iat, 17); equal(uploadClaims.scope, "send.upload");
    const issued = await issue(f), accessClaims = jwt(issued.access_token);
    equal(issued.expires_in, 300); equal(accessClaims.exp - accessClaims.iat, 300); equal(accessClaims.scope, "send.access");
    for (const request of [() => grant(f, issued.access_token), () => legacyGrant(f)]) {
      const download = await (await status(await request(), 200)).json(), claims = jwt(tokenIn(download.url));
      equal(claims.exp - claims.iat, 17); equal(claims.scope, "send.download");
      equal((await status(await f.fetch(pathIn(download.url)), 200)).status, 200);
      const expired = await accessToken({ ...claims, exp: Math.floor(Date.now() / 1000) - 1 });
      const expiredUrl = new URL(download.url); expiredUrl.searchParams.set("t", expired);
      await status(await f.fetch(pathIn(expiredUrl.href)), 401);
    }
    await status(await f.fetch(pathIn(upload.url), { method: "PUT", body: "new123" }), 201);
    const download = await (await status(await legacyGrant(f), 200)).json();
    sql.exec("UPDATE sends SET is_disabled=1 WHERE id=?", SEND);
    await status(await f.fetch(pathIn(download.url)), 404);
  });

  await check("invalid Send TTL rejects reservations, all upload variants and grants before any related write", async () => {
    for (const ttl of ["0", "-1", "9223372036854775807", "253402300799"]) {
      const f = fixture();
      const pending = await (await status(await post(f, "/api/sends/file/v2", filePayload()), 200)).json();
      f.env.SEND_TTL_SECS = ttl;
      const issued = await issue(f), before = state(f);
      await status(await post(f, "/api/sends/file/v2", filePayload()), 500); unchanged(f, before);
      for (const path of [`/api/sends/${SEND}/file/${FILE}`, `/sends/${SEND}/file/${FILE}`]) {
        await status(await multipart(f, path), 500); unchanged(f, before);
      }
      await status(await f.fetch(pathIn(pending.url), { method: "PUT", body: "new123" }), 500); unchanged(f, before);
      await status(await grant(f, issued.access_token), 500); unchanged(f, before);
      await status(await legacyGrant(f), 500); unchanged(f, before);
    }
  });

  await check("Send file TTL uses reference defaults for absent, malformed and integer-overflow bindings", async () => {
    for (const ttl of [undefined, "invalid", "18446744073709551616"]) {
      const f = fixture();
      if (ttl !== undefined) f.env.SEND_TTL_SECS = ttl;
      const upload = await (await status(await post(f, "/api/sends/file/v2", filePayload()), 200)).json();
      const claims = jwt(tokenIn(upload.url)); equal(claims.exp - claims.iat, 300);
    }
  });

  await check("Send text limits count UTF-8 JSON consistently for create and update after stripping response metadata", async () => {
    const f = fixture(), text = { text: "é€🙂", hidden: false };
    const bytes = new TextEncoder().encode(JSON.stringify(text)).length;
    f.env.SEND_TEXT_MAX_BYTES = String(bytes);
    const body = payload({ text: { ...text, response: "temporary-client-response" } });
    const send = await (await status(await post(f, "/api/sends", body), 200)).json();
    const stored = JSON.parse(sql.exec("SELECT data FROM sends WHERE id=?", send.id).one().data);
    equal(stored.text, text.text); equal(stored.hidden, false); equal(Object.hasOwn(stored, "response"), false);
    f.env.SEND_TEXT_MAX_BYTES = String(bytes - 1);
    const before = state(f);
    await status(await post(f, "/api/sends", body), 400); unchanged(f, before);
    await status(await post(f, `/api/sends/${send.id}`, { ...body, name: "changed-name" }, "PUT"), 400); unchanged(f, before);
    f.env.SEND_TEXT_MAX_BYTES = String(bytes);
    await status(await post(f, `/api/sends/${send.id}`, { ...body, name: "changed-name" }, "PUT"), 200);
    equal(sql.exec("SELECT name FROM sends WHERE id=?", send.id).one().name, "changed-name");
  });

  await check("Send text zero, invalid and oversized limits retain deterministic WASM and D1 boundaries", async () => {
    {
      const f = fixture(); f.env.SEND_TEXT_MAX_BYTES = "0";
      const before = state(f);
      await status(await post(f, "/api/sends", payload()), 400); unchanged(f, before);
      await status(await post(f, "/api/sends/file/v2", filePayload()), 200);
    }
    for (const limit of ["invalid", "-1", "18446744073709551616"]) {
      const f = fixture(); f.env.SEND_TEXT_MAX_BYTES = limit;
      await status(await post(f, "/api/sends", payload()), 200);
    }
    const f = fixture(); f.env.SEND_TEXT_MAX_BYTES = "18446744073709551615";
    const text = { text: "x".repeat(1_900_000 - new TextEncoder().encode('{"text":""}').length) };
    const send = await (await status(await post(f, "/api/sends", payload({ text })), 200)).json();
    equal(new TextEncoder().encode(sql.exec("SELECT data FROM sends WHERE id=?", send.id).one().data).length, 1_900_000);
    const count = sql.exec("SELECT COUNT(*) AS n FROM sends").one().n;
    await status(await post(f, "/api/sends", payload({ text: { text: text.text + "x" } })), 400);
    equal(sql.exec("SELECT COUNT(*) AS n FROM sends").one().n, count);
  });

  await check("personal purge rejects either organization selector and conflicting aliases without deleting personal data", async () => {
    for (const query of ["organizationId=organization", "organizationID=organization", "organizationId=&organizationID=organization", "organizationId=organization&organizationId=", "organization%49d=%20"]) {
      const f = fixture(), before = state(f);
      await status(await post(f, `/api/ciphers/purge?${query}`, { masterPasswordHash: "hash" }), 400);
      unchanged(f, before);
    }
    const f = fixture();
    await status(await post(f, "/api/ciphers/purge?organizationId=&organizationID=", { masterPasswordHash: "hash" }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM ciphers WHERE user_id=?", USER).one().n, 0);
  });

  await check("both move methods interpret an empty folder ID as clearing the personal folder", async () => {
    for (const method of ["POST", "PUT"]) {
      const f = fixture();
      sql.exec("INSERT INTO folders(id,user_id,name,created_at,updated_at) VALUES('send-parity-folder',?,'encrypted','old','old')", USER);
      sql.exec("UPDATE ciphers SET folder_id='send-parity-folder' WHERE id=?", CIPHER);
      await status(await post(f, "/api/ciphers/move", { ids: [CIPHER], folderId: "" }, method), 200);
      equal(sql.exec("SELECT folder_id FROM ciphers WHERE id=?", CIPHER).one().folder_id, null);
      const before = state(f);
      await status(await post(f, "/api/ciphers/move", { ids: [CIPHER], folderId: "not-owned" }, method), 400);
      unchanged(f, before);
    }
  });
}
