import { captureNotifications, SEND_KEY, snapshotTables } from "./runtime-fixture.mjs";
import { bearerJsonHeaders, equal, expectJson, expectStatus, jwtClaims as jwt, oauthToken, ok, requestJson } from "./runtime-tools.mjs";

// Compiled Rust HTTP behavior over workerd's native SQLite adapter and fixture
// object storage. SQL below seeds data or schedules real transactional races.

export async function runSendTests({ fixture, check, accessToken, USER, FILE, SEND, sql }) {
  const row = (id = SEND) => sql.exec("SELECT * FROM sends WHERE id=?", id).one();
  const count = (id = SEND) => row(id).access_count;
  const owner = async () => bearerJsonHeaders(await accessToken());
  const payload = (extra = {}) => ({ type: 0, name: "encrypted-send", key: "wrapped-key",
    text: { text: "encrypted-content", hidden: false }, deletionDate: new Date(Date.now() + 86400000).toISOString(), ...extra });
  const post = async (f, path, body, method) => requestJson(f, path, body, { method, headers: await owner() });
  const create = async (f, extra = {}) => expectJson(await post(f, "/api/sends", payload(extra)), 200);
  async function accessId(f, id = SEND) {
    return (await expectJson(await f.fetch(`/api/sends/${id}`, { headers: await owner() }), 200)).accessId;
  }
  async function issue(f, id) {
    return expectJson(await oauthToken(f, { grant_type: "send_access", send_id: id ?? await accessId(f) }), 200);
  }
  const access = (f, token, path = "/api/sends/access") => requestJson(f, path, {}, { headers: bearerJsonHeaders(token) });
  const grant = (f, token) => access(f, token, `/api/sends/access/file/${FILE}`);
  async function upload(f, bytes, { extra = false, path = `/api/sends/${SEND}/file/${FILE}` } = {}) {
    const form = new FormData();
    form.append("data", new Blob([bytes]), "encrypted");
    if (extra) form.append("file", new Blob(["unexpected"]), "encrypted");
    return f.fetch(path, { method: "POST", headers: { Authorization: `Bearer ${await accessToken()}` }, body: form });
  }

  const filePayload = (fileLength = 6) => payload({ type: 1, text: undefined, file: { fileName: "encrypted" }, fileLength });
  const state = f => JSON.stringify({
    tables: snapshotTables(sql, ["users", "sends", "storage_upload_stages", "storage_cleanup_jobs"]),
    objects: [...f.bucket.objects].map(([key, bytes]) => [key, [...bytes]]).sort(([a], [b]) => a.localeCompare(b)),
    created: f.bucket.created, deleted: f.bucket.deleted,
  });
  const unchanged = (f, expected) => equal(state(f), expected, "failed request changed database or object storage");
  const tokenIn = url => { const parsed = new URL(url); return parsed.searchParams.get("token") ?? parsed.searchParams.get("t"); };
  const pathIn = url => { const parsed = new URL(url); return parsed.pathname + parsed.search; };
  const legacyGrant = f => requestJson(f, `/api/sends/${SEND}/access/file/${FILE}`, {});

  await check("Send bearer routes challenge missing and invalid capabilities without labeling D1 errors", async () => {
    const f = fixture();
    const issued = await issue(f);
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

    f.db.failQuery(query => query.startsWith("SELECT * FROM sends WHERE id = ?1"), "fixture Send query unavailable");
    for (const path of paths) {
      const failure = await post(path, `Bearer ${issued.access_token}`);
      equal(challenge(failure), null);
      const body = await expectJson(failure, 500);
      equal(body.message, "Database query failed: Failed to fetch Send (D1: D1_ERROR)");
      ok(!JSON.stringify(body).includes("fixture Send query unavailable"));
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
    const issued = await issue(f, send.accessId);
    await expectJson(await access(f, issued.access_token), 200);
    equal(count(send.id), 1);
    assertRevision(send.id, 13);

    await expectJson(await legacyGrant(f), 200);
    equal(count(), 1);
    assertRevision(SEND, 13);
  });

  await check("Send issuance does not count; five concurrent actual text reads enforce max two", async () => {
    const f = fixture();
    const send = await create(f, { maxAccessCount: 2, hideEmail: true });
    const issued = await issue(f, send.accessId);
    equal(count(send.id), 0);
    const responses = await Promise.all(Array.from({ length: 5 }, () => access(f, issued.access_token)));
    equal(responses.filter(r => r.status === 200).length, 2);
    equal(responses.filter(r => r.status === 404).length, 3);
    equal(count(send.id), 2);
  });

  await check("Send file grants, missing bytes, replacements, quotas, TTLs, and UTF-8 limits work end to end", async () => {
    const f = fixture();
    sql.exec("UPDATE sends SET max_access_count=1 WHERE id=?", SEND);
    const issued = await issue(f);
    await expectJson(await access(f, issued.access_token), 200);
    equal(count(), 0);
    const granted = await expectJson(await grant(f, issued.access_token), 200);
    equal(count(), 1);
    await expectJson(await grant(f, issued.access_token), 404);
    for (const method of ["GET", "HEAD"]) {
      const resp = await f.fetch(pathIn(granted.url), { method });
      equal((await resp.arrayBuffer()).byteLength, method === "HEAD" ? 0 : 6);
    }

    const fMissing = fixture(); fMissing.bucket.objects.delete(SEND_KEY);
    await expectJson(await grant(fMissing, (await issue(fMissing)).access_token), 404);

    const fRep = fixture();
    await expectStatus(await upload(fRep, "short"), 400);
    sql.exec("UPDATE sends SET file_size_bytes=0 WHERE id=?", SEND);
    await expectStatus(await upload(fRep, ""), 201);
    equal(fRep.bucket.objects.has(SEND_KEY), false);

    const fQuota = fixture(); fQuota.env.USER_SEND_LIMIT_KB = "1"; fQuota.env.SEND_TTL_SECS = "17";
    const res = await expectJson(await post(fQuota, "/api/sends/file/v2", filePayload(1018)), 200);
    equal(jwt(tokenIn(res.url)).exp - jwt(tokenIn(res.url)).iat, 17);
    await expectStatus(await post(fQuota, "/api/sends/file/v2", filePayload(1)), 400);

    const fText = fixture(), text = { text: "é€🙂", hidden: false };
    fText.env.SEND_TEXT_MAX_BYTES = String(new TextEncoder().encode(JSON.stringify(text)).length);
    const created = await expectJson(await post(fText, "/api/sends", payload({ text: { ...text, response: "tmp" } })), 200);
    equal(Object.hasOwn(JSON.parse(sql.exec("SELECT data FROM sends WHERE id=?", created.id).one().data), "response"), false);
  });
}
