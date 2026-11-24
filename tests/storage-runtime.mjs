import RustWorker from "./index.js";
import { assertDownloadSecurityHeaders, bearerJsonHeaders, equal, expectJson, expectJsonOrEmpty as expect, ok, sameBytes } from "./runtime-assertions.mjs";
import {
  ATTACHMENT_KEY, CIPHER, FILE, NOW, ORIGIN, SEND, SEND_KEY, USER, DurableObjectNamespace, KvNamespace,
  attachmentPath, attachmentToken, byteStream, encoder, sendToken,
} from "./runtime-fixture.mjs";

export async function runStorageChecks({ fixture, attachmentUploadFixture, kvFixture, check, ctx, sql, accessToken }) {
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
      await expect(await f.fetch(path, { method, headers: { Authorization: `Bearer ${foreign}` } }), 404);
      ok(f.bucket.objects.has(ATTACHMENT_KEY), "unauthorized delete removed the object");
      await expect(await f.fetch(path, { method, headers: await headers() }), 200);
      equal(sql.exec("SELECT count(*) AS n FROM attachments WHERE id=?", FILE).one().n, 0);
      equal(f.bucket.objects.has(ATTACHMENT_KEY), false);
    }
    const f = fixture();
    for (const path of ["trusted", "granted"]) {
      const body = await expect(await f.fetch(`/api/emergency-access/${path}`), 200);
      equal(body.object, "list"); equal(body.data.length, 0);
    }
  });

  await check("invalid storage bindings reject downloads and never acknowledge cleanup against the fallback", async () => {
    const f = fixture();
    const path = attachmentPath("download", await attachmentToken());
    const kv = new KvNamespace();
    f.env.ATTACHMENTS_BUCKET = {};
    f.env.ATTACHMENTS_KV = kv;
    const r2Error = await expect(await f.fetch(path), 500);
    equal(r2Error.code, 0);
    equal(kv.gets, 0, "KV must not mask an invalid R2 binding");

    delete f.env.ATTACHMENTS_BUCKET;
    f.env.ATTACHMENTS_KV = { get() {} };
    const kvError = await expect(await f.fetch(path), 500);
    equal(kvError.code, 0);
    delete f.env.ATTACHMENTS_KV;
    await expect(await f.fetch(path), 400);

    f.env.ATTACHMENTS_BUCKET = {};
    f.env.ATTACHMENTS_KV = kv;
    await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { method: "DELETE", headers: await headers() }), 200);
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
    await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${FILE}`, { method: "DELETE", headers: await headers() }), 200);
    ok(failed, "attachment deletion did not reach the failing storage backend");
    equal(f.db.attachment, null, "metadata deletion should remain committed");
    sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
    equal(sql.exec("SELECT object_key FROM storage_cleanup_jobs").one().object_key, ATTACHMENT_KEY, "failed deletion must remain queued");

    const second = "00000000-0000-4000-8000-000000000005", secondKey = `${CIPHER}/${second}`;
    sql.exec("INSERT INTO attachments(id,cipher_id,file_name,file_size_bytes,encrypted_key,created_at,updated_at) VALUES(?,?,'second-file',3,'encrypted-key',?,?)", second, CIPHER, NOW, NOW);
    f.bucket.objects.set(secondKey, new Uint8Array([10, 20, 30]));
    f.bucket.delete = removeObjects;
    await expect(await f.fetch(`/api/ciphers/${CIPHER}/attachment/${second}`, { method: "DELETE", headers: await headers() }), 200);
    equal(sql.exec("SELECT COUNT(*) AS n FROM attachments WHERE cipher_id=?", CIPHER).one().n, 0);
    equal(f.bucket.objects.has(ATTACHMENT_KEY), false, "retry must remove the first object's retained bytes");
    equal(f.bucket.objects.has(secondKey), false);
    equal(sql.exec("SELECT COUNT(*) AS n FROM storage_cleanup_jobs").one().n, 0, "only successful storage deletion acknowledges jobs");
    ok(f.bucket.objects.has(SEND_KEY), "unrelated adopted storage must remain intact");
  });

  await check("an attachment commit with a lost acknowledgement retains its adopted staged bytes", async () => {
    const f = attachmentUploadFixture(); const batch = f.db.batch.bind(f.db);
    f.db.batch = async statements => { const rows = await batch(statements); if (statements.some(s => /^INSERT INTO attachments /.test(s.sql))) throw new Error("simulated lost D1 acknowledgement"); return rows; };
    await expect(await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) }), 500);
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
      await expect(await f.fetch(path, { method: "PUT", body: byteStream(6) }), 500);
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
      await expect(await f.fetch(path, { method: "PUT", body: byteStream(6) }), 400);
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
      const error = await expect(await f.fetch(path, { method: "PUT", body: byteStream(size) }), 500);
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
    await expect(await f.fetch(attachmentPath("azure-upload", await attachmentToken()), { method: "PUT", body: byteStream(6) }), 400);
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
      await expect(await reserveAttachment(f), 200);
      const path = attachmentPath("azure-upload", await attachmentToken());
      const upload = size => capability
        ? f.fetch(path, { method: "PUT", body: byteStream(size) })
        : replaceAttachment(f, new Uint8Array(size));

      // Another reservation uses 600 of 1024 bytes. The upload excludes its own reservation.
      f.db.pending.file_size_bytes = 425;
      const declaredTooLarge = await expect(await upload(424), 400);
      equal(declaredTooLarge.msg, "Invalid query parameters: Attachment storage limit reached");
      equal(f.bucket.deleted.length, 0, "a rejected declaration started a staged upload");
      f.db.pending.file_size_bytes = 424;
      const streamTooLarge = await expect(await upload(425), 400);
      equal(streamTooLarge.msg, "Invalid request: File size exceeds limit");
      equal(f.db.pending.file_size_bytes, 424);
      equal(f.db.attachment, null);

      await expect(await upload(424), capability ? 201 : 200);
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
      await expect(await reserveAttachment(f), 200);
      resume();
      const rejected = await expect(await first, 400);
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
        await expect(await reserveAttachment(f), 200);
        const revision = f.db.row("users", USER).updated_at;
        resume();
        const rejected = await expect(await upload, 400);
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
    await expect(await replaceAttachment(f, bytes, key), 200);

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
    await expect(await replaceAttachment(f, "newest"), 500);
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
      await expect(await replaceAttachment(f, "winner"), 200); release(); await expect(await losing, 400);
      const adopted = f.db.attachment.storage_key; equal(new TextDecoder().decode(f.bucket.objects.get(adopted)), "winner");
      ok(!f.bucket.deleted.includes(adopted), "losing replacement erased adopted bytes");
      equal([...f.bucket.objects.keys()].filter(key => key.startsWith(`attachments/${CIPHER}/`)).length, 1);
    } finally { release(); await losing; }
  });
  await check("a legacy download capability cannot write a ready attachment through Azure PUT", async () => {
    const f = fixture(); f.db.pending = null; const before = JSON.stringify(f.db.attachment); const signed = await attachmentToken();
    equal((await f.fetch(attachmentPath("download", signed))).status, 200);
    await expect(await f.fetch(attachmentPath("azure-upload", signed), { method: "PUT", body: byteStream(6) }), 404);
    equal(JSON.stringify(f.db.attachment), before); sameBytes(f.bucket.objects.get(ATTACHMENT_KEY), [0, 1, 2, 3, 128, 255]);
  });
}
