/** Actual compatibility aliases, bounded icons and atomic WebAuthn clearing. */
export async function runRouteParityCompatibility({ fixture, check, sql, accessToken, USER, SEND }) {
  const equal = (actual, expected, label = "value") => { if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`); };
  const ok = (value, label) => { if (!value) throw new Error(label); };
  const expect = async (response, status) => { const text = await response.text(); equal(response.status, status, text); return text ? JSON.parse(text) : null; };
  const headers = async () => ({ Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" });
  const request = async (f, path, body, method = "POST", authorized = true) => f.fetch(path, { method,
    headers: authorized ? await headers() : { "Content-Type": "application/json" }, body: JSON.stringify(body) });

  class DurableObjectNamespace {
    constructor(handler) { this.handler = handler; }
    idFromName(name) { return { name }; }
    get() { return { fetch: request => this.handler(request) }; }
  }
  const captureNotifications = (f, readAccount) => {
    const captured = [];
    f.env.NOTIFY_DO = new DurableObjectNamespace(async req => {
      captured.push({ update: await req.json(), account: readAccount() });
      return new Response(null, { status: 204 });
    });
    return captured;
  };
  const expectNotification = (update, type, logout) => {
    equal(update.selector.kind, "user"); equal(update.selector.user_id, USER);
    equal(update.logout, logout);
    const frame = atob(update.message);
    ok(frame.includes(`\xa4Type${String.fromCharCode(type)}`), `missing notification type ${type}`);
    ok(frame.includes("\xa9ContextId\xa6device"), "missing authenticated device context");
  };

  await check("remaining account and folder method aliases share validation and authenticated mutations", async () => {
    const f = fixture();
    equal((await expect(await request(f, "/accounts/verify-password", { masterPasswordHash: "hash" }), 200)).Object, "masterPasswordPolicy");
    await expect(await request(f, "/accounts/verify-password", { masterPasswordHash: "wrong" }), 401);
    const avatar = await expect(await request(f, "/api/accounts/avatar", { avatarColor: "#123abc" }), 200);
    equal(avatar.avatarColor, "#123abc");
    const folder = await expect(await request(f, "/api/folders", { name: "2.original" }), 200);
    const renamed = await expect(await request(f, `/api/folders/${folder.id}`, { name: "2.renamed" }), 200);
    equal(renamed.name, "2.renamed");
    for (const [path, body] of [["/api/accounts/avatar", { avatarColor: "#ffffff" }], [`/api/folders/${folder.id}`, { name: "2.unauthorized" }], ["/accounts/verify-password", { masterPasswordHash: "hash" }]]) {
      await expect(await request(f, path, body, "POST", false), 401);
    }
    equal(sql.exec("SELECT name FROM folders WHERE id=?", folder.id).one().name, "2.renamed");
    sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
    await expect(await request(f, "/api/accounts/avatar", { avatarColor: "#ffffff" }), 401);
    equal(sql.exec("SELECT avatar_color FROM users WHERE id=?", USER).one().avatar_color, "#123abc");
  });

  await check("profile and avatar writes each send one SyncVault update after success", async () => {
    const f = fixture();
    const captured = captureNotifications(f, () => sql.exec("SELECT name,avatar_color FROM users WHERE id=?", USER).one());
    await expect(await f.fetch("/api/accounts/profile", { headers: await headers() }), 200);
    await expect(await request(f, "/api/accounts/profile", { name: "x".repeat(51) }), 400);
    await expect(await request(f, "/api/accounts/avatar", { avatarColor: "x" }), 400);
    await expect(await request(f, "/api/accounts/avatar", { avatarColor: "#123abc" }, "PUT", false), 401);
    equal(captured.length, 0);
    for (const method of ["POST", "PUT"]) {
      const name = `Profile ${method}`;
      await expect(await request(f, "/api/accounts/profile", { name }, method), 200);
      equal(captured.length, 1); const profile = captured.shift();
      expectNotification(profile.update, 5, false); equal(profile.account.name, name);

      const avatarColor = method === "POST" ? "#123abc" : "#345def";
      await expect(await request(f, "/api/accounts/avatar", { avatarColor }, method), 200);
      equal(captured.length, 1); const avatar = captured.shift();
      expectNotification(avatar.update, 5, false); equal(avatar.account.avatar_color, avatarColor);
    }
  });

  await check("an optional bearer on anonymous Send metadata never produces an account update", async () => {
    const f = fixture();
    const captured = captureNotifications(f, () => null);
    sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) SELECT 'other-owner',device_id,name,device_type,session_token,created_at,updated_at FROM devices WHERE user_id=?", USER);
    const send = await expect(await f.fetch(`/api/sends/${SEND}`, { headers: await headers() }), 200);
    const result = await expect(await f.fetch(`/api/sends/access/${send.accessId}`, {
      method: "POST", body: "{}",
      headers: { Authorization: `Bearer ${await accessToken({ sub: "other-owner", sstamp: "other" })}`, "Content-Type": "application/json" },
    }), 200);
    equal(result.object, "send-access");
    equal(captured.length, 0);
  });

  await check("KDF changes notify once with LogOut after revoking the old session and never after rollback", async () => {
    const f = fixture();
    const captured = captureNotifications(f, () => sql.exec("SELECT key,kdf_iterations,security_stamp FROM users WHERE id=?", USER).one());
    const body = { masterPasswordHash: "hash", newMasterPasswordHash: "changed-auth", key: "2.kdf-change", kdf: 0, kdfIterations: 650000 };
    f.db.failBatch = true;
    await expect(await request(f, "/api/accounts/kdf", body), 500);
    equal(captured.length, 0);

    f.db.failBatch = false;
    await expect(await request(f, "/api/accounts/kdf", body), 200);
    equal(captured.length, 1);
    expectNotification(captured[0].update, 11, true);
    equal(captured[0].account.key, body.key);
    equal(captured[0].account.kdf_iterations, body.kdfIterations);
    ok(captured[0].account.security_stamp !== "owner-stamp", "LogOut preceded session invalidation");
    await expect(await f.fetch("/api/accounts/profile", { headers: await headers() }), 401);
  });

  await check("admin-request is the same public known-device approval request protocol", async () => {
    const f = fixture();
    const post = body => f.fetch("/api/auth-requests/admin-request", { method: "POST", headers: { "Content-Type": "application/json", "device-type": "0" }, body: JSON.stringify(body) });
    const body = { email: "owner@example.test", deviceIdentifier: "device", accessCode: "request-code", publicKey: "request-public-key" };
    const created = await expect(await post(body), 200);
    equal(created.object, "auth-request");
    equal(sql.exec("SELECT request_device_id FROM auth_requests WHERE id=?", created.id).one().request_device_id, "device");
    equal(sql.exec("SELECT COUNT(*) AS n FROM auth_requests WHERE user_id=?", USER).one().n, 1);
    await expect(await post({ ...body, deviceIdentifier: "unknown-device" }), 400);
    equal(sql.exec("SELECT COUNT(*) AS n FROM auth_requests WHERE user_id=?", USER).one().n, 1);
  });

  await check("client event aliases return an empty successful body without weakening session checks", async () => {
    const f = fixture();
    for (const path of ["/events/collect", "/api/events/collect"]) {
      const response = await request(f, path, [{ type: 1000, date: "2026-11-18T00:00:00Z" }]);
      equal(response.status, 200); equal(await response.text(), "");
      await expect(await request(f, path, [], "POST", false), 401);
    }
  });

  await check("security-stamp publishes one logout only after its database commit and none after failure", async () => {
    for (const fail of [true, false]) {
      const f = fixture(), messages = [];
      f.env.NOTIFY_DO = new DurableObjectNamespace(async req => {
        equal(new URL(req.url).pathname, "/internal/fanout");
        const message = await req.json(); equal(message.logout, true); messages.push(message);
        equal(sql.exec("SELECT COUNT(*) AS n FROM devices WHERE user_id=?", USER).one().n, 0, "logout preceded its database commit");
        return new Response('{"sent":1}', { headers: { "Content-Type": "application/json" } });
      });
      f.db.failBatch = fail;
      await expect(await request(f, "/api/accounts/security-stamp", { masterPasswordHash: "hash" }), fail ? 500 : 200);
      equal(messages.length, fail ? 0 : 1, "logout notification count");
      equal(sql.exec("SELECT security_stamp FROM users WHERE id=?", USER).one().security_stamp === "owner-stamp", fail);
    }
  });

  await check("trailing slash normalization preserves JSON, query strings and streamed request bodies without HeavyDo", async () => {
    const f = fixture(); f.env.HEAVY_DO_ENABLED = "false";
    await expect(await f.fetch("/api/config///"), 200);
    const sync = await expect(await f.fetch("/api/sync///?excludeDomains=true", { headers: await headers() }), 200);
    equal(sync.policies.length, 0); equal(sync.policiesNew.length, 0); equal(sync.domains, null, "normalized path lost its query");
    const folder = await expect(await request(f, "/api/folders///?keep=a%2Fb", { name: "2.streamed" }), 200);
    const bytes = new TextEncoder().encode(JSON.stringify({ name: "2.after-stream" })); let offset = 0;
    const body = new ReadableStream({ pull(controller) { if (offset === bytes.length) { controller.close(); return; } controller.enqueue(bytes.slice(offset, ++offset)); } });
    await expect(await f.fetch(`/api/folders/${folder.id}///?keep=a%2Fb`, { method: "POST", headers: await headers(), body }), 200);
    equal(sql.exec("SELECT name FROM folders WHERE id=?", folder.id).one().name, "2.after-stream");
    // An absent auth-request response is a harmless query-bearing lookup.
    const lookup = await f.fetch("/api/auth-requests/not-present/response///?code=a%2Fb");
    equal(lookup.status, 400);
  });

  const withIcon = async (f, upstream, run) => {
    const previous = globalThis.fetch, captured = [];
    globalThis.fetch = async (input, init) => {
      const req = input instanceof Request ? input : new Request(input, init); captured.push(req.url);
      equal(req.url, "https://vault.bitwarden.com/icons/example.test/icon.png", "fixed icon upstream");
      return upstream();
    };
    try { await run(captured); } finally { globalThis.fetch = previous; }
  };
  const miss = async response => { equal(response.status, 404); equal(response.headers.get("cache-control"), "public, max-age=300"); equal(await response.text(), ""); };

  await check("icon wildcard aliases serve only fixed-upstream raster content and preserve cache policy", async () => {
    const f = fixture();
    await withIcon(f, () => new Response(new Uint8Array([137, 80, 78, 71]), { headers: { "Content-Type": "IMAGE/PNG; charset=binary" } }), async captured => {
      for (const path of ["/icons/example.test", "/icons/example.test/icon.png", "/icons/example.test/icon.png///"]) {
        const response = await f.fetch(path); equal(response.status, 200); equal(response.headers.get("cache-control"), "public, max-age=604800, immutable");
        equal([...new Uint8Array(await response.arrayBuffer())].join(","), "137,80,78,71");
      }
      equal(captured.length, 3);
      for (const path of ["/icons/bad%40example.test/icon.png", "/icons/example.test/unexpected", "/icons/-bad.test"]) await miss(await f.fetch(path));
      f.env.DISABLE_ICON_DOWNLOAD = "true"; await miss(await f.fetch("/icons/example.test")); equal(captured.length, 3);
    });
  });

  await check("icon misses, redirects and active or unknown formats never become long-lived successful content", async () => {
    const f = fixture();
    for (const [status, kind] of [[404, "text/html"], [500, "image/png"], [302, "image/png"], [200, "image/svg+xml"], [200, "text/html"], [200, "image/unknown"], [200, ""]]) {
      await withIcon(f, () => new Response("untrusted upstream", { status, headers: kind ? { "Content-Type": kind } : {} }), async () => miss(await f.fetch("/icons/example.test/icon.png")));
    }
    await withIcon(f, () => new Response(new Uint8Array([1]), { headers: { "Content-Type": "image/png", "Content-Length": String(5 * 1024 * 1024 + 1) } }), async () => miss(await f.fetch("/icons/example.test")));
  });

  await check("icons without Content-Length stop reading when their streamed body exceeds five MiB", async () => {
    const f = fixture(); let pulled = 0;
    await withIcon(f, () => new Response(new ReadableStream({ pull(controller) {
      if (++pulled > 32) { controller.close(); return; } controller.enqueue(new Uint8Array(1024 * 1024));
    } }), { headers: { "Content-Type": "image/png" } }), async () => {
      await miss(await f.fetch("/icons/example.test")); ok(pulled < 12, `Oversized icon consumed ${pulled} chunks`);
    });
  });

  const seedCredential = (id, user, usage, slot) => sql.exec("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,created_at,updated_at) VALUES(?,?,?,?,?,'public',?,'old','old')", id, user, slot, id, `wire-${id}`, usage);
  const seed2fa = () => {
    const f = fixture(); seedCredential("route-2fa-one", USER, "2fa", 1); seedCredential("route-2fa-two", USER, "2fa", 2);
    seedCredential("route-passkey", USER, "login", 3); seedCredential("route-other", "other-owner", "2fa", 1);
    sql.exec("UPDATE users SET two_factor_recovery_code='existing-recovery' WHERE id=?", USER);
    for (const type of [5, 7]) sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,?,1,'{}',0)", `route-factor-${type}`, USER, type);
    for (const purpose of ["register.2fa", "assert.2fa", "assert.login"]) sql.exec("INSERT INTO webauthn_challenges(id,challenge,purpose,user_id,rp_id,origin,expires_at) VALUES(?,?,?,?, 'vault.test','https://vault.test','2099-01-01T00:00:00Z')", purpose, purpose, purpose, USER);
    return f;
  };
  const proof = async f => (await expect(await request(f, "/api/two-factor/get-webauthn", { masterPasswordHash: "hash" }), 200)).userVerificationToken;
  const clear = (f, token) => request(f, "/api/two-factor/webauthn/all", { userVerificationToken: token }, "DELETE");
  const state = () => JSON.stringify(Object.fromEntries(["users", "devices", "webauthn_credentials", "webauthn_challenges", "two_factors"].map(table => [table, sql.exec(`SELECT * FROM ${table} ORDER BY rowid`).toArray()])));
  const isClear = statements => statements[0]?.sql.includes("json_array_length(?7)>0");

  await check("dedicated WebAuthn clear requires the matching purpose proof and preserves login passkeys", async () => {
    const f = seed2fa(), token = await proof(f), before = state();
    await expect(await request(f, "/api/two-factor/get-webauthn", { userVerificationToken: token }), 400); equal(state(), before);
    await expect(await request(f, "/api/two-factor/webauthn/all", { masterPasswordHash: "hash" }, "DELETE"), 400); equal(state(), before);
    const totp = await expect(await request(f, "/api/two-factor/get-authenticator", { masterPasswordHash: "hash" }), 200);
    await expect(await clear(f, totp.userVerificationToken), 401); equal(state(), before);
    const result = await expect(await clear(f, token), 200); equal(result.enabled, false); equal(result.keys.length, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id=? AND credential_use='2fa'", USER).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE credential_use='login'").one().n, 1);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id='other-owner'").one().n, 1);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_challenges").one().n, 1);
    equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=?", USER).one().n, 0);
    equal(sql.exec("SELECT two_factor_recovery_code FROM users WHERE id=?", USER).one().two_factor_recovery_code, null);
    const cleared = state(); await expect(await clear(f, token), 400); equal(state(), cleared);
  });

  await check("WebAuthn bulk clear fences every observed credential field, set membership, account and session before cleanup", async () => {
    for (const mode of ["counter", "name", "key", "addition", "session", "account"]) {
      const f = seed2fa(), token = await proof(f), batch = f.db.batch.bind(f.db); let reached = false, expected;
      f.db.batch = async statements => {
        if (!reached && isClear(statements)) {
          reached = true;
          if (mode === "addition") seedCredential("concurrent", USER, "2fa", 4);
          else if (mode === "session") sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
          else if (mode === "account") sql.exec("UPDATE users SET key='concurrent-wrapper' WHERE id=?", USER);
          else sql.exec(`UPDATE webauthn_credentials SET ${mode === "counter" ? "sign_count=sign_count+1" : mode === "name" ? "name='concurrent'" : "public_key='concurrent'"} WHERE id='route-2fa-one'`);
          expected = state();
        }
        return batch(statements);
      };
      await expect(await clear(f, token), 409); equal(reached, true); equal(state(), expected);
    }
  });

  await check("WebAuthn bulk clear rolls back late recovery failures and retains independent factors", async () => {
    let f = seed2fa(), token = await proof(f);
    sql.exec("CREATE TRIGGER route_clear_failure BEFORE UPDATE OF two_factor_recovery_code ON users BEGIN SELECT RAISE(ABORT,'injected clear failure'); END");
    const before = state(); await expect(await clear(f, token), 500); equal(state(), before);
    f = seed2fa(); token = await proof(f);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('route-email',?,1,1,'{}',0)", USER);
    await expect(await clear(f, token), 200); equal(sql.exec("SELECT two_factor_recovery_code FROM users WHERE id=?", USER).one().two_factor_recovery_code, "existing-recovery");
  });

  await check("WebAuthn collection update uses assertion identity and retains authentication and required proof checks", async () => {
    const f = fixture(), body = { deviceResponse: {}, encryptedUserKey: "2.user", encryptedPrivateKey: "2.private", encryptedPublicKey: "2.public" };
    await expect(await request(f, "/api/webauthn", body, "PUT", false), 401);
    await expect(await request(f, "/api/webauthn", body, "PUT"), 400);
    const before = state();
    await expect(await request(f, "/api/webauthn", { ...body, deviceResponse: { id: "not-registered" } }, "PUT"), 401);
    equal(state(), before);
  });

  await check("WebAuthn collection PUT verifies a real RSA assertion and updates exactly its owned passkey", async () => {
    const f = fixture(), encoder = new TextEncoder();
    const b64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    const decode = value => Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), char => char.charCodeAt(0));
    const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey), n = decode(jwk.n), e = decode(jwk.e);
    const cborBytes = bytes => bytes.length < 24 ? [0x40 + bytes.length, ...bytes] : bytes.length < 256 ? [0x58, bytes.length, ...bytes] : [0x59, bytes.length >> 8, bytes.length & 255, ...bytes];
    const cose = new Uint8Array([0xa4, 1, 3, 3, 0x39, 1, 0, 0x20, ...cborBytes(n), 0x21, ...cborBytes(e)]);
    const id = b64(encoder.encode("route-assertion-key"));
    seedCredential("route-rsa", USER, "login", 1);
    sql.exec("UPDATE webauthn_credentials SET credential_id=?,public_key=? WHERE id='route-rsa'", id, b64(cose));
    const issued = await expect(await request(f, "/api/webauthn/assertion-options", { masterPasswordHash: "hash" }), 200);
    const client = encoder.encode(JSON.stringify({ type: "webauthn.get", challenge: issued.options.challenge, origin: "https://vault.test", crossOrigin: false }));
    const auth = new Uint8Array(37); auth.set(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode("vault.test")))); auth[32] = 5; new DataView(auth.buffer).setUint32(33, 1, false);
    const signed = new Uint8Array(auth.length + 32); signed.set(auth); signed.set(new Uint8Array(await crypto.subtle.digest("SHA-256", client)), auth.length);
    const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, signed));
    const body = { token: issued.token, name: "Updated passkey", encryptedPublicKey: "2.updated-public", encryptedUserKey: "2.updated-user", encryptedPrivateKey: "2.updated-private",
      deviceResponse: { id, rawId: id, response: { clientDataJSON: b64(client), authenticatorData: b64(auth), signature: b64(signature) } } };
    const result = await expect(await request(f, "/api/webauthn", body, "PUT"), 200);
    equal(result.data.length, 1); equal(result.data[0].name, "Updated passkey");
    const stored = sql.exec("SELECT * FROM webauthn_credentials WHERE id='route-rsa'").one();
    equal(stored.sign_count, 1); equal(stored.encrypted_public_key, body.encryptedPublicKey); equal(stored.encrypted_user_key, body.encryptedUserKey); equal(stored.encrypted_private_key, body.encryptedPrivateKey);
    const before = state(); await expect(await request(f, "/api/webauthn", body, "PUT"), 400); equal(state(), before);
  });
}
