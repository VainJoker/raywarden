import { bearerJsonHeaders, equal, expectStatus as expect, ok } from "./runtime-assertions.mjs";
import { captureNotifications } from "./runtime-fixture.mjs";

/** API-key, domain-setting and logical storage contracts in real Worker WASM. */
export async function runAccountSettingsChecks({ fixture, check, sql, accessToken, USER, CIPHER, SEND }) {
  const owner = async () => bearerJsonHeaders(await accessToken());
  const api = async (f, rotate = false, hash = "hash") => f.fetch(`/api/accounts/${rotate ? "rotate-api-key" : "api-key"}`, {
    method: "POST", headers: await owner(), body: JSON.stringify({ masterPasswordHash: hash }),
  });
  const apiJson = async (f, rotate = false) => (await expect(await api(f, rotate), 200)).json();
  const state = () => JSON.stringify(Object.fromEntries(["users", "devices", "user_api_keys", "user_api_key_sessions"]
    .map(table => [table, sql.exec(`SELECT * FROM ${table} ORDER BY rowid`).toArray()])));
  const unchanged = before => equal(state() === before, true, "rejected operation changed account or session state");
  const isApi = statements => statements.some(value => value.sql.startsWith("UPDATE users SET account_write_token="));
  async function competing(f, operation) {
    const batch = f.db.batch.bind(f.db); let waiting = 0, release;
    const ready = new Promise(resolve => { release = resolve; });
    f.db.batch = async statements => {
      if (isApi(statements)) { if (++waiting === 2) release(); await ready; }
      return batch(statements);
    };
    const result = await Promise.all([operation(), operation()]);
    equal(waiting, 2, "both verified API requests must reach the conditional write");
    return result;
  }

  await check("profile and avatar writes wait for the two-factor status read", async () => {
    for (const [action, field, column, value] of [
      ["profile", "name", "name", "Updated name"],
      ["avatar", "avatarColor", "avatar_color", "#abcdef"],
    ]) {
      const f = fixture(), before = state();
      const request = async () => f.fetch(`/api/accounts/${action}`, {
        method: "PUT", headers: await owner(), body: JSON.stringify({ [field]: value }),
      });
      const execute = f.db.execute;
      let reads = 0;
      f.db.execute = function (query, params) {
        if (query.includes("FROM two_factors")) {
          reads++;
          throw new Error("injected profile two-factor query failure");
        }
        return execute.call(this, query, params);
      };

      await expect(await request(), 500);
      equal(reads, 1, `${action} two-factor reads`);
      unchanged(before);

      f.db.execute = execute;
      const response = await expect(await request(), 200);
      equal((await response.json())[field], value);
      equal(f.db.row("users", USER)[column], value);
    }
  });

  await check("profile and avatar writes advance a sync revision ahead of the Worker clock", async () => {
    const f = fixture();
    let revision = "2099-01-01T00:00:00.000Z";
    sql.exec("UPDATE users SET updated_at=? WHERE id=?", revision, USER);
    for (const [path, body] of [
      ["/api/accounts/profile", { name: "Profile" }],
      ["/api/accounts/avatar", { avatarColor: "#abcdef" }],
    ]) {
      await expect(await f.fetch(path, { method: "PUT", headers: await owner(), body: JSON.stringify(body) }), 200);
      const updated = f.db.row("users", USER).updated_at;
      equal(Date.parse(updated), Date.parse(revision) + 1);
      revision = updated;
    }

    // Revoking the device session between Claims validation and the write batch rejects with 409.
    for (const [path, method, body] of [
      ["/api/accounts/profile", "PUT", { name: "Revoked" }],
      ["/api/accounts/avatar", "PUT", { avatarColor: "#112233" }],
      ["/api/accounts/key-management/user-key-id", "POST", { userKeyId: "0123456789abcdef0123456789abcdef" }],
    ]) {
      const fRace = fixture();
      const batch = fRace.db.batch.bind(fRace.db);
      let expected;
      fRace.db.batch = async statements => {
        sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
        expected = state();
        return batch(statements);
      };
      await expect(await fRace.fetch(path, { method, headers: await owner(), body: JSON.stringify(body) }), 409);
      unchanged(expected);
    }
  });

  await check("API-key current reads reuse the persisted value without writes and reject incorrect passwords", async () => {
    const f = fixture(), first = await apiJson(f), before = state();
    const second = await apiJson(f);
    equal(second.apiKey, first.apiKey); equal(second.revisionDate, first.revisionDate); unchanged(before);
    await expect(await api(f, false, "wrong-password"), 401); unchanged(before);
  });

  await check("simultaneous first API-key requests return the same single persisted winner", async () => {
    const f = fixture(), responses = await competing(f, () => api(f));
    const values = await Promise.all(responses.map(async value => (await expect(value, 200)).json()));
    equal(values[0].apiKey, values[1].apiKey);
    equal(sql.exec("SELECT COUNT(*) AS n FROM user_api_keys WHERE user_id=?", USER).one().n, 1);
    equal((await apiJson(f)).apiKey, values[0].apiKey);
  });

  await check("simultaneous rotations of one verified API-key snapshot publish exactly one new secret", async () => {
    const f = fixture(), old = await apiJson(f), responses = await competing(f, () => api(f, true));
    equal(responses.map(value => value.status).sort().join(","), "200,409");
    const winner = await responses.find(value => value.status === 200).json();
    await responses.find(value => value.status === 409).text();
    ok(winner.apiKey !== old.apiKey, "rotation retained the old secret");
    equal((await apiJson(f)).apiKey, winner.apiKey);
  });

  await check("API-key rotation rejects changed credentials, envelope, nonce, stamp and prior key before revocation", async () => {
    for (const mode of ["stamp", "nonce", "hash", "salt", "cost", "envelope", "key"]) {
      const f = fixture(); await apiJson(f);
      let expected;
      const reached = f.db.beforeNextBatch(isApi, () => {
        if (mode === "nonce") sql.exec("UPDATE devices SET session_token='new-session' WHERE user_id=?", USER);
        else if (mode === "key") sql.exec("UPDATE user_api_keys SET key_hash='concurrent-api-hash' WHERE user_id=?", USER);
        else {
          const columns = { stamp: "security_stamp", hash: "master_password_hash", salt: "password_salt", cost: "password_iterations", envelope: "key" };
          sql.exec(`UPDATE users SET ${columns[mode]}=? WHERE id=?`, mode === "cost" ? 1200000 : `new-${mode}`, USER);
        }
        expected = state();
      });
      await expect(await api(f, true), 409); ok(reached(), "API rotation race missed the production batch"); unchanged(expected);
    }
  });

  await check("a current API-key read cannot reveal a key after its verified session or credential snapshot changes", async () => {
    for (const mode of ["nonce", "hash"]) {
      const f = fixture(); await apiJson(f);
      const prepare = f.db.prepare.bind(f.db); let reached = false, expected;
      f.db.prepare = query => {
        if (!reached && query.startsWith("SELECT encrypted_key,key_hash,updated_at FROM user_api_keys WHERE") && query.includes("EXISTS")) {
          reached = true;
          if (mode === "nonce") sql.exec("UPDATE devices SET session_token='new-session' WHERE user_id=?", USER);
          else sql.exec("UPDATE users SET master_password_hash='new-verifier' WHERE id=?", USER);
          expected = state();
        }
        return prepare(query);
      };
      await expect(await api(f), 409); ok(reached, "API read race missed the actual current-row query"); unchanged(expected);
    }
  });

  await check("API-key failures roll back all revocation and successful rotation preserves a newer password session", async () => {
    const f = fixture(); await apiJson(f);
    sql.exec("INSERT INTO user_api_key_sessions VALUES(?,'device','old-api-session')", USER);
    sql.exec("INSERT INTO devices(user_id,device_id,name,device_type,session_token,created_at,updated_at) VALUES(?,'api-device','CLI',14,'api-session','old','old')", USER);
    sql.exec("INSERT INTO user_api_key_sessions VALUES(?,'api-device','api-session')", USER);
    sql.exec("INSERT INTO user_api_keys VALUES('other-owner','other-encrypted','other-hash','other-time')");
    const other = JSON.stringify(sql.exec("SELECT * FROM user_api_keys WHERE user_id='other-owner'").one());
    sql.exec("CREATE TRIGGER misc_api_failure BEFORE INSERT ON user_api_keys BEGIN SELECT RAISE(ABORT,'injected API-key failure'); END");
    const before = state(); await expect(await api(f, true), 500); unchanged(before);
    sql.exec("DROP TRIGGER misc_api_failure");
    await apiJson(f, true);
    equal(sql.exec("SELECT session_token FROM devices WHERE user_id=? AND device_id='device'", USER).one().session_token, "session");
    equal(sql.exec("SELECT COUNT(*) AS n FROM devices WHERE user_id=? AND device_id='api-device'", USER).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM user_api_key_sessions WHERE user_id=?", USER).one().n, 0);
    equal(JSON.stringify(sql.exec("SELECT * FROM user_api_keys WHERE user_id='other-owner'").one()), other);
    await expect(await f.fetch("/api/accounts/profile", { headers: await owner() }), 200);
  });

  await check("an API-key-authenticated session can rotate its key successfully before its own session is revoked", async () => {
    const f = fixture(), original = await apiJson(f);
    const authenticated = await (await expect(await f.fetch("/identity/connect/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Bitwarden-Client-Version": "2026.10.2", "device-type": "14" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: `user.${USER}`, client_secret: original.apiKey,
        scope: "api offline_access", deviceIdentifier: "misc-api-client", deviceName: "API Runtime", deviceType: "14" }),
    }), 200)).json();
    const apiHeaders = { Authorization: `Bearer ${authenticated.access_token}`, "Content-Type": "application/json" };
    await expect(await f.fetch("/api/accounts/profile", { headers: apiHeaders }), 200);
    const rotated = await (await expect(await f.fetch("/api/accounts/rotate-api-key", { method: "POST", headers: apiHeaders,
      body: '{"masterPasswordHash":"hash"}' }), 200)).json();
    ok(rotated.apiKey !== original.apiKey, "API session failed to rotate its own key");
    await expect(await f.fetch("/api/accounts/profile", { headers: apiHeaders }), 401);
    await expect(await f.fetch("/api/accounts/profile", { headers: await owner() }), 200);
    equal((await apiJson(f)).apiKey, rotated.apiKey);
  });

  await check("an API key rotated before binding cannot replace a live device nonce", async () => {
    const f = fixture(), apiKey = (await apiJson(f)).apiKey;
    const headers = await owner();
    const batch = f.db.batch.bind(f.db); let expected;
    f.db.batch = async statements => {
      if (!expected && statements.some(statement => statement.sql.includes("user_api_key_sessions(user_id,device_id,session_token)"))) {
        sql.exec("UPDATE user_api_keys SET key_hash='replacement-key' WHERE user_id=?", USER);
        expected = state();
      }
      return batch(statements);
    };
    const response = await expect(await f.fetch("/identity/connect/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Bitwarden-Client-Version": "2026.10.2", "device-type": "14" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "user." + USER, client_secret: apiKey,
        scope: "api offline_access", deviceIdentifier: "device", deviceName: "API Runtime", deviceType: "14" }),
    }), 400);
    await response.text(); ok(expected, "the race did not reach the production session batch"); unchanged(expected);
    await expect(await f.fetch("/api/accounts/profile", { headers }), 200);
  });

  const domains = async (f, body, method = "POST", authorized = true) => f.fetch("/api/settings/domains", {
    method, headers: authorized ? await owner() : { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const settings = () => sql.exec("SELECT equivalent_domains,excluded_globals,updated_at FROM users WHERE id=?", USER).one();
  const payload = { equivalentDomains: [["one.example", "two.example"]], excludedGlobalEquivalentDomains: [1, 2] };
  const isDomains = statements => statements.some(value => value.sql.startsWith("UPDATE users SET equivalent_domains"));
  function notificationType(value) {
    const bytes = Uint8Array.from(atob(value.message), char => char.charCodeAt(0));
    // Type is a short MessagePack map key followed by its positive fixint value.
    const key = [0xa4, 0x54, 0x79, 0x70, 0x65];
    for (let i = 0; i < bytes.length - key.length; i++) if (key.every((byte, at) => bytes[i + at] === byte)) return bytes[i + key.length];
    throw new Error("Notification frame has no Type entry");
  }

  await check("domain POST and PUT require a session, advance the cursor and notify once per write", async () => {
    const f = fixture(), captured = captureNotifications(f);
    sql.exec("UPDATE users SET updated_at='2099-01-01T00:00:00.000Z' WHERE id=?", USER);
    const other = JSON.stringify(sql.exec("SELECT * FROM users WHERE id='other-owner'").one());
    let previous = settings().updated_at;
    for (const method of ["POST", "PUT"]) {
      const notifications = captured.length;
      await expect(await domains(f, payload, method), 200);
      const current = settings(); ok(Date.parse(current.updated_at) > Date.parse(previous), "domain cursor did not increase"); previous = current.updated_at;
      equal(current.equivalent_domains, JSON.stringify(payload.equivalentDomains)); equal(current.excluded_globals, JSON.stringify(payload.excludedGlobalEquivalentDomains));
      equal(captured.length, notifications + 1);
      await expect(await domains(f, {}, method, false), 401);
      equal(JSON.stringify(settings()), JSON.stringify(current));
      equal(captured.length, notifications + 1);
    }
    equal(captured.length, 2); for (const event of captured) { equal(notificationType(event), 10); equal(event.selector.user_id, USER); }
    equal(JSON.stringify(sql.exec("SELECT * FROM users WHERE id='other-owner'").one()), other);
  });

  await check("settings and sync project cached domain exclusions once in cache order", async () => {
    const f = fixture();
    sql.exec("INSERT INTO global_domains_cache VALUES(1, 4000000000)");
    for (const [order, type, domain] of [[0, 20, "first.test"], [1, 1, "second.test"], [2, 10, "third.test"]]) {
      sql.exec("INSERT INTO global_equivalent_domains(type,sort_order,domains_json) VALUES(?,?,?)", type, order, JSON.stringify([domain]));
    }
    const headers = await owner();
    for (const [excluded, expectedSettings, expectedSync] of [
      ["[1,1]", [[20, false], [1, true], [10, false]], [[20, false], [10, false]]],
      ["{invalid", [[20, false], [1, false], [10, false]], [[20, false], [1, false], [10, false]]],
    ]) {
      sql.exec("UPDATE users SET excluded_globals=? WHERE id=?", excluded, USER);
      const settings = await (await expect(await f.fetch("/api/settings/domains", { headers }), 200)).json();
      const sync = await (await expect(await f.fetch("/api/sync", { headers }), 200)).json();
      const groups = response => response.globalEquivalentDomains.map(group => [group.type, group.excluded]);
      equal(JSON.stringify(groups(settings)), JSON.stringify(expectedSettings));
      equal(JSON.stringify(groups(sync.domains)), JSON.stringify(expectedSync));
    }
  });

  await check("invalid persisted equivalent domains leave settings and sync readable", async () => {
    const f = fixture(), headers = await owner();
    sql.exec("INSERT INTO global_domains_cache VALUES(1, 4000000000)");
    for (const invalid of ["[", '{"domains":[]}', '[1]', '[[false]]']) {
      sql.exec("UPDATE users SET equivalent_domains=? WHERE id=?", invalid, USER);
      const settings = await (await expect(await f.fetch("/api/settings/domains", { headers }), 200)).json();
      const sync = await (await expect(await f.fetch("/api/sync", { headers }), 200)).json();
      equal(JSON.stringify(settings.equivalentDomains), "[]");
      equal(JSON.stringify(sync.domains.equivalentDomains), "[]");
      equal(sql.exec("SELECT equivalent_domains FROM users WHERE id=?", USER).one().equivalent_domains, invalid);
    }
    await expect(await domains(f, payload), 200);
    const corrected = await (await expect(await f.fetch("/api/settings/domains", { headers }), 200)).json();
    equal(JSON.stringify(corrected.equivalentDomains), JSON.stringify(payload.equivalentDomains));
  });

  await check("domain mutations reject stale sessions, keys or settings and roll back late cursor failures", async () => {
    for (const [mode, status] of [["nonce", 401], ["stamp", 401], ["key", 400], ["settings", 400], ["cursor-failure", 500]]) {
      const f = fixture(), captured = captureNotifications(f);
      if (mode === "cursor-failure") sql.exec("CREATE TRIGGER misc_domain_failure BEFORE UPDATE OF updated_at ON users BEGIN SELECT RAISE(ABORT,'injected domain cursor failure'); END");
      let expected;
      const reached = f.db.beforeNextBatch(isDomains, () => {
        if (mode === "nonce") sql.exec("UPDATE devices SET session_token='new-session' WHERE user_id=?", USER);
        else if (mode === "stamp") sql.exec("UPDATE users SET security_stamp='new-stamp' WHERE id=?", USER);
        else if (mode === "key") sql.exec("UPDATE users SET key='new-wrapped-key' WHERE id=?", USER);
        else if (mode === "settings") sql.exec("UPDATE users SET equivalent_domains='[[\"concurrent.example\"]]' WHERE id=?", USER);
        expected = state();
      });
      await expect(await domains(f, payload), status);
      ok(reached(), "domain race missed the actual batch"); unchanged(expected); equal(captured.length, 0);
    }
  });

  await check("logical usage counts UTF-8 bytes, separates file storage and never exposes another owner", async () => {
    const f = fixture(), text = '{"name":"€🙂"}';
    sql.exec("UPDATE ciphers SET data=? WHERE id=?", text, CIPHER);
    const inspect = async path => (await expect(await f.fetch(path, { headers: await owner() }), 200)).json();
    const first = await inspect("/api/d1/usage");
    equal(first.isEstimate, true); equal(first.quotaIsEstimate, true); equal(first.quotaSource, "reference-budget");
    equal(first.totalBytes, first.d1Bytes + first.r2Bytes); equal(first.fileBytes, first.r2Bytes);
    equal(first.items.find(item => item.key === "ciphers").bytes, new TextEncoder().encode(text).length);
    equal(first.items.filter(item => item.storage === "d1").reduce((sum, item) => sum + item.bytes, 0), first.d1Bytes);
    equal(first.items.filter(item => item.storage === "r2").reduce((sum, item) => sum + item.bytes, 0), first.r2Bytes);
    equal(first.sendFilesBytes, sql.exec("SELECT file_size_bytes FROM sends WHERE id=?", SEND).one().file_size_bytes);
    equal(first.remainingBytes, Math.max(0, first.maxBytes - first.d1Bytes));
    sql.exec("UPDATE users SET key='other-owner-has-a-much-larger-key' WHERE id='other-owner'");
    equal(JSON.stringify(await inspect("/api/d1/usage")), JSON.stringify(first));
    await expect(await f.fetch("/api/d1/usage?userId=other-owner", { headers: await owner() }), 401);
  });
}
