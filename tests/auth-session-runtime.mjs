/** OAuth aliases, safe cookie fallback and remembered-factor CAS contracts. */
export async function runAuthSessionChecks({ fixture, check, sql, accessToken, USER }) {
  const DEVICE = "identity-parity-device", EMAIL = "owner@example.test", REMEMBER = "legacy-remember-proof";
  const equal = (actual, expected, label = "value") => { if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`); };
  const expect = async (response, status) => {
    if (response.status !== status) throw new Error(`Expected HTTP ${status}, received ${response.status}: ${await response.text()}`);
    return response;
  };
  const token = (f, fields, headers = {}) => f.fetch("/identity/connect/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "device-type": "14", "Bitwarden-Client-Version": "2026.10.1", ...headers },
    body: fields instanceof URLSearchParams ? fields : new URLSearchParams(fields) });
  const login = (f, extra = {}, headers = {}) => token(f, { grant_type: "password", username: EMAIL, password: "hash",
    deviceIdentifier: DEVICE, deviceName: "Identity parity", deviceType: "14", ...extra }, headers);
  const state = () => JSON.stringify({ users: sql.exec("SELECT * FROM users ORDER BY id").toArray(),
    devices: sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray(),
    factors: sql.exec("SELECT * FROM two_factors ORDER BY id").toArray() });
  const refreshCookie = value => `bw_refresh_token=${value}`;
  const refresh = (f, value) => token(f, { grant_type: "refresh_token", refresh_token: value });
  const claims = value => JSON.parse(atob(value.split(".")[1].replaceAll("-", "+").replaceAll("_", "/")));
  const remembered = (days = 30, age = 0) => {
    const f = fixture(); f.env.TWO_FACTOR_REMEMBER_DAYS = String(days);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('identity-totp',?,0,1,'JBSWY3DPEHPK3PXP',0)", USER);
    sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('identity-remember',?,5,1,?,0)", USER,
      JSON.stringify({ tokens: [{ device_id: DEVICE, token: REMEMBER, created_at: Math.floor(Date.now() / 1000) - age * 86400 }] }));
    return f;
  };

  await check("token aliases normalize case and underscores while canonical duplicates fail before writes", async () => {
    const f = fixture();
    const response = await expect(await token(f, { GrAnTtYpE: " password ", USERNAME: ` ${EMAIL.toUpperCase()} `, PASSWORD: "hash", DEVICEID: DEVICE, DEVICENAME: "Phone", DEVICETYPE: "14", CLIENTID: "web" }), 200);
    const body = await response.json();
    equal(body.MasterPasswordPolicy.Object, "masterPasswordPolicy"); equal(body.UserDecryptionOptions.Object, "userDecryptionOptions");
    const before = state();
    for (const [field, duplicates] of [
      ["grant_type", [["GRANTTYPE", "refresh_token"]]],
      ["twoFactorToken", [["twoFactorToken", " \t "], ["TWO_FACTOR_TOKEN", "proof"]]],
      ["deviceIdentifier", [["deviceId", "one"], ["DEVICE_IDENTIFIER", "two"]]],
      ["access_code", [["code", "one"], ["ACCESS_CODE", "two"]]],
    ]) {
      const fields = new URLSearchParams([["grant_type", "password"], ...duplicates]);
      const error = await (await expect(await token(f, fields), 400)).json();
      equal(error.msg, `Invalid request: Duplicate token field: ${field}`);
      equal(state(), before);
    }
    await expect(await token(f, { grant_type: "password", username: EMAIL, password: "wrong", deviceType: "invalid" }), 400);
  });

  await check("refresh cookies are HttpOnly origin-scoped and refresh returns only standard OAuth fields", async () => {
    const f = fixture(), issued = await expect(await login(f), 200);
    const cookies = issued.headers.get("set-cookie");
    for (const value of ["bw_refresh_token=", "HttpOnly", "SameSite=Strict", "Path=/identity/connect/token", "Secure"]) equal(cookies.includes(value), true, value);
    equal(issued.headers.get("cache-control"), "no-store");
    const tokens = await issued.json();
    const response = await expect(await token(f, { GRANT_TYPE: "refresh_token" }, { Cookie: refreshCookie(tokens.refresh_token), Origin: "https://vault.test", "Sec-Fetch-Site": "same-origin" }), 200);
    const refreshed = await response.json();
    equal(Object.keys(refreshed).sort().join(","), "access_token,expires_in,refresh_token,scope,token_type");
    equal(refreshed.scope, "api offline_access");
    const before = state(), original = claims(tokens.refresh_token);
    for (const value of [refreshed.access_token, refreshed.refresh_token]) {
      const current = claims(value);
      equal(current.sstamp, original.sstamp); equal(current.session_token, original.session_token); equal(current.device, DEVICE);
    }
    await expect(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${refreshed.access_token}` } }), 200);
    await expect(await refresh(f, refreshed.refresh_token), 200); equal(state(), before);
    await expect(await f.fetch("/api/accounts/profile", { headers: { Cookie: `bw_access_token=${tokens.access_token}` } }), 401);
    await expect(await token(f, { grant_type: "refresh_token" }, { Cookie: refreshCookie(tokens.refresh_token) }), 200);
  });

  await check("refresh form proofs take priority; cross-origin cookies and invalid grants never modify sessions", async () => {
    const f = fixture(), tokens = await (await expect(await login(f), 200)).json(), before = state();
    for (const headers of [
      { Origin: "https://attacker.test" }, { Origin: "https://vault.test", "Sec-Fetch-Site": "cross-site" },
      { Origin: "https://vault.test", "Sec-Fetch-Site": "same-site" }, { Origin: "null" },
    ]) { await expect(await token(f, { grant_type: "refresh_token" }, { Cookie: refreshCookie(tokens.refresh_token), ...headers }), 401); equal(state(), before); }
    await expect(await token(f, { grant_type: "refresh_token" }, { Cookie: `${refreshCookie(tokens.refresh_token)}; ${refreshCookie(tokens.refresh_token)}` }), 400);
    for (const fields of [{ grant_type: "refresh_token" }, { grant_type: "refresh_token", refresh_token: "invalid" },
      { grant_type: "refresh_token", refresh_token: "" }]) {
      const response = await expect(await token(f, fields, fields.refresh_token === "" ? { Cookie: refreshCookie(tokens.refresh_token) } : {}), 400);
      equal((await response.json()).error, "invalid_grant"); equal(state(), before);
    }
    const explicit = await expect(await token(f, { grant_type: "refresh_token", refreshToken: tokens.refresh_token },
      { Cookie: "bw_refresh_token=bad; bw_refresh_token=also-bad", Origin: "https://attacker.test", "Sec-Fetch-Site": "cross-site" }), 200);
    equal(explicit.headers.get("set-cookie"), null); equal(state(), before);
  });

  // The adapter still executes production SQL in workerd SQLite. Each hook
  // models a completed credential/session change at one refresh read boundary.
  const revocations = [
    ["password change", "UPDATE users SET master_password_hash='concurrent-password-verifier',password_salt='concurrent-salt',key='2.password-rewrap',security_stamp='concurrent-generation' WHERE id=?"],
    ["KDF change", "UPDATE users SET kdf_iterations=650000,master_password_hash='concurrent-kdf-verifier',key='2.kdf-rewrap',security_stamp='concurrent-generation' WHERE id=?"],
    ["email change", "UPDATE users SET email='changed@example.test',is_email_verified=1,master_password_hash='concurrent-email-verifier',security_stamp='concurrent-generation' WHERE id=?"],
    ["explicit stamp reset", "UPDATE users SET security_stamp='concurrent-generation' WHERE id=?"],
    ["device nonce rotation", "UPDATE devices SET session_token='concurrent-session' WHERE user_id=? AND device_id=?"],
  ];
  const boundaries = [
    { name: "before session validation", query: "SELECT d.session_token, u.security_stamp", occurrence: 1, status: 400, nonceStatus: 400 },
    { name: "between validation and owner read", query: "SELECT * FROM users", occurrence: 1, status: 400, nonceStatus: 400 },
    { name: "between owner and device read", query: "SELECT * FROM devices", occurrence: 1, status: 409, nonceStatus: 400 },
    { name: "before the final account snapshot", query: "SELECT * FROM users", occurrence: 2, status: 409, nonceStatus: 200 },
    { name: "after the final account snapshot", query: "SELECT * FROM users", occurrence: 2, after: true, status: 200, nonceStatus: 200 },
  ];
  for (const boundary of boundaries) {
    await check(`refresh preserves its original generation when revoked ${boundary.name}`, async () => {
      for (const [name, mutation] of revocations) {
        const f = fixture(), tokens = await (await expect(await login(f), 200)).json(), original = claims(tokens.refresh_token);
        const execute = f.db.execute.bind(f.db); let reads = 0, reached = false, revoked;
        const revoke = () => {
          reached = true;
          sql.exec(mutation, ...(name.startsWith("device") ? [USER, DEVICE] : [USER]));
          revoked = state();
        };
        f.db.execute = (query, params) => {
          const matches = !reached && query.startsWith(boundary.query) && ++reads === boundary.occurrence;
          if (matches && !boundary.after) revoke();
          const result = execute(query, params);
          if (matches && boundary.after) revoke();
          return result;
        };
        const status = name.startsWith("device") ? boundary.nonceStatus : boundary.status;
        const response = await refresh(f, tokens.refresh_token);
        equal(response.status, status, `${name} refresh status`);
        equal(reached, true, `${name} missed ${boundary.name}`); equal(state(), revoked, `${name} changed revoked state`);
        const body = await response.json();
        if (status === 400) equal(body.error, "invalid_grant", name);
        if (status === 200) {
          // Revocation after the last relevant read may race with issuance.
          // Such tokens must retain the old stamp/nonce and already be invalid.
          for (const value of [body.access_token, body.refresh_token]) {
            const issued = claims(value);
            equal(issued.sstamp, original.sstamp, `${name} adopted a newer stamp`);
            equal(issued.session_token, original.session_token, `${name} adopted a newer nonce`);
          }
          await expect(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${body.access_token}` } }), 401);
          equal((await (await expect(await refresh(f, body.refresh_token), 400)).json()).error, "invalid_grant");
        }
        await expect(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${tokens.access_token}` } }), 401);
        equal(state(), revoked, `${name} revived a revoked session`);
      }
    });
  }

  await check("remember duration controls legacy proofs, hashes new secrets and emits matching cookie lifetimes", async () => {
    for (const [days, age, status, seconds] of [[1, 2, 400, 86400], [3, 2, 200, 259200], [0, 2, 400, 86400], [1000, 91, 400, 7776000], ["invalid", 2, 200, 2592000]]) {
      const f = remembered(days, age), before = state();
      const response = await expect(await login(f, { two_factor_provider: "5", two_factor_token: REMEMBER, two_factor_remember: "true" }), status);
      if (status !== 200) {
        const challenge = await response.json();
        equal(challenge.error, "invalid_grant");
        equal(challenge.error_description, "Two factor required.");
        equal(JSON.stringify(challenge.TwoFactorProviders), '["0"]');
        equal(JSON.stringify(challenge.TwoFactorProviders2), '{"0":null}');
        equal(challenge.MasterPasswordPolicy.Object, "masterPasswordPolicy");
        equal(state(), before);
        continue;
      }
      const body = await response.json(); equal(typeof body.TwoFactorToken, "string");
      const record = sql.exec("SELECT data FROM two_factors WHERE id='identity-remember'").one().data;
      equal(record.includes(body.TwoFactorToken), false, "new remembered secret stored verbatim"); equal(record.includes("sha256:"), true);
      equal(response.headers.get("set-cookie").includes(`Max-Age=${seconds}`), true);
      await expect(await login(f, { twoFactorProvider: "5", twoFactorToken: body.TwoFactorToken }), 200);
    }
  });

  await check("remember cookies use the same proof validation and reject browser cross-origin fallback", async () => {
    let f = remembered();
    await expect(await login(f, { two_factor_token: " \t " }, { Cookie: `twoFactorRemember=${REMEMBER}; TwoFactorRemember=${REMEMBER}`, Origin: "https://vault.test", "Sec-Fetch-Site": "same-origin" }), 200);
    f = remembered(); const before = state();
    await expect(await login(f, {}, { Cookie: `twoFactorRemember=${REMEMBER}`, Origin: "https://attacker.test" }), 401); equal(state(), before);
    await expect(await login(f, {}, { Cookie: `twoFactorRemember=${REMEMBER}; TwoFactorRemember=different` }), 400); equal(state(), before);
    await expect(await login(f, { twoFactorToken: REMEMBER, twoFactorProvider: "5" }, { Cookie: "twoFactorRemember=bad; twoFactorRemember=also-bad", Origin: "https://attacker.test" }), 200);
  });

  await check("remember renewal and non-renewing logins cannot resurrect or reuse concurrently revoked bypasses", async () => {
    for (const renew of [false, true]) {
      for (const mutation of ["delete", "change", "stamp", "cost"]) {
        const f = remembered(), prepare = f.db.prepare.bind(f.db); let reached = false, expected;
        f.db.prepare = query => {
          if (!reached && query.startsWith("INSERT INTO two_factors") && query.includes("password_iterations=?7")) {
            reached = true;
            if (mutation === "delete") sql.exec("DELETE FROM two_factors WHERE id='identity-remember'");
            else if (mutation === "change") sql.exec("UPDATE two_factors SET data='{}' WHERE id='identity-remember'");
            else if (mutation === "stamp") sql.exec("UPDATE users SET security_stamp='concurrent-stamp' WHERE id=?", USER);
            else sql.exec("UPDATE users SET password_iterations=1200000 WHERE id=?", USER);
            expected = state();
          }
          return prepare(query);
        };
        await expect(await login(f, { twoFactorProvider: "5", twoFactorToken: REMEMBER, twoFactorRemember: renew ? "1" : "0" }), 409);
        equal(reached, true); equal(state(), expected);
      }
    }
  });

  await check("competing remember renewals preserve one winner instead of overwriting a newer proof", async () => {
    const f = remembered(), prepare = f.db.prepare.bind(f.db); let pending = 0, release;
    const ready = new Promise(resolve => { release = resolve; });
    f.db.prepare = query => {
      const statement = prepare(query);
      if (query.startsWith("INSERT INTO two_factors") && query.includes("password_iterations=?7")) {
        const bind = statement.bind.bind(statement);
        statement.bind = (...values) => {
          const bound = bind(...values), first = bound.first.bind(bound);
          bound.first = async column => { if (++pending === 2) release(); await ready; return first(column); };
          return bound;
        };
      }
      return statement;
    };
    const responses = await Promise.all([0, 1].map(() => login(f, { twoFactorProvider: "5", twoFactorToken: REMEMBER, twoFactorRemember: "1" })));
    equal(pending, 2); equal(responses.map(response => response.status).sort().join(","), "200,409");
    for (const response of responses) await response.text();
  });

  const api = async (f, path, body, method = "POST") => f.fetch(path, { method,
    headers: { Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const b64url = bytes => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  const fromB64 = value => Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), char => char.charCodeAt(0));
  const concat = (...values) => {
    const output = new Uint8Array(values.reduce((size, value) => size + value.length, 0));
    let offset = 0; for (const value of values) { output.set(value, offset); offset += value.length; } return output;
  };
  const cborHead = (kind, length) => length < 24 ? Uint8Array.of(kind * 32 + length)
    : length < 256 ? Uint8Array.of(kind * 32 + 24, length) : Uint8Array.of(kind * 32 + 25, length >> 8, length & 255);
  const cbor = value => {
    if (typeof value === "number") return cborHead(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
    if (typeof value === "string") { const bytes = new TextEncoder().encode(value); return concat(cborHead(3, bytes.length), bytes); }
    if (value instanceof Uint8Array) return concat(cborHead(2, value.length), value);
    if (value instanceof Map) return concat(cborHead(5, value.size), ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)]));
    throw new Error("Unsupported CBOR fixture");
  };
  const makePasskey = async (f, prf = {}) => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey), id = crypto.getRandomValues(new Uint8Array(16));
    const options = await (await expect(await api(f, "/api/webauthn/attestation-options", { masterPasswordHash: "hash" }), 200)).json();
    const rp = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(options.options.rp.id)));
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64(jwk.x)], [-3, fromB64(jwk.y)]]));
    const auth = concat(rp, Uint8Array.of(0x45, 0, 0, 0, 0), new Uint8Array(16), Uint8Array.of(0, id.length), id, cose);
    const attestation = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", auth]]));
    const client = new TextEncoder().encode(JSON.stringify({ type: "webauthn.create", challenge: options.token, origin: "https://vault.test", crossOrigin: false }));
    const response = await expect(await api(f, "/api/webauthn", { token: options.token, KeyName: "Runtime passkey", ...prf,
      deviceResponse: { response: { attestationObject: b64url(attestation), clientDataJSON: b64url(client) } } }), 200);
    return { saved: await response.json(), pair, id };
  };

  await check("PRF probe optional capability flags and fallback messages describe the supplied support", async () => {
    const f = fixture();
    for (const [body, supported] of [[{}, false], [{ supportsPrf: false }, false], [{ supportsPrf: true }, true]]) {
      const result = await (await expect(await api(f, "/api/webauthn/prf-probe", body), 200)).json();
      equal(result.supportsPrf, supported); equal(result.canUsePasskeyUnlock, supported); equal(result.requiresPasswordLogin, !supported);
      equal(result.fallback, "master_password"); equal(typeof result.message, "string");
    }
    sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
    await expect(await api(f, "/api/webauthn/prf-probe", {}), 401);
  });

  await check("verified passkey saves report actual complete, supported-only and unsupported PRF states", async () => {
    for (const [prf, status] of [
      [{ supportsPrf: false }, 2], [{ supportsPrf: true }, 1],
      [{ supportsPrf: true, encryptedUserKey: "2.user", encryptedPrivateKey: "2.private" }, 1],
      [{ supportsPrf: true, encryptedUserKey: "2.user", encryptedPrivateKey: "2.private", encryptedPublicKey: "2.public" }, 0],
    ]) {
      const f = fixture(), { saved } = await makePasskey(f, prf);
      equal(saved.success, true); equal(saved.name, "Runtime passkey"); equal(saved.prfStatus, status);
      equal(saved.canUsePasskeyUnlock, status === 0); equal(saved.requiresPasswordLogin, status !== 0); equal(typeof saved.message, "string");
      equal(saved.data.length, 1); equal(saved.Data.length, 1);
      equal(sql.exec("SELECT prf_status FROM webauthn_credentials WHERE user_id=?", USER).one().prf_status, status);
    }
  });

  const prfAssertion = async (f, passkey) => {
    const options = await (await expect(await api(f, "/api/webauthn/assertion-options", { masterPasswordHash: "hash" }), 200)).json();
    const client = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: options.token, origin: "https://vault.test", crossOrigin: false }, null, 2));
    const rp = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(options.options.rpId)));
    const auth = concat(rp, Uint8Array.of(0x05, 0, 0, 0, 1));
    const signed = concat(auth, new Uint8Array(await crypto.subtle.digest("SHA-256", client)));
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passkey.pair.privateKey, signed));
    // WebAuthn transports an ASN.1 DER ECDSA signature, WebCrypto returns r||s.
    const integer = bytes => { let first = 0; while (first < bytes.length - 1 && bytes[first] === 0) first++; const value = bytes.slice(first); return concat(Uint8Array.of(2, value.length + (value[0] >= 128 ? 1 : 0)), value[0] >= 128 ? Uint8Array.of(0) : new Uint8Array(), value); };
    const rs = concat(integer(signature.slice(0, 32)), integer(signature.slice(32)));
    return { token: options.token, encryptedUserKey: "2.new-user", encryptedPrivateKey: "2.new-private", encryptedPublicKey: "2.new-public",
      deviceResponse: { id: b64url(passkey.id), rawId: b64url(passkey.id), type: "public-key", response: {
        clientDataJSON: b64url(client), authenticatorData: b64url(auth), signature: b64url(concat(Uint8Array.of(0x30, rs.length), rs)) } } };
  };

  await check("PRF enable requires all three wrappers and preserves signed session authorization", async () => {
    const f = fixture(), passkey = await makePasskey(f, { supportsPrf: true });
    const body = await prfAssertion(f, passkey), missing = structuredClone(body); delete missing.encryptedPublicKey;
    const path = `/api/webauthn/${passkey.saved.id}`;
    await expect(await api(f, path, missing, "PUT"), 400);
    const invalid = structuredClone(body);
    const clientData = fromB64(body.deviceResponse.response.clientDataJSON);
    for (const bytes of [Uint8Array.of(0x7b), concat(clientData, new Uint8Array(32768).fill(0x20))]) {
      invalid.deviceResponse.response.clientDataJSON = b64url(bytes);
      const error = await (await expect(await api(f, path, invalid, "PUT"), 401)).json();
      equal(error.message, "Invalid credentials: Invalid WebAuthn client data");
    }
    const result = await (await expect(await api(f, path, body, "PUT"), 200)).json();
    equal(result.success, true); equal(result.data[0].prfStatus, 0); equal(result.data[0].encryptedPublicKey, "2.new-public");
  });

  await check("PRF collection updates use the signed credential ID when the route has no path ID", async () => {
    const f = fixture(), passkey = await makePasskey(f, { supportsPrf: true });
    const body = await prfAssertion(f, passkey), missing = structuredClone(body);
    delete missing.deviceResponse.id;
    delete missing.deviceResponse.rawId;
    const error = await (await expect(await api(f, "/api/webauthn", missing, "PUT"), 400)).json();
    equal(error.message, "Invalid request: Missing WebAuthn credential ID");
    await expect(await api(f, "/api/webauthn/%FF", body, "PUT"), 400);
    delete body.deviceResponse.id;
    const result = await (await expect(await api(f, "/api/webauthn", body, "PUT"), 200)).json();
    equal(result.success, true); equal(result.data[0].prfStatus, 0);
  });

  await check("PRF final writes reject a revoked session or newer accepted assertion without changing wrappers", async () => {
    for (const mutation of ["nonce", "stamp", "counter", "challenge", "consumed"]) {
      const f = fixture(), passkey = await makePasskey(f, { supportsPrf: true });
      const body = await prfAssertion(f, passkey), prepare = f.db.prepare.bind(f.db); let reached = false;
      f.db.prepare = query => {
        if (!reached && query.startsWith("UPDATE webauthn_credentials SET name=")) {
          reached = true;
          if (mutation === "nonce") sql.exec("UPDATE devices SET session_token='revoked' WHERE user_id=?", USER);
          else if (mutation === "stamp") sql.exec("UPDATE users SET security_stamp='revoked' WHERE id=?", USER);
          else if (mutation === "counter") sql.exec("UPDATE webauthn_credentials SET sign_count=sign_count+1 WHERE user_id=?", USER);
          else if (mutation === "challenge") sql.exec("UPDATE webauthn_credentials SET last_challenge='newer-proof' WHERE user_id=?", USER);
          else sql.exec("UPDATE webauthn_challenges SET consumed_at=NULL WHERE user_id=? AND purpose='assert.login'", USER);
        }
        return prepare(query);
      };
      await expect(await api(f, `/api/webauthn/${passkey.saved.id}`, body, "PUT"), 409);
      equal(reached, true);
      const record = sql.exec("SELECT prf_status,encrypted_public_key,encrypted_user_key,encrypted_private_key FROM webauthn_credentials WHERE user_id=?", USER).one();
      equal(record.prf_status, 1); equal(record.encrypted_public_key, null); equal(record.encrypted_user_key, null); equal(record.encrypted_private_key, null);
    }
  });

  await check("a PRF assertion for the wrong credential leaves its challenge available", async () => {
    const f = fixture();
    const actual = await makePasskey(f, { supportsPrf: true });
    const target = await makePasskey(f, { supportsPrf: true });
    const actualSlot = Number(actual.saved.id), targetSlot = Number(target.saved.id);
    const body = await prfAssertion(f, actual);
    await expect(await api(f, `/api/webauthn/${target.saved.id}`, body, "PUT"), 401);
    equal(sql.exec("SELECT consumed_at FROM webauthn_challenges WHERE challenge=?", body.token).one().consumed_at, null);
    equal(sql.exec("SELECT sign_count FROM webauthn_credentials WHERE user_id=? AND slot=?", USER, actualSlot).one().sign_count, 0);
    const updated = await (await expect(await api(f, `/api/webauthn/${actual.saved.id}`, body, "PUT"), 200)).json();
    const prfStatus = new Map(updated.data.map(key => [key.id, key.prfStatus]));
    equal(prfStatus.get(actualSlot), 0);
    equal(prfStatus.get(targetSlot), 1);
  });
}
