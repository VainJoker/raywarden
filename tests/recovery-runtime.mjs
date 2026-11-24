import { equal, expectStatus as status } from "./runtime-assertions.mjs";
import { oauthToken } from "./runtime-auth.mjs";

/** Recovery-code ownership, snapshot and transaction regressions. */
export async function runRecoveryCompatibility({ fixture, check, sql }) {
  const CODE = "ABCDEF0123456789ABCDEF0123456789";
  const EMAIL = "owner@example.test";
  const seed = () => {
    const f = fixture();
    const owner = sql.exec("SELECT id FROM users WHERE email=?", EMAIL).one().id;
    for (const user of [owner, "other-owner"]) {
      sql.exec("UPDATE users SET two_factor_recovery_code=? WHERE id=?", CODE, user);
      for (const kind of [0, 1, 5, 7]) {
        sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,?,1,'factor-data',0)", `${user}-${kind}`, user, kind);
      }
      sql.exec("INSERT INTO verification_codes(id,owner_key,user_id,purpose,recipient,code_hash,issued_at,expires_at,ready) VALUES(?,?,?,'email-2fa',?,'code-hash',1,9999999999,1)", `code-${user}`, user, user, `${user}@example.test`);
      for (const use of ["login", "2fa"]) {
        const key = `${user}-${use}`;
        sql.exec("INSERT INTO webauthn_credentials(id,user_id,slot,name,credential_id,public_key,credential_use,created_at,updated_at) VALUES(?,?,1,'key',?,'public',?,'before','before')", key, user, key, use);
      }
    }
    return { ...f, owner };
  };
  const state = () => JSON.stringify({
    users: sql.exec("SELECT * FROM users ORDER BY id").toArray(),
    devices: sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray(),
    providers: sql.exec("SELECT * FROM two_factors ORDER BY id").toArray(),
    codes: sql.exec("SELECT * FROM verification_codes ORDER BY id").toArray(),
    passkeys: sql.exec("SELECT * FROM webauthn_credentials ORDER BY id").toArray(),
  });
  const otherState = () => JSON.stringify({
    user: sql.exec("SELECT * FROM users WHERE id='other-owner'").one(),
    providers: sql.exec("SELECT * FROM two_factors WHERE user_id='other-owner' ORDER BY id").toArray(),
    codes: sql.exec("SELECT * FROM verification_codes WHERE user_id='other-owner' ORDER BY id").toArray(),
    passkeys: sql.exec("SELECT * FROM webauthn_credentials WHERE user_id='other-owner' ORDER BY id").toArray(),
  });
  const recover = (f, override = {}, headers = {}) => f.fetch("/api/two-factor/recover", {
    method: "POST", headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ email: EMAIL, masterPasswordHash: "hash", recoveryCode: CODE, ...override }),
  });
  const login = (f, { version = "2026.10.1", code = CODE, username = EMAIL, device = "recovery-runtime-client" } = {}) => oauthToken(f, {
    grant_type: "password", username, password: "hash",
    deviceIdentifier: device, deviceName: "Recovery Browser", deviceType: "14",
    twoFactorProvider: "8", twoFactorToken: code, twoFactorRemember: "1",
  }, { "device-type": "14", ...(version === null ? {} : { "Bitwarden-Client-Version": version }) });
  const call = (kind, f) => kind === "recover" ? recover(f) : login(f);
  const isRecovery = statements => statements.some(statement => statement.sql.startsWith("UPDATE users SET two_factor_recovery_code=NULL,account_write_token="));
  const assertCleared = (f, other) => {
    equal(sql.exec("SELECT two_factor_recovery_code FROM users WHERE id=?", f.owner).one().two_factor_recovery_code, null);
    equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=?", f.owner).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM verification_codes WHERE user_id=?", f.owner).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id=? AND credential_use='2fa'", f.owner).one().n, 0);
    equal(sql.exec("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id=? AND credential_use='login'", f.owner).one().n, 1);
    equal(otherState(), other, "other user's authentication state");
  };

  await check("public recovery atomically consumes its code and factors while preserving login keys and other users", async () => {
    const f = seed(), other = otherState();
    const stamp = sql.exec("SELECT security_stamp FROM users WHERE id=?", f.owner).one().security_stamp;
    const devices = JSON.stringify(sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray());
    await status(await recover(f, { email: " Owner@Example.TEST ", recoveryCode: CODE.toLowerCase() }), 200);
    assertCleared(f, other);
    equal(sql.exec("SELECT security_stamp FROM users WHERE id=?", f.owner).one().security_stamp, stamp);
    equal(JSON.stringify(sql.exec("SELECT * FROM devices ORDER BY user_id,device_id").toArray()), devices, "public recovery retains the existing session policy");
    const completed = state();
    await status(await recover(f), 401);
    equal(state(), completed, "replayed public recovery cannot change state");
  });

  await check("incorrect recovery credentials leave every provider and verification record intact", async () => {
    const f = seed(), before = state();
    for (const body of [{ masterPasswordHash: "wrong-password" }, { recoveryCode: "wrong-code" }, { email: "missing@example.test" }]) {
      const response = await status(await recover(f, body), 401);
      if (body.recoveryCode) {
        const error = await response.json();
        equal(error.code, 2);
        equal(error.message, "Invalid credentials: Invalid recovery code");
      }
      equal(state(), before);
    }
    sql.exec("UPDATE users SET two_factor_recovery_code='' WHERE id=?", f.owner);
    const invalid = state();
    await status(await recover(f, { recoveryCode: "" }), 401);
    equal(state(), invalid);
  });

  await check("both recovery entry points reject changed credential and raw-code snapshots before cleanup", async () => {
    for (const kind of ["recover", "login"]) {
      for (const [column, value] of [
        ["security_stamp", "changed-stamp"], ["master_password_hash", "changed-password-hash"],
        ["password_salt", "changed-password-salt"], ["password_iterations", 1200000],
        ["two_factor_recovery_code", "new-recovery-code"], ["two_factor_recovery_code", CODE.toLowerCase()],
        ["email", "changed-owner@example.test"],
      ]) {
        const f = seed(), batch = f.db.batch.bind(f.db);
        let changed = false, expected;
        f.db.batch = async statements => {
          if (!changed && isRecovery(statements)) {
            changed = true;
            sql.exec(`UPDATE users SET ${column}=? WHERE id=?`, value, f.owner);
            expected = state();
          }
          return batch(statements);
        };
        await status(await call(kind, f), 409);
        equal(changed, true, `${kind} did not reach the actual recovery batch`);
        equal(state(), expected, `${kind} cleaned state after ${column} changed`);
      }
    }
  });

  await check("simultaneous verified recovery attempts commit one winner through either entry point", async () => {
    for (const kind of ["recover", "login"]) {
      const f = seed(), other = otherState(), batch = f.db.batch.bind(f.db);
      let pending = 0, release;
      const ready = new Promise(resolve => { release = resolve; });
      f.db.batch = async statements => {
        if (isRecovery(statements)) {
          if (++pending === 2) release();
          await ready;
        }
        return batch(statements);
      };
      const responses = await Promise.all([call(kind, f), call(kind, f)]);
      equal(pending, 2, "both requests must reach the verified snapshot write");
      equal(responses.map(response => response.status).sort().join(","), "200,409");
      for (const response of responses) await response.text();
      assertCleared(f, other);
    }
  });

  await check("a late database failure rolls back recovery code consumption and every cleanup", async () => {
    for (const kind of ["recover", "login"]) {
      const f = seed();
      sql.exec("CREATE TRIGGER recovery_runtime_failure BEFORE DELETE ON two_factors BEGIN SELECT RAISE(ABORT, 'injected recovery cleanup failure'); END;");
      const before = state();
      await status(await call(kind, f), 500);
      equal(state(), before, `${kind} partially committed recovery cleanup`);
    }
  });

  await check("recovery login keeps factors and the prior session on signing or session-write failure", async () => {
    for (const failure of ["signing", "device upsert"]) {
      const f = seed();
      let username = EMAIL;
      if (failure === "signing") {
        username = `${"a".repeat(9000)}@example.test`;
        sql.exec("UPDATE users SET email=? WHERE id=?", username, f.owner);
      } else {
        sql.exec("CREATE TRIGGER reject_recovery_session BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'fixture session rejected'); END;");
      }
      const before = state();
      await status(await login(f, { username, device: "device" }), 500);
      equal(state(), before, `${failure} changed recovery or session state`);
      if (failure === "signing") {
        sql.exec("UPDATE users SET email=? WHERE id=?", EMAIL, f.owner);
      } else {
        sql.exec("DROP TRIGGER reject_recovery_session");
      }
      const other = otherState();
      const tokens = await (await status(await login(f, { device: "device" }), 200)).json();
      assertCleared(f, other);
      await status(await f.fetch("/api/accounts/profile", { headers: { Authorization: `Bearer ${tokens.access_token}` } }), 200);
    }
  });

  await check("public recovery enforces real IP and normalized-email rate limits including unknown accounts", async () => {
    class Ratelimit {
      calls = []; counts = new Map();
      constructor(prefix) { this.prefix = prefix; }
      async limit({ key }) {
        this.calls.push(key);
        const count = (this.counts.get(key) ?? 0) + 1; this.counts.set(key, count);
        return { success: !key.startsWith(this.prefix) || count === 1 };
      }
    }
    {
      const f = fixture(), limiter = new Ratelimit("twofactor-recover:");
      f.env.LOGIN_RATE_LIMITER = limiter;
      await status(await recover(f, { email: " Missing@Example.TEST " }, { "cf-connecting-ip": "198.51.100.1" }), 401);
      await status(await recover(f, { email: "missing@example.test" }, { "cf-connecting-ip": "198.51.100.2" }), 429);
      equal(limiter.calls.join("|"), "twofactor-recover-ip:198.51.100.1|twofactor-recover:missing@example.test|twofactor-recover-ip:198.51.100.2|twofactor-recover:missing@example.test");
    }
    {
      const f = fixture(), limiter = new Ratelimit("twofactor-recover-ip:");
      f.env.LOGIN_RATE_LIMITER = limiter;
      await status(await recover(f, { email: "missing-one@example.test" }, { "cf-connecting-ip": "198.51.100.3" }), 401);
      await status(await recover(f, { email: "missing-two@example.test" }, { "cf-connecting-ip": "198.51.100.3" }), 429);
      equal(limiter.calls.length, 3, "denied IP must stop before the email bucket and password lookup");
    }
  });

  await check("password login recovery consumes second factors without issuing a new Remember token", async () => {
    const f = seed(), other = otherState();
    const response = await status(await login(f), 200);
    const token = await response.json();
    if (typeof token.access_token !== "string") throw new Error("recovery login did not issue the normal access token");
    equal(Object.hasOwn(token, "TwoFactorToken"), false, "recovery login recreated remembered 2FA");
    assertCleared(f, other);
  });

  await check("recovery login rejects empty and whitespace-only stored codes without changing authentication state", async () => {
    for (const [stored, submitted] of [["", ""], [" ", " "], ["\t", "\t"], [CODE, ""], [CODE, " "], [CODE, "\t"]]) {
      const f = seed();
      sql.exec("UPDATE users SET two_factor_recovery_code=? WHERE id=?", stored, f.owner);
      const before = state();
      await status(await login(f, { code: submitted }), 401);
      equal(state(), before, "invalid recovery code changed authentication state");
    }
  });

  await check("recovery login checks client compatibility before consuming a verified recovery code", async () => {
    for (const version of [null, "invalid-version", "2026.9.0"]) {
      const f = seed();
      sql.exec("UPDATE users SET security_version=2,private_key='7.private' WHERE id=?", f.owner);
      const before = state();
      await status(await login(f, { version }), 400);
      equal(state(), before, "an incompatible client consumed or upgraded authentication state");
    }
  });
}
