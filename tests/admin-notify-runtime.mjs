// Administrative events from the compiled Rust handlers. Only the synthetic
// HTTPS sink is intercepted; no actual webhook or external network is used.
function equal(actual, expected, label = "value") {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
}
function ok(value, label) { if (!value) throw new Error(label); }

export async function runAdminNotificationCompatibility({ fixture, check, accessToken, USER, sql }) {
  async function status(response, expected) {
    equal(response.status, expected, await response.clone().text());
    return response;
  }
  const owner = async () => ({ Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json" });
  const login = (f, password = "hash") => f.fetch("/identity/connect/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Bitwarden-Client-Version": "2026.10.2" },
    body: new URLSearchParams({ grant_type: "password", username: "owner@example.test", password,
      deviceIdentifier: "admin-runtime-login", deviceName: "Runtime Browser", deviceType: "14" }),
  });
  const createSend = async f => f.fetch("/api/sends", { method: "POST", headers: await owner(), body: JSON.stringify({
    type: 0, name: "private-encrypted-name", key: "private-wrapped-key", text: { text: "private-ciphertext" },
    deletionDate: new Date(Date.now() + 86400000).toISOString(),
  }) });
  async function sink(run, deliveryStatus = 200) {
    const captured = [];
    const previous = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (new URL(request.url).origin !== "https://notify.runtime.test") throw new Error("Unexpected outbound URL in administrative-event test");
      equal(request.method, "POST", "webhook method");
      const body = await request.json();
      equal(body.msgtype, "text", "WeWork payload");
      const text = body.text.content;
      ok(text.startsWith("raywarden: "), "event name in notification");
      for (const secret of ["owner@example.test", "private-ciphertext", "private-wrapped-key", "private-encrypted-name", "wrong-password-secret", "private-admin-recovery-code"]) {
        ok(!text.includes(secret), `notification excludes ${secret}`);
      }
      captured.push(text);
      return new Response("{}", { status: deliveryStatus, headers: { "Content-Type": "application/json" } });
    };
    try { await run(captured); } finally { globalThis.fetch = previous; }
  }
  const configure = (f, events = "all", level = "info") => {
    f.env.WEWORK_WEBHOOK_URL = "https://notify.runtime.test/events";
    f.env.NOTIFY_EVENTS = events;
    f.env.NOTIFY_LEVEL = level;
  };
  const event = text => text.split("\n")[0].slice("raywarden: ".length);

  await check("administrative Send events follow successful commits and legacy filters do not double-send", async () => {
    const f = fixture(); configure(f, "vault-changed,send_create,send_delete");
    await sink(async captured => {
      f.db.failBatch = true;
      const failed = await createSend(f);
      ok(failed.status >= 400, "injected Send commit failed");
      equal(captured.length, 0, "failed transaction has no successful event");
      f.db.failBatch = false;
      const send = await (await status(await createSend(f), 200)).json();
      equal(captured.length, 1); equal(event(captured[0]), "send_create");
      await status(await f.fetch(`/api/sends/${send.id}`, { method: "DELETE", headers: await owner() }), 200);
      equal(captured.length, 2); equal(event(captured[1]), "send_delete");
    });
  });

  await check("administrative warning level reports failed login but not the normal two-factor challenge", async () => {
    const f = fixture(); configure(f, "all", "WARN");
    await sink(async captured => {
      await status(await login(f, "wrong-password-secret"), 401);
      equal(captured.length, 1); equal(event(captured[0]), "login_failed");
      ok(captured[0].includes("Level: warning"), "failure severity");
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES('admin-runtime-totp',?,0,1,'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',0)", USER);
      const challenge = await (await status(await login(f), 400)).json();
      ok(challenge.TwoFactorProviders || challenge.TwoFactorProviders2, "actual two-factor challenge response");
      equal(captured.length, 1, "challenge is not a failed login");
    });
  });

  await check("administrative login_failed excludes rate limiting and D1 failures masked as public credential errors", async () => {
    {
      const f = fixture(); configure(f, "login_failed", "warning");
      // workers-rs validates the constructor name before using a binding.
      // A plain Object would silently exercise the missing-binding fallback.
      class Ratelimit {
        calls = 0;
        async limit({ key }) {
          equal(typeof key, "string");
          this.calls++;
          return { success: false };
        }
      }
      const limiter = new Ratelimit();
      f.env.LOGIN_RATE_LIMITER = limiter;
      await sink(async captured => {
        await status(await login(f, "wrong-password-secret"), 429);
        equal(limiter.calls, 1, "actual SDK limiter binding was called");
        equal(captured.length, 0, "rate limiter does not emit login_failed");
      });
    }
    {
      const f = fixture(); configure(f, "login_failed", "warning");
      const execute = f.db.execute.bind(f.db);
      let injected = false;
      f.db.execute = (query, values) => {
        if (/FROM\s+users\s+WHERE\s+email\s*=/i.test(query)) {
          injected = true;
          throw new Error("injected account lookup failure");
        }
        return execute(query, values);
      };
      await sink(async captured => {
        // The existing public response deliberately masks the lookup failure.
        await status(await login(f), 401);
        ok(injected, "actual login account lookup failed");
        equal(captured.length, 0, "D1 failure does not emit login_failed");
      });
    }
  });

  await check("administrative login, refresh and sync events come from actual successful requests", async () => {
    const f = fixture(); configure(f, "login,token_refresh,sync");
    await sink(async captured => {
      const tokens = await (await status(await login(f), 200)).json();
      equal(event(captured[0]), "login");
      await status(await f.fetch("/identity/connect/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Bitwarden-Client-Version": "2026.10.2" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }) }), 200);
      equal(event(captured[1]), "token_refresh");
      await status(await f.fetch("/api/sync?excludeDomains=true", { headers: { Authorization: `Bearer ${await accessToken()}` } }), 200);
      equal(captured.length, 3); equal(event(captured[2]), "sync");
    });
  });

  await check("administrative recovery applies error threshold and failed delivery cannot undo recovery", async () => {
    const f = fixture(); configure(f, "all", "error");
    sql.exec("UPDATE users SET two_factor_recovery_code='private-admin-recovery-code' WHERE id=?", USER);
    await sink(async captured => {
      await status(await f.fetch("/api/two-factor/get-recover", { method: "POST", headers: await owner(), body: JSON.stringify({ masterPasswordHash: "hash" }) }), 200);
      equal(captured.length, 0, "warning recovery-code view is below threshold");
      await status(await f.fetch("/api/two-factor/recover", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "owner@example.test", masterPasswordHash: "hash", recoveryCode: "private-admin-recovery-code" }) }), 200);
      equal(captured.length, 1); equal(event(captured[0]), "2fa_recover");
      ok(captured[0].includes("Level: error"), "recovery severity");
      equal(sql.exec("SELECT two_factor_recovery_code FROM users WHERE id=?", USER).one().two_factor_recovery_code, null, "recovery remains committed");
    }, 500);
  });

  await check("administrative 2fa_disable requires an enabled provider while no-op cleanup still returns 200", async () => {
    const f = fixture(); configure(f, "2fa_disable");
    const disable = async type => f.fetch("/api/two-factor/disable", { method: "POST", headers: await owner(),
      body: JSON.stringify({ type, masterPasswordHash: "hash" }) });
    const disableEmail = async () => f.fetch("/api/two-factor/email", { method: "DELETE", headers: await owner(),
      body: JSON.stringify({ masterPasswordHash: "hash" }) });
    const seed = (type, id) => {
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,?,1,?,0)", id, USER, type,
        type === 1 ? JSON.stringify({ email: "factor@example.test" }) : "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
      sql.exec("INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) VALUES(?,?,5,1,'{}',0)", `${id}-remember`, USER);
    };
    const noRemember = () => equal(sql.exec("SELECT COUNT(*) AS n FROM two_factors WHERE user_id=? AND provider_type=5", USER).one().n, 0, "Remember cleanup remains effective");
    await sink(async captured => {
      await status(await disable(0), 200);
      await status(await disable(1), 200);
      await status(await disableEmail(), 200);
      equal(captured.length, 0, "absent providers do not report disable");
      seed(0, "admin-disable-totp");
      await status(await disable(0), 200); noRemember();
      equal(captured.length, 1); equal(event(captured[0]), "2fa_disable");
      await status(await disable(0), 200);
      equal(captured.length, 1, "repeated TOTP disable remains a no-op");
      seed(1, "admin-disable-email");
      await status(await disableEmail(), 200); noRemember();
      equal(captured.length, 2); equal(event(captured[1]), "2fa_disable");
      await status(await disableEmail(), 200);
      equal(captured.length, 2, "repeated Email disable remains a no-op");
      seed(1, "admin-disable-email-generic");
      await status(await disable(1), 200); noRemember();
      equal(captured.length, 3); equal(event(captured[2]), "2fa_disable");
    });
  });

  await check("administrative legacy security-stamp event follows successful revoke_all and excludes failed batches", async () => {
    const f = fixture(); configure(f, "account-security-changed");
    const revoke = async () => f.fetch("/api/accounts/security-stamp", { method: "POST", headers: await owner(),
      body: JSON.stringify({ masterPasswordHash: "hash" }) });
    await sink(async captured => {
      f.db.failBatch = true;
      const failed = await revoke();
      ok(failed.status >= 400, "actual revoke transaction failed");
      equal(captured.length, 0, "failed revoke does not report a successful security change");
      f.db.failBatch = false;
      await status(await revoke(), 200);
      equal(captured.length, 1); equal(event(captured[0]), "account-security-changed");
      equal(sql.exec("SELECT COUNT(*) AS n FROM devices WHERE user_id=?", USER).one().n, 0, "devices actually revoked");
    });
  });
}
