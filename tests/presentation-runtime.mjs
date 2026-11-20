/** Presentation preferences through the compiled Rust config/CSS handlers. */
export async function runPresentationCompatibility({ fixture, check }) {
  const equal = (actual, expected, label = "value") => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, received ${actual}`);
  };
  const ok = (value, label) => { if (!value) throw new Error(label); };
  const css = async (f, init) => {
    const response = await f.fetch("/css/vaultwarden.css", init);
    equal(response.status, 200, await response.clone().text());
    return { response, text: await response.text() };
  };
  const config = async (f, headers) => {
    const response = await f.fetch("/api/config", { headers });
    equal(response.status, 200);
    equal(response.headers.get("cache-control"), "no-store");
    return response.json();
  };
  const hidden = (text, selector, expected) => equal(text.includes(selector), expected, selector);
  const names = [
    "SIGNUP_DISABLED", "SENDS_ALLOWED", "PASSWORD_HINTS_ALLOWED", "SSO_ENABLED", "SSO_ONLY",
    "PASSKEY_2FA_SUPPORTED", "PASSKEY_LOGIN_ENABLED", "REMEMBER_2FA_DISABLED",
    "MAIL_2FA_ENABLED", "MAIL_ENABLED", "YUBICO_ENABLED", "DUO_ENABLED",
    "EMERGENCY_ACCESS_ALLOWED", "LOAD_USER_CSS",
  ];
  const custom = ".presentation-runtime-custom { color: rgb(1, 2, 3); }";

  await check("all CSS preferences accept the four boolean spellings and remove fixed feature hiding", async () => {
    const f = fixture();
    f.env.VW_CSS_USER = custom;
    for (const [yes, no] of [["true", "false"], ["1", "0"], [" YES ", " NO "], ["On", "Off"]]) {
      for (const [value, enabled] of [[yes, true], [no, false]]) {
        for (const name of names) f.env[`VW_CSS_${name}`] = value;
        const { text } = await css(f);
        hidden(text, 'a[routerlink="/signup"]', enabled);
        hidden(text, 'bit-nav-item[route="sends"]', !enabled);
        hidden(text, ".vw-password-hint", !enabled);
        hidden(text, ".vw-sso-login", !enabled);
        hidden(text, ".vw-email-continue", enabled);
        hidden(text, ".providers-2fa-7", !enabled);
        hidden(text, ".vw-passkey-login", !enabled);
        hidden(text, "app-two-factor-auth > form > bit-form-control", enabled);
        hidden(text, ".providers-2fa-1", !enabled);
        hidden(text, ".providers-2fa-3", !enabled);
        hidden(text, ".providers-2fa-2", !enabled);
        hidden(text, "settings/emergency-access", !enabled);
        hidden(text, custom, enabled);
      }
    }
    // SSO-only and the two mail preferences also work independently.
    f.env.VW_CSS_SSO_ENABLED = "true";
    f.env.VW_CSS_SSO_ONLY = "false";
    f.env.VW_CSS_MAIL_ENABLED = "true";
    f.env.VW_CSS_MAIL_2FA_ENABLED = "false";
    let result = await css(f);
    hidden(result.text, ".vw-other-login", false);
    hidden(result.text, ".providers-2fa-1", true);
    f.env.VW_CSS_SSO_ONLY = "true";
    f.env.VW_CSS_MAIL_ENABLED = "false";
    f.env.VW_CSS_MAIL_2FA_ENABLED = "true";
    result = await css(f);
    hidden(result.text, ".vw-other-login", true);
    hidden(result.text, ".providers-2fa-1", true);
  });

  await check("CSS defaults and the legacy Passkey alias preserve current presentation", async () => {
    const f = fixture();
    let result = await css(f);
    for (const selector of [".vw-sso-login", ".providers-2fa-1", ".providers-2fa-2", ".providers-2fa-3", "settings/emergency-access", 'a[routerlink="/signup"]']) {
      hidden(result.text, selector, true);
    }
    hidden(result.text, ".providers-2fa-7", false);
    hidden(result.text, ".vw-passkey-login", false);
    f.env.PASSKEY_LOGIN_ENABLED = "false";
    result = await css(f);
    hidden(result.text, ".vw-passkey-login", true);
    f.env.VW_CSS_PASSKEY_LOGIN_ENABLED = "true";
    f.env.VW_CSS_SIGNUP_DISABLED = "false";
    result = await css(f);
    hidden(result.text, ".vw-passkey-login", false);
    hidden(result.text, 'a[routerlink="/signup"]', false);
    equal((await config(f)).settings.disableUserRegistration, true, "CSS does not change the client registration setting");
    delete f.env.VW_CSS_PASSKEY_LOGIN_ENABLED;
    f.env.PASSKEY_LOGIN_ENABLED = "invalid";
    f.env.VW_CSS_DUO_ENABLED = "invalid";
    result = await css(f);
    hidden(result.text, ".vw-passkey-login", false);
    hidden(result.text, ".providers-2fa-2", true);
    f.env.MAIL_WEBHOOK_URL = "https://mail.example.test/fixture-only";
    hidden((await css(f)).text, ".providers-2fa-1", false);
  });

  await check("CSS validators change with effective settings and HEAD keeps GET validators", async () => {
    const f = fixture();
    const first = await css(f);
    const etag = first.response.headers.get("etag");
    ok(/^"[a-f0-9]{64}"$/.test(etag), "CSS has no strong content ETag");
    equal(first.response.headers.get("cache-control"), "public, no-cache");
    let response = await f.fetch("/css/vaultwarden.css", { headers: { "If-None-Match": `"another", W/${etag}` } });
    equal(response.status, 304); equal(await response.text(), ""); equal(response.headers.get("etag"), etag);
    response = await f.fetch("/css/vaultwarden.css", { method: "HEAD" });
    equal(response.status, 200); equal(await response.text(), ""); equal(response.headers.get("etag"), etag);
    f.env.VW_CSS_USER = custom;
    const changed = await css(f, { headers: { "If-None-Match": etag } });
    ok(changed.text.endsWith(custom), "custom CSS was not appended last");
    ok(changed.response.headers.get("etag") !== etag, "CSS change retained the old validator");
    f.env.VW_CSS_LOAD_USER_CSS = "false";
    const disabled = await css(f);
    hidden(disabled.text, custom, false);
    equal(disabled.response.headers.get("etag"), etag, "disabled custom CSS did not restore the baseline");
    response = await f.fetch("/css/vaultwarden.css", { method: "HEAD", headers: { "If-None-Match": etag } });
    equal(response.status, 304); equal(await response.text(), "");
  });

  await check("onboarding suppression is a real client setting independent of registration visibility", async () => {
    const f = fixture({ empty: true });
    f.env.ALLOWED_EMAILS = "owner@example.test";
    f.env.OWNER_SETUP_TOKEN = "presentation-runtime-private-owner-authorization";
    f.env.DISABLE_USER_REGISTRATION = "false";
    let settings = (await config(f)).settings;
    equal(settings.disableUserRegistration, true, "a presentation variable cannot open public registration");
    equal(settings.suppressOnboardingInterstitials, false);
    const baseline = await css(f);
    const baselineEtag = baseline.response.headers.get("etag");
    hidden(baseline.text, "app-vault-onboarding", false);
    const authorization = await f.fetch("/api/accounts/setup", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: f.env.OWNER_SETUP_TOKEN }),
    });
    equal(authorization.status, 200);
    const headers = { Cookie: authorization.headers.get("set-cookie").split(";")[0] };
    for (const [yes, no] of [["true", "false"], ["1", "0"], [" YES ", " NO "], ["On", "Off"]]) {
      f.env.CLIENT_SUPPRESS_ONBOARDING = yes;
      settings = (await config(f, headers)).settings;
      equal(settings.suppressOnboardingInterstitials, true);
      equal(settings.disableUserRegistration, false);
      equal((await config(f)).settings.disableUserRegistration, true);
      const suppressed = await css(f, { headers: { "If-None-Match": baselineEtag } });
      hidden(suppressed.text, "app-vault-onboarding { display:none !important; }", true);
      const suppressedEtag = suppressed.response.headers.get("etag");
      ok(suppressedEtag !== baselineEtag, "onboarding suppression retained the visible checklist validator");
      f.env.CLIENT_SUPPRESS_ONBOARDING = no;
      equal((await config(f, headers)).settings.suppressOnboardingInterstitials, false);
      const restored = await css(f, { headers: { "If-None-Match": suppressedEtag } });
      hidden(restored.text, "app-vault-onboarding", false);
      equal(restored.response.headers.get("etag"), baselineEtag, "showing onboarding did not restore the baseline validator");
    }
    f.env.DISABLE_USER_REGISTRATION = "true";
    settings = (await config(f)).settings;
    equal(settings.disableUserRegistration, true);
    equal(settings.suppressOnboardingInterstitials, false);
    equal((await config(f, headers)).settings.disableUserRegistration, false);
  });
}
