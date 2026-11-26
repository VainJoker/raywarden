//! Web Vault presentation preferences. These never authorize an API operation.
use worker::Env;

use crate::infra::config::{env_bool, env_text};

pub(crate) fn suppress_onboarding(env: &Env) -> bool {
    env_bool(env, "CLIENT_SUPPRESS_ONBOARDING", false)
}

pub(crate) fn stylesheet(env: &Env, registration_disabled: bool) -> String {
    let signup_disabled = env_bool(env, "VW_CSS_SIGNUP_DISABLED", registration_disabled);
    let sends_allowed = env_bool(env, "VW_CSS_SENDS_ALLOWED", true);
    let hints_allowed = env_bool(env, "VW_CSS_PASSWORD_HINTS_ALLOWED", true);
    let passkey_2fa = env_bool(env, "VW_CSS_PASSKEY_2FA_SUPPORTED", true);
    let passkey_login = env_bool(env, "VW_CSS_PASSKEY_LOGIN_ENABLED", true);
    let remember_disabled = env_bool(env, "VW_CSS_REMEMBER_2FA_DISABLED", false);
    let mail_enabled = env_bool(
        env,
        "VW_CSS_MAIL_ENABLED",
        env_text(env, "MAIL_WEBHOOK_URL").is_some(),
    );
    let mail_2fa = env_bool(env, "VW_CSS_MAIL_2FA_ENABLED", true);
    let user_css = if env_bool(env, "VW_CSS_LOAD_USER_CSS", true) {
        env_text(env, "VW_CSS_USER")
    } else {
        None
    };

    let rules = [
        (suppress_onboarding(env), "app-vault-onboarding"),
        (
            signup_disabled,
            "a[routerlink=\"/signup\"], a[href*=\"/signup\"]",
        ),
        (!sends_allowed, "bit-nav-item[route=\"sends\"]"),
        (!hints_allowed, "a[routerlink=\"/hint\"], .vw-password-hint"),
        (!passkey_2fa, ".providers-2fa-7"),
        (
            !passkey_login,
            ".vw-passkey-login, app-login-via-webauthn, \
             app-webauthn-login-settings",
        ),
        (
            remember_disabled,
            "app-two-factor-auth > form > bit-form-control",
        ),
        (!mail_enabled || !mail_2fa, ".providers-2fa-1"),
    ];
    let mut css = include_str!("../../static/overrides/vaultwarden.css").to_string();
    for (hide, selectors) in rules {
        if hide {
            css.push('\n');
            css.push_str(selectors);
            css.push_str(" { display:none !important; }\n");
        }
    }
    if let Some(custom) = user_css {
        css.push('\n');
        css.push_str(&custom);
    }
    css
}
