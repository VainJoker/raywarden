//! Optional administrative events; recipient mail and verification codes never
//! enter this channel. Only stable event names and account IDs are rendered.
use serde_json::json;
use worker::Env;

use super::post_json;
use crate::{errors::AppResult, infra::config::env_text};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Level {
    Info,
    Warning,
    Error,
}

impl Level {
    fn parse(value: Option<&str>) -> Self {
        match value
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "warning" | "warn" => Self::Warning,
            "error" => Self::Error,
            _ => Self::Info,
        }
    }

    const fn key(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EventFamily {
    Vault,
    AccountSecurity,
}

struct EventMeta {
    key: &'static str,
    aliases: &'static [&'static str],
    level: Level,
    family: Option<EventFamily>,
}

macro_rules! events {
    ($($event:ident => ($key:literal, $aliases:expr, $level:ident, $family:expr)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum Event {
            $($event),+
        }

        impl Event {
            const fn meta(self) -> EventMeta {
                match self {
                    $(Self::$event => EventMeta {
                        key: $key,
                        aliases: $aliases,
                        level: Level::$level,
                        family: $family,
                    }),+
                }
            }
        }
    };
}

events! {
    Login => ("login", &[], Info, None),
    LoginFailed => ("login_failed", &["login_fail", "loginfailed"], Warning, None),
    PasswordHint => ("password_hint", &["password-hint"], Warning, None),
    PasswordChange => ("password", &["password_change", "passwordchange"], Warning, Some(EventFamily::AccountSecurity)),
    EmailChange => ("email", &["email_change", "emailchange", "account.email-changed"], Warning, Some(EventFamily::AccountSecurity)),
    KdfChange => ("kdf", &["kdf_change", "kdfchange"], Warning, Some(EventFamily::AccountSecurity)),
    CipherCreate => ("cipher_create", &["cipher.add", "cipher_add", "create_cipher"], Info, Some(EventFamily::Vault)),
    CipherUpdate => ("cipher_update", &["cipher.update", "cipher_edit", "update_cipher"], Info, Some(EventFamily::Vault)),
    CipherDelete => ("cipher_delete", &["cipher.del", "delete_cipher"], Warning, Some(EventFamily::Vault)),
    Import => ("import", &[], Info, Some(EventFamily::Vault)),
    SendCreate => ("send_create", &["send.create", "send_add"], Info, Some(EventFamily::Vault)),
    SendDelete => ("send_delete", &["send.del", "send_remove"], Warning, Some(EventFamily::Vault)),
    TwoFactorEnable => ("2fa_enable", &["two_factor_enable", "twofactor_enable", "two-factor.enabled"], Info, None),
    TwoFactorDisable => ("2fa_disable", &["two_factor_disable", "twofactor_disable", "two-factor.disabled"], Warning, None),
    TwoFactorRecoveryCodeView => ("2fa_recovery_code_view", &["two_factor_recovery_code_view"], Warning, None),
    TwoFactorRecover => ("2fa_recover", &["two_factor_recover", "twofactor_recover"], Error, None),
    TokenRefresh => ("token_refresh", &["unlock"], Info, None),
    Sync => ("sync", &[], Info, None),
    AuthRequest => ("auth_request", &["authrequest"], Info, None),
    AuthResponse => ("auth_response", &["authresponse"], Info, None),
    WebauthnCredentialCreate => ("webauthn_credential_create", &["webauthn_create", "passkey_create"], Info, None),
    WebauthnCredentialDelete => ("webauthn_credential_delete", &["webauthn_delete", "passkey_delete"], Warning, None),
    WebauthnCredentialUpdate => ("webauthn_credential_update", &["webauthn_update", "passkey_update"], Info, None),
    WebauthnLogin => ("webauthn_login", &["passkey_login"], Info, None),
    VaultChanged => ("vault-changed", &[], Info, Some(EventFamily::Vault)),
    AccountSecurityChanged => ("account-security-changed", &[], Warning, Some(EventFamily::AccountSecurity)),
    AccountSettingsChanged => ("account-settings-changed", &[], Info, None),
    AccountDeleted => ("account.deleted", &[], Warning, None),
}

impl Event {
    pub(crate) const fn key(self) -> &'static str {
        self.meta().key
    }

    const fn level(self) -> Level {
        self.meta().level
    }

    fn selected_by(self, filter: &str) -> bool {
        let meta = self.meta();
        if filter == "*" || filter.eq_ignore_ascii_case("all") {
            true
        } else if filter.eq_ignore_ascii_case("vault-changed") {
            meta.family == Some(EventFamily::Vault)
        } else if filter.eq_ignore_ascii_case("account-security-changed") {
            meta.family == Some(EventFamily::AccountSecurity)
        } else {
            meta.key.eq_ignore_ascii_case(filter)
                || meta
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(filter))
        }
    }
}

fn enabled(event: Event, level: Option<&str>, events: Option<&str>) -> bool {
    event.level() >= Level::parse(level)
        && events.is_some_and(|events| {
            events
                .split(',')
                .any(|filter| event.selected_by(filter.trim()))
        })
}

fn message(event: Event, user_id: &str) -> String {
    format!(
        "raywarden: {}\nLevel: {}\nAccount: {user_id}",
        event.key(),
        event.level().key()
    )
}

/// Called after successful authorization/commit. Delivery failures are isolated
/// from the operation; callers never pass payloads, tokens, codes or
/// ciphertext.
pub(crate) async fn emit(env: &Env, event: Event, user_id: &str) {
    if !enabled(
        event,
        env_text(env, "NOTIFY_LEVEL").as_deref(),
        env_text(env, "NOTIFY_EVENTS").as_deref(),
    ) {
        return;
    }
    let text = message(event, user_id);
    if deliver_wework(env, &text).await.is_err() {
        log::warn!("Administrative WeWork notification failed");
    }
    if deliver_telegram(env, &text).await.is_err() {
        log::warn!("Administrative Telegram notification failed");
    }
}

async fn deliver_wework(env: &Env, text: &str) -> AppResult<()> {
    let Some(url) = env_text(env, "WEWORK_WEBHOOK_URL") else {
        return Ok(());
    };
    post_json(
        &url,
        json!({"msgtype":"text","text":{"content":text}}),
        None,
    )
    .await
}

async fn deliver_telegram(env: &Env, text: &str) -> AppResult<()> {
    let (Some(token), Some(chat)) = (
        env_text(env, "TELEGRAM_BOT_TOKEN"),
        env_text(env, "TELEGRAM_CHAT_ID"),
    ) else {
        return Ok(());
    };
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
    {
        return Ok(());
    }
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    post_json(&url, json!({"chat_id":chat,"text":text}), None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const STANDARD: [Event; 24] = [
        Event::Login,
        Event::LoginFailed,
        Event::PasswordHint,
        Event::PasswordChange,
        Event::EmailChange,
        Event::KdfChange,
        Event::CipherCreate,
        Event::CipherUpdate,
        Event::CipherDelete,
        Event::Import,
        Event::SendCreate,
        Event::SendDelete,
        Event::TwoFactorEnable,
        Event::TwoFactorDisable,
        Event::TwoFactorRecoveryCodeView,
        Event::TwoFactorRecover,
        Event::TokenRefresh,
        Event::Sync,
        Event::AuthRequest,
        Event::AuthResponse,
        Event::WebauthnCredentialCreate,
        Event::WebauthnCredentialDelete,
        Event::WebauthnCredentialUpdate,
        Event::WebauthnLogin,
    ];

    #[test]
    fn standard_event_names_select_events_and_disabled_filters_stay_disabled() {
        for event in STANDARD {
            assert!(enabled(event, None, Some(event.key())));
            for filter in [
                None,
                Some(""),
                Some("none"),
                Some("OFF"),
                Some("0"),
                Some("false"),
                Some("unknown"),
            ] {
                assert!(!enabled(event, None, filter));
            }
            assert!(enabled(event, None, Some(" ALL ")));
            assert!(enabled(event, Some("invalid"), Some("*")));
        }
    }

    #[test]
    fn levels_apply_to_selected_events_and_warn_is_an_alias() {
        for event in STANDARD {
            for filter in ["warning", "WARN"] {
                assert_eq!(
                    enabled(event, Some(filter), Some("all")),
                    event.level() >= Level::Warning
                );
            }
            assert_eq!(
                enabled(event, Some("error"), Some("*")),
                event == Event::TwoFactorRecover
            );
        }
        assert_eq!(Event::LoginFailed.level(), Level::Warning);
        assert!(!enabled(Event::Login, Some("error"), Some("login")));
    }

    #[test]
    fn seven_ray_filters_keep_their_event_families_without_duplicate_events() {
        for (filter, events) in [
            ("vault-changed", vec![
                Event::CipherCreate,
                Event::CipherUpdate,
                Event::CipherDelete,
                Event::Import,
                Event::SendCreate,
                Event::SendDelete,
                Event::VaultChanged,
            ]),
            ("account-security-changed", vec![
                Event::PasswordChange,
                Event::EmailChange,
                Event::KdfChange,
                Event::AccountSecurityChanged,
            ]),
            ("account-settings-changed", vec![
                Event::AccountSettingsChanged,
            ]),
            ("account.deleted", vec![Event::AccountDeleted]),
            ("account.email-changed", vec![Event::EmailChange]),
            ("two-factor.enabled", vec![Event::TwoFactorEnable]),
            ("two-factor.disabled", vec![Event::TwoFactorDisable]),
        ] {
            for event in events {
                assert!(
                    enabled(event, None, Some(filter)),
                    "{filter} selects {event:?}"
                );
            }
        }
        assert!(!enabled(Event::Login, None, Some("vault-changed")));
        assert_eq!(
            message(Event::LoginFailed, "unidentified"),
            "raywarden: login_failed\nLevel: warning\nAccount: unidentified"
        );
    }
}
