//! Optional administrative events; recipient mail and verification codes never
//! enter this channel. Only stable event names and account IDs are rendered.
use serde_json::json;
use worker::Env;

use super::{
    config::env_text,
    delivery::post_json,
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    Login,
    LoginFailed,
    PasswordHint,
    PasswordChange,
    EmailChange,
    KdfChange,
    CipherCreate,
    CipherUpdate,
    CipherDelete,
    Import,
    SendCreate,
    SendDelete,
    TwoFactorEnable,
    TwoFactorDisable,
    TwoFactorRecoveryCodeView,
    TwoFactorRecover,
    TokenRefresh,
    Sync,
    AuthRequest,
    AuthResponse,
    WebAuthnCredentialCreate,
    WebAuthnCredentialDelete,
    WebAuthnCredentialUpdate,
    WebAuthnLogin,
    // Existing Ray events without an equivalent among the standard 24.
    VaultChanged,
    AccountSecurityChanged,
    AccountSettingsChanged,
    AccountDeleted,
}

impl Event {
    pub(crate) const fn key(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::LoginFailed => "login_failed",
            Self::PasswordHint => "password_hint",
            Self::PasswordChange => "password",
            Self::EmailChange => "email",
            Self::KdfChange => "kdf",
            Self::CipherCreate => "cipher_create",
            Self::CipherUpdate => "cipher_update",
            Self::CipherDelete => "cipher_delete",
            Self::Import => "import",
            Self::SendCreate => "send_create",
            Self::SendDelete => "send_delete",
            Self::TwoFactorEnable => "2fa_enable",
            Self::TwoFactorDisable => "2fa_disable",
            Self::TwoFactorRecoveryCodeView => "2fa_recovery_code_view",
            Self::TwoFactorRecover => "2fa_recover",
            Self::TokenRefresh => "token_refresh",
            Self::Sync => "sync",
            Self::AuthRequest => "auth_request",
            Self::AuthResponse => "auth_response",
            Self::WebAuthnCredentialCreate => "webauthn_credential_create",
            Self::WebAuthnCredentialDelete => "webauthn_credential_delete",
            Self::WebAuthnCredentialUpdate => "webauthn_credential_update",
            Self::WebAuthnLogin => "webauthn_login",
            Self::VaultChanged => "vault-changed",
            Self::AccountSecurityChanged => "account-security-changed",
            Self::AccountSettingsChanged => "account-settings-changed",
            Self::AccountDeleted => "account.deleted",
        }
    }

    const fn level(self) -> Level {
        match self {
            Self::TwoFactorRecover => Level::Error,
            Self::LoginFailed |
            Self::PasswordHint |
            Self::PasswordChange |
            Self::EmailChange |
            Self::KdfChange |
            Self::CipherDelete |
            Self::SendDelete |
            Self::TwoFactorDisable |
            Self::TwoFactorRecoveryCodeView |
            Self::WebAuthnCredentialDelete |
            Self::AccountSecurityChanged |
            Self::AccountDeleted => Level::Warning,
            _ => Level::Info,
        }
    }

    fn from_key(value: &str) -> Option<Self> {
        Some(match value {
            "login" => Self::Login,
            "login_failed" | "login_fail" | "loginfailed" => Self::LoginFailed,
            "password_hint" | "password-hint" => Self::PasswordHint,
            "password" | "password_change" | "passwordchange" => {
                Self::PasswordChange
            }
            "email" |
            "email_change" |
            "emailchange" |
            "account.email-changed" => Self::EmailChange,
            "kdf" | "kdf_change" | "kdfchange" => Self::KdfChange,
            "cipher_create" | "cipher.add" | "cipher_add" | "create_cipher" => {
                Self::CipherCreate
            }
            "cipher_update" | "cipher.update" | "cipher_edit" |
            "update_cipher" => Self::CipherUpdate,
            "cipher_delete" | "cipher.del" | "delete_cipher" => {
                Self::CipherDelete
            }
            "import" => Self::Import,
            "send_create" | "send.create" | "send_add" => Self::SendCreate,
            "send_delete" | "send.del" | "send_remove" => Self::SendDelete,
            "2fa_enable" | "two_factor_enable" | "twofactor_enable" |
            "two-factor.enabled" => Self::TwoFactorEnable,
            "2fa_disable" |
            "two_factor_disable" |
            "twofactor_disable" |
            "two-factor.disabled" => Self::TwoFactorDisable,
            "2fa_recovery_code_view" | "two_factor_recovery_code_view" => {
                Self::TwoFactorRecoveryCodeView
            }
            "2fa_recover" | "two_factor_recover" | "twofactor_recover" => {
                Self::TwoFactorRecover
            }
            "token_refresh" | "unlock" => Self::TokenRefresh,
            "sync" => Self::Sync,
            "auth_request" | "authrequest" => Self::AuthRequest,
            "auth_response" | "authresponse" => Self::AuthResponse,
            "webauthn_credential_create" |
            "webauthn_create" |
            "passkey_create" => Self::WebAuthnCredentialCreate,
            "webauthn_credential_delete" |
            "webauthn_delete" |
            "passkey_delete" => Self::WebAuthnCredentialDelete,
            "webauthn_credential_update" |
            "webauthn_update" |
            "passkey_update" => Self::WebAuthnCredentialUpdate,
            "webauthn_login" | "passkey_login" => Self::WebAuthnLogin,
            "vault-changed" => Self::VaultChanged,
            "account-security-changed" => Self::AccountSecurityChanged,
            "account-settings-changed" => Self::AccountSettingsChanged,
            "account.deleted" => Self::AccountDeleted,
            _ => return None,
        })
    }

    fn selected_by(self, filter: &str) -> bool {
        match filter {
            "*" | "all" => true,
            "vault-changed" => matches!(
                self,
                Self::CipherCreate |
                    Self::CipherUpdate |
                    Self::CipherDelete |
                    Self::Import |
                    Self::SendCreate |
                    Self::SendDelete |
                    Self::VaultChanged
            ),
            "account-security-changed" => matches!(
                self,
                Self::PasswordChange |
                    Self::EmailChange |
                    Self::KdfChange |
                    Self::AccountSecurityChanged
            ),
            _ => Self::from_key(filter) == Some(self),
        }
    }
}

fn enabled(event: Event, level: Option<&str>, events: Option<&str>) -> bool {
    event.level() >= Level::parse(level) &&
        events.is_some_and(|events| {
            events.split(',').any(|filter| {
                event.selected_by(&filter.trim().to_ascii_lowercase())
            })
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
    if let Some(url) = env_text(env, "WEWORK_WEBHOOK_URL") &&
        post_json(
            &url,
            json!({"msgtype":"text","text":{"content":text}}),
            None,
        )
        .await
        .is_err()
    {
        log::warn!("Administrative WeWork notification failed");
    }
    if let (Some(token), Some(chat)) = (
        env_text(env, "TELEGRAM_BOT_TOKEN"),
        env_text(env, "TELEGRAM_CHAT_ID"),
    ) {
        if !token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-')
        }) {
            return;
        }
        let url = format!("https://api.telegram.org/bot{token}/sendMessage");
        if post_json(&url, json!({"chat_id":chat,"text":text}), None)
            .await
            .is_err()
        {
            log::warn!("Administrative Telegram notification failed");
        }
    }
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
        Event::WebAuthnCredentialCreate,
        Event::WebAuthnCredentialDelete,
        Event::WebAuthnCredentialUpdate,
        Event::WebAuthnLogin,
    ];

    #[test]
    fn all_standard_events_round_trip_and_disabled_filters_stay_disabled() {
        for event in STANDARD {
            assert_eq!(Event::from_key(event.key()), Some(event));
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
