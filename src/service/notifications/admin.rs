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
        let trimmed = value.unwrap_or_default().trim();
        if trimmed.eq_ignore_ascii_case("warning") || trimmed.eq_ignore_ascii_case("warn") {
            Self::Warning
        } else if trimmed.eq_ignore_ascii_case("error") {
            Self::Error
        } else {
            Self::Info
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

macro_rules! events {
    ($($event:ident => ($key:literal, $level:ident)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum Event {
            $($event),+
        }

        impl Event {
            pub(crate) const fn key(self) -> &'static str {
                match self {
                    $(Self::$event => $key),+
                }
            }

            const fn level(self) -> Level {
                match self {
                    $(Self::$event => Level::$level),+
                }
            }
        }
    };
}

events! {
    Login => ("login", Info),
    LoginFailed => ("login_failed", Warning),
    PasswordHint => ("password_hint", Warning),
    PasswordChange => ("password", Warning),
    EmailChange => ("email", Warning),
    KdfChange => ("kdf", Warning),
    CipherCreate => ("cipher_create", Info),
    CipherUpdate => ("cipher_update", Info),
    CipherDelete => ("cipher_delete", Warning),
    Import => ("import", Info),
    SendCreate => ("send_create", Info),
    SendDelete => ("send_delete", Warning),
    TwoFactorEnable => ("2fa_enable", Info),
    TwoFactorDisable => ("2fa_disable", Warning),
    TwoFactorRecoveryCodeView => ("2fa_recovery_code_view", Warning),
    TwoFactorRecover => ("2fa_recover", Error),
    TokenRefresh => ("token_refresh", Info),
    Sync => ("sync", Info),
    AuthRequest => ("auth_request", Info),
    AuthResponse => ("auth_response", Info),
    WebauthnCredentialCreate => ("webauthn_credential_create", Info),
    WebauthnCredentialDelete => ("webauthn_credential_delete", Warning),
    WebauthnCredentialUpdate => ("webauthn_credential_update", Info),
    WebauthnLogin => ("webauthn_login", Info),
    VaultChanged => ("vault-changed", Info),
    AccountSecurityChanged => ("account-security-changed", Warning),
    AccountSettingsChanged => ("account-settings-changed", Info),
    AccountDeleted => ("account.deleted", Warning),
}

impl Event {
    fn selected_by(self, filter: &str) -> bool {
        filter == "*"
            || filter.eq_ignore_ascii_case("all")
            || self.key().eq_ignore_ascii_case(filter)
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

    #[test]
    fn event_filters_and_levels_gate_delivery() {
        assert!(enabled(Event::Login, None, Some("login")));
        assert!(enabled(Event::Login, None, Some(" ALL ")));
        assert!(enabled(Event::Login, Some("invalid"), Some("*")));
        for filter in [None, Some(""), Some("none"), Some("OFF"), Some("unknown")] {
            assert!(!enabled(Event::Login, None, filter));
        }
        assert!(enabled(Event::LoginFailed, Some("WARN"), Some("all")));
        assert!(!enabled(Event::Login, Some("warning"), Some("all")));
        assert!(enabled(Event::TwoFactorRecover, Some("error"), Some("*")));
        assert!(!enabled(Event::LoginFailed, Some("error"), Some("*")));
        assert_eq!(
            message(Event::LoginFailed, "unidentified"),
            "raywarden: login_failed\nLevel: warning\nAccount: unidentified"
        );
    }
}
