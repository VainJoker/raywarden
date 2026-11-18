use axum::http::HeaderMap;
use hmac::{
    Hmac,
    KeyInit,
    Mac,
};
use serde_json::{
    Value,
    json,
};
use sha2::Sha256;
use uuid::Uuid;
use worker::D1Database;

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            rate,
        },
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    infra::{
        admin_notify::{
            self,
            Event,
        },
        delivery,
    },
    models::{
        email::{
            EmailDB,
            VerificationCode,
        },
        twofactor::{
            TwoFactorDB,
            TwoFactorType,
        },
        user::{
            PasswordOrOtpData,
            UserDB,
        },
    },
};

pub const PROTECTED_ACTION: &str = "protected-action";
pub const EMAIL_LOGIN: &str = "email-login";
pub const EMAIL_SETUP: &str = "email-setup";
pub const VERIFY_EMAIL: &str = "verify-email";
pub const CHANGE_EMAIL: &str = "change-email";
pub const REGISTRATION: &str = "registration";
pub const DELETE_RECOVER: &str = "delete-recover";

pub fn normalize_email(email: &str) -> AppResult<String> {
    let email = email.trim().to_lowercase();
    let Some((local, domain)) = email.rsplit_once('@') else {
        return Err(AppError::bad_request("Invalid email address"));
    };
    if local.is_empty() ||
        domain.is_empty() ||
        email.len() > 320 ||
        email.chars().any(char::is_whitespace) ||
        email.chars().any(char::is_control)
    {
        return Err(AppError::bad_request("Invalid email address"));
    }
    Ok(email)
}

pub fn mask_email(email: &str) -> String {
    let Some((name, domain)) = email.rsplit_once('@') else {
        return "***".into();
    };
    format!("{}***@{domain}", name.chars().next().unwrap_or('*'))
}

pub fn code_hash(
    secret: &str,
    owner: &str,
    purpose: &str,
    recipient: &str,
    context: &str,
    code: &str,
) -> AppResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::Internal)?;
    for part in [owner, purpose, recipient, context, code] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn generate_code(short: bool) -> AppResult<String> {
    if !short {
        return Ok(format!(
            "{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        ));
    }
    loop {
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes).map_err(|_| AppError::Internal)?;
        let number = u32::from_be_bytes(bytes);
        if number < u32::MAX - (u32::MAX % 1_000_000) {
            return Ok(format!("{:06}", number % 1_000_000));
        }
    }
}

fn query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() ||
            matches!(byte, b'-' | b'_' | b'.' | b'~')
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

/// Reserve first, deliver synchronously, then enable the code. Failed delivery
/// cannot leave an active code behind or report a successful send.
#[allow(clippy::too_many_arguments)]
pub async fn issue_code(
    state: &AppState,
    user: Option<&UserDB>,
    purpose: &str,
    recipient: &str,
    context: &str,
    session: &str,
    short: bool,
    reuse: bool,
) -> AppResult<()> {
    if !delivery::mail_configured(&state.env) {
        return Err(AppError::bad_request("Email delivery is not configured"));
    }
    let recipient = normalize_email(recipient)?;
    let owner = user.map_or(recipient.as_str(), |user| user.id.as_str());
    let stamp = user.map_or("", |user| user.security_stamp.as_str());
    let id = Uuid::new_v4().to_string();
    let raw = generate_code(short)?;
    let hash = code_hash(
        &state.config.jwt_secret,
        owner,
        purpose,
        &recipient,
        context,
        &raw,
    )?;
    let code = VerificationCode {
        id: &id,
        owner,
        user_id: user.map(|user| user.id.as_str()),
        purpose,
        recipient: &recipient,
        context,
        hash: &hash,
        stamp,
        session,
    };
    let db = state.get_db();
    if !EmailDB::reserve(&db, &code, crate::infra::time::now_seconds()).await? {
        if reuse {
            return Ok(());
        }
        return Err(AppError::TooManyRequests {
            message: "Wait 60 seconds before requesting another code".into(),
        });
    }
    let link = match purpose {
        REGISTRATION => Some(format!(
            "{}/#/finish-signup?email={}&emailVerificationToken={}",
            state.get_domain(),
            query_value(&recipient),
            query_value(&raw)
        )),
        VERIFY_EMAIL => user.map(|user| {
            format!(
                "{}/#/verify-email?userId={}&token={}",
                state.get_domain(),
                query_value(&user.id),
                query_value(&raw)
            )
        }),
        DELETE_RECOVER => user.map(|user| {
            format!(
                "{}/#/delete-account?userId={}&token={}",
                state.get_domain(),
                query_value(&user.id),
                query_value(&raw)
            )
        }),
        _ => None,
    };
    let text = format!(
        "Your raywarden {purpose} verification code is:\n\n{raw}\n\nIt \
         expires in 10 minutes.\nAccount: {recipient}\nContext: {context}{}",
        link.map_or(String::new(), |url| format!("\n\nContinue: {url}"))
    );
    if delivery::deliver_mail(
        &state.env,
        &recipient,
        purpose,
        "raywarden verification",
        &text,
    )
    .await
    .is_err()
    {
        EmailDB::cancel(&db, &id).await?;
        return Err(AppError::bad_request(
            "Email delivery failed; request a new verification code",
        ));
    }
    EmailDB::mark_ready(&db, &id).await
}

#[allow(clippy::too_many_arguments)]
pub async fn verify_code(
    state: &AppState,
    user: Option<&UserDB>,
    purpose: &str,
    recipient: &str,
    context: &str,
    session: &str,
    raw: &str,
    consume: bool,
) -> AppResult<()> {
    if raw.is_empty() || raw.len() > 1024 {
        return Err(AppError::bad_request("Invalid verification code"));
    }
    let recipient = normalize_email(recipient)?;
    let owner = user.map_or(recipient.as_str(), |user| user.id.as_str());
    let hash = code_hash(
        &state.config.jwt_secret,
        owner,
        purpose,
        &recipient,
        context,
        raw.trim(),
    )?;
    let code = VerificationCode {
        id: "",
        owner,
        user_id: user.map(|user| user.id.as_str()),
        purpose,
        recipient: &recipient,
        context,
        hash: &hash,
        stamp: user.map_or("", |user| user.security_stamp.as_str()),
        session,
    };
    EmailDB::check(
        &state.get_db(),
        &code,
        crate::infra::time::now_seconds(),
        consume,
    )
    .await
}

pub async fn fetch_user(
    state: &AppState,
    claims: &Claims,
) -> AppResult<UserDB> {
    UserDB::fetch_by_id_with(
        &state.get_db(),
        &claims.sub,
        "Failed to fetch verification owner",
        || AuthError::UserNotFound.into(),
    )
    .await
}

pub async fn verify_password_or_otp(
    state: &AppState,
    claims: &Claims,
    payload: &PasswordOrOtpData,
) -> AppResult<()> {
    let user = fetch_user(state, claims).await?;
    rate::check_rate_limit(state, format!("protected-action:{}", claims.sub))
        .await?;
    if let Some(hash) = payload.master_password_hash.as_deref() {
        if user.verify_master_password(hash).await?.is_valid() {
            return Ok(());
        }
        return Err(AuthError::InvalidPassword.into());
    }
    if payload.user_verification_token.is_some() {
        return Err(AppError::bad_request(
            "Verification proof cannot be used for this action",
        ));
    }
    let otp = payload.otp.as_deref().ok_or_else(|| {
        AppError::bad_request("Password or verification code is required")
    })?;
    verify_code(
        state,
        Some(&user),
        PROTECTED_ACTION,
        &user.email,
        "",
        &claims.session_token,
        otp,
        true,
    )
    .await
}

pub async fn email_provider(
    db: &D1Database,
    user_id: &str,
) -> AppResult<Option<String>> {
    let provider = TwoFactorDB::get_for_user_by_type(
        db,
        user_id,
        TwoFactorType::Email as i32,
    )
    .await?;
    let Some(provider) = provider.filter(|provider| provider.enabled) else {
        return Ok(None);
    };
    let data: Value =
        serde_json::from_str(&provider.data).map_err(|_| AppError::Internal)?;
    Ok(data.get("email").and_then(Value::as_str).map(str::to_owned))
}

pub async fn login_metadata(
    db: &D1Database,
    user_id: &str,
) -> AppResult<Value> {
    Ok(email_provider(db, user_id)
        .await?
        .map_or(Value::Null, |email| json!({"Email":mask_email(&email)})))
}

pub async fn issue_login_code(
    state: &AppState,
    user: &UserDB,
) -> AppResult<()> {
    let email = email_provider(&state.get_db(), &user.id)
        .await?
        .ok_or_else(|| {
            AppError::bad_request(
                "Email two-factor authentication is not enabled",
            )
        })?;
    issue_code(state, Some(user), EMAIL_LOGIN, &email, "", "", true, true).await
}

pub async fn verify_login_code(
    state: &AppState,
    user: &UserDB,
    code: &str,
) -> AppResult<()> {
    let email = email_provider(&state.get_db(), &user.id)
        .await?
        .ok_or_else(|| {
            AppError::bad_request(
                "Email two-factor authentication is not enabled",
            )
        })?;
    verify_code(state, Some(user), EMAIL_LOGIN, &email, "", "", code, true)
        .await
}

pub fn registration_verification_required(state: &AppState) -> bool {
    crate::infra::config::env_text(&state.env, "REQUIRE_EMAIL_VERIFICATION")
        .is_some_and(|value| {
            matches!(
                value.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

pub async fn enforce_registration_verification(
    state: &AppState,
    email: &str,
    token: Option<&str>,
) -> AppResult<()> {
    let required = registration_verification_required(state);
    if !required {
        return Ok(());
    }
    verify_code(
        state,
        None,
        REGISTRATION,
        email,
        "",
        "",
        token.ok_or_else(|| {
            AppError::bad_request("Email verification is required")
        })?,
        true,
    )
    .await
}

pub async fn set_email_provider(
    state: &AppState,
    user: &UserDB,
    email: &str,
) -> AppResult<()> {
    EmailDB::enable_provider(
        &state.get_db(),
        &user.id,
        email,
        &Uuid::new_v4().simple().to_string(),
    )
    .await?;
    admin_notify::emit(&state.env, Event::TwoFactorEnable, &user.id).await;
    Ok(())
}

pub async fn send_password_hint(
    state: &AppState,
    user: &UserDB,
) -> AppResult<()> {
    let db = state.get_db();
    let id = Uuid::new_v4().to_string();
    let hash = code_hash(
        &state.config.jwt_secret,
        &user.id,
        "password-hint",
        &user.email,
        "",
        &id,
    )?;
    let marker = VerificationCode {
        id:        &id,
        owner:     &user.id,
        user_id:   Some(&user.id),
        purpose:   "password-hint",
        recipient: &user.email,
        context:   "",
        hash:      &hash,
        stamp:     &user.security_stamp,
        session:   "",
    };
    if !EmailDB::reserve(&db, &marker, crate::infra::time::now_seconds())
        .await?
    {
        return Ok(());
    }
    let text = user
        .master_password_hint
        .as_deref()
        .filter(|hint| !hint.trim().is_empty())
        .unwrap_or(
            "No master password hint was set. Your encrypted vault cannot be \
             recovered without an unlock method.",
        );
    if delivery::deliver_mail(
        &state.env,
        &user.email,
        "password-hint",
        "raywarden password hint",
        text,
    )
    .await
    .is_err()
    {
        EmailDB::cancel(&db, &id).await?;
        return Err(AppError::bad_request("Password hint delivery failed"));
    }
    EmailDB::mark_ready(&db, &id).await?;
    admin_notify::emit(&state.env, Event::PasswordHint, &user.id).await;
    Ok(())
}

pub async fn rate_unauthenticated(
    state: &AppState,
    headers: &HeaderMap,
    purpose: &str,
) -> AppResult<()> {
    rate::check_rate_limit(
        state,
        format!("{purpose}:{}", rate::client_ip(headers)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_hash_is_bound_to_recipient_purpose_and_context() {
        let hash = code_hash(
            "secret",
            "owner",
            EMAIL_LOGIN,
            "a@example.com",
            "",
            "123456",
        )
        .unwrap();
        assert_ne!(
            hash,
            code_hash(
                "secret",
                "owner",
                EMAIL_SETUP,
                "a@example.com",
                "",
                "123456"
            )
            .unwrap()
        );
        assert_ne!(
            hash,
            code_hash(
                "secret",
                "owner",
                EMAIL_LOGIN,
                "b@example.com",
                "",
                "123456"
            )
            .unwrap()
        );
        assert_ne!(
            hash,
            code_hash(
                "secret",
                "owner",
                EMAIL_LOGIN,
                "a@example.com",
                "device",
                "123456"
            )
            .unwrap()
        );
        assert!(!hash.contains("123456"));
    }
    #[test]
    fn email_validation_and_masking() {
        assert_eq!(
            normalize_email(" User@Example.com ").unwrap(),
            "user@example.com"
        );
        assert!(normalize_email("x\n@example.com").is_err());
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
    }
}
