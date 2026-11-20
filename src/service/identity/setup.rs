//! Private enrollment for a small set of explicitly allowed accounts.
use axum::http::{
    HeaderMap,
    header,
};
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest,
    Sha256,
};
use worker::Env;

use crate::{
    app::AppContext,
    config::normalize_account_email,
    errors::{
        AppError,
        AppResult,
    },
    infra::jwt,
    models::identity::user::UserRow,
    utils::constant_time_eq,
};

pub(crate) const COOKIE_NAME: &str = "raywarden_owner_setup";
pub(crate) const TTL_SECONDS: i64 = 600;
const TOKEN_HEADER: &str = "x-raywarden-setup-token";
const PURPOSE: &str = "owner-setup";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupClaims {
    sub:     String,
    aud:     String,
    purpose: String,
    exp:     i64,
    nbf:     i64,
    iat:     i64,
}

fn allowed_emails(state: &AppContext) -> AppResult<&[String]> {
    state
        .config
        .allowed_emails
        .as_deref()
        .filter(|emails| !emails.is_empty())
        .ok_or_else(|| {
            AppError::bad_request(
                "ALLOWED_EMAILS must specify allowed account emails",
            )
        })
}

fn registration_scope(emails: &[String]) -> String {
    hex::encode(Sha256::digest(emails.join(",").as_bytes()))
}

fn valid_setup_secret(value: &str) -> bool {
    (32..=512).contains(&value.chars().count()) &&
        !value.chars().any(char::is_control) &&
        value == value.trim()
}

fn verify_secret(env: &Env, supplied: &str) -> AppResult<()> {
    // No ordinary-variable fallback and no normalization of secret bytes.
    let expected = env
        .secret("OWNER_SETUP_TOKEN")
        .map_err(|_error| {
            AppError::bad_request("Owner setup is not configured")
        })?
        .to_string();
    if !valid_setup_secret(&expected) {
        return Err(AppError::bad_request(
            "OWNER_SETUP_TOKEN must contain 32 to 512 characters without \
             surrounding whitespace or control characters",
        ));
    }
    if !valid_setup_secret(supplied) ||
        !constant_time_eq(expected.as_bytes(), supplied.as_bytes())
    {
        return Err(AppError::setup_authorization_required());
    }
    Ok(())
}

fn check_origin(origin: &str, headers: &HeaderMap) -> AppResult<()> {
    if headers
        .get(header::ORIGIN)
        .is_some_and(|value| value.to_str().ok() != Some(origin))
    {
        return Err(AppError::setup_authorization_required());
    }
    Ok(())
}

#[allow(
    clippy::explicit_iter_loop,
    reason = "ValueIter borrows HeaderMap; IntoIterator would borrow the \
              temporary GetAll view"
)]
fn cookie_value(headers: &HeaderMap) -> AppResult<Option<&str>> {
    let mut token = None;
    for value in headers.get_all(header::COOKIE).iter() {
        for item in value
            .to_str()
            .map_err(|_error| AppError::setup_authorization_required())?
            .split(';')
        {
            let Some((name, value)) = item.trim().split_once('=') else {
                continue;
            };
            if name == COOKIE_NAME && token.replace(value).is_some() {
                return Err(AppError::setup_authorization_required());
            }
        }
    }
    Ok(token)
}

fn verify_cookie(
    token: &str,
    secret: &str,
    owner: &str,
    domain: &str,
) -> AppResult<()> {
    let claims = jwt::decode::<SetupClaims>(
        token,
        secret.as_bytes(),
        &jwt::ValidationOptions {
            leeway_seconds: 0,
            validate_issued_at: true,
            expected_audience: Some(domain.into()),
            ..Default::default()
        },
    )
    .map_err(|_error| AppError::setup_authorization_required())?;
    if claims.purpose != PURPOSE ||
        claims.sub != owner ||
        claims.exp.checked_sub(claims.iat) != Some(TTL_SECONDS) ||
        claims.nbf != claims.iat
    {
        return Err(AppError::setup_authorization_required());
    }
    Ok(())
}

fn verify_credential(
    state: &AppContext,
    headers: &HeaderMap,
    owner: &str,
) -> AppResult<()> {
    check_origin(state.domain(), headers)?;
    if let Some(token) = headers.get(TOKEN_HEADER) {
        return verify_secret(
            &state.env,
            token
                .to_str()
                .map_err(|_error| AppError::setup_authorization_required())?,
        );
    }
    verify_cookie(
        cookie_value(headers)?
            .ok_or_else(AppError::setup_authorization_required)?,
        &state.jwt_keys.access_secret,
        owner,
        state.domain(),
    )
}

async fn require_available(
    state: &AppContext,
    emails: &[String],
) -> AppResult<()> {
    if !UserRow::has_available_email(state.database(), emails).await? {
        return Err(AppError::conflict("All allowed accounts already exist"));
    }
    Ok(())
}

fn cookie(origin: &str, token: &str, max_age: i64) -> String {
    let secure = if origin.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; \
         Max-Age={max_age}{secure}"
    )
}

pub(crate) async fn issue_cookie(
    state: &AppContext,
    headers: &HeaderMap,
    token: &str,
) -> AppResult<String> {
    check_origin(state.domain(), headers)?;
    let emails = allowed_emails(state)?;
    require_available(state, emails).await?;
    let scope = registration_scope(emails);
    verify_secret(&state.env, token)?;
    let now = crate::utils::time::now_seconds();
    let proof = SetupClaims {
        sub:     scope,
        aud:     state.domain().into(),
        purpose: PURPOSE.into(),
        exp:     now.checked_add(TTL_SECONDS).ok_or(AppError::Internal)?,
        nbf:     now,
        iat:     now,
    };
    let signed = jwt::encode(&proof, state.jwt_keys.access_secret.as_bytes())?;
    Ok(cookie(state.domain(), &signed, TTL_SECONDS))
}

pub(crate) async fn authorize_registration(
    state: &AppContext,
    headers: &HeaderMap,
    requested_email: &str,
) -> AppResult<String> {
    let emails = allowed_emails(state)?;
    verify_credential(state, headers, &registration_scope(emails))?;
    let address = normalize_account_email(requested_email)?;
    if !emails.contains(&address) {
        return Err(AppError::setup_authorization_required());
    }
    if !UserRow::has_available_email(
        state.database(),
        std::slice::from_ref(&address),
    )
    .await?
    {
        return Err(AppError::conflict(
            "An account with this email already exists",
        ));
    }
    Ok(address)
}

pub(crate) async fn registration_enabled(
    state: &AppContext,
    headers: &HeaderMap,
) -> AppResult<bool> {
    if !headers.contains_key(TOKEN_HEADER) && cookie_value(headers)?.is_none() {
        return Ok(false);
    }
    let emails = allowed_emails(state)?;
    if verify_credential(state, headers, &registration_scope(emails)).is_err() {
        return Ok(false);
    }
    UserRow::has_available_email(state.database(), emails).await
}

pub(crate) fn clear_cookie(state: &AppContext) -> String {
    cookie(state.domain(), "", 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_secret_bounds_never_trim_or_accept_controls() {
        assert!(valid_setup_secret(&"a".repeat(32)));
        assert!(valid_setup_secret(&"a".repeat(512)));
        for invalid in [
            "a".repeat(31),
            "a".repeat(513),
            format!(" {}", "a".repeat(32)),
            format!("{} ", "a".repeat(32)),
            format!("{}\n", "a".repeat(32)),
            format!("{}\u{85}x", "a".repeat(32)),
        ] {
            assert!(!valid_setup_secret(&invalid));
        }
    }

    #[test]
    fn setup_cookies_require_their_exact_scope_and_strict_expiry() {
        let secret = "test-signing-key";
        let now = crate::utils::time::now_seconds();
        let mut proof = SetupClaims {
            sub:     "owner@example.test".into(),
            aud:     "https://vault.test".into(),
            purpose: PURPOSE.into(),
            exp:     now + TTL_SECONDS,
            nbf:     now,
            iat:     now,
        };
        let signed = jwt::encode(&proof, secret.as_bytes())
            .expect("valid setup fixture");
        assert!(verify_cookie(&signed, secret, &proof.sub, &proof.aud).is_ok());
        assert!(
            verify_cookie(&signed, secret, "other@example.test", &proof.aud)
                .is_err()
        );
        assert!(
            verify_cookie(&signed, secret, &proof.sub, "https://other.test")
                .is_err()
        );
        proof.purpose = "email-factor".into();
        assert!(
            verify_cookie(
                &jwt::encode(&proof, secret.as_bytes())
                    .expect("valid setup fixture"),
                secret,
                &proof.sub,
                &proof.aud
            )
            .is_err()
        );
        proof.purpose = PURPOSE.into();
        proof.iat = now - TTL_SECONDS;
        proof.nbf = proof.iat;
        proof.exp = now;
        assert!(
            verify_cookie(
                &jwt::encode(&proof, secret.as_bytes())
                    .expect("valid setup fixture"),
                secret,
                &proof.sub,
                &proof.aud
            )
            .is_err()
        );
    }

    #[test]
    fn cookie_security_follows_the_configured_origin_and_rejects_duplicates() {
        assert!(cookie("https://vault.test", "test", 600).contains("; Secure"));
        assert!(
            !cookie("http://localhost:8787", "test", 600).contains("; Secure")
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{COOKIE_NAME}=one; {COOKIE_NAME}=two")
                .parse()
                .expect("valid setup fixture"),
        );
        assert!(cookie_value(&headers).is_err());
    }
}
