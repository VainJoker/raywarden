//! Short-lived authorization for creating the one owner-supplied account.
use axum::http::{
    HeaderMap,
    header,
};
use serde::{
    Deserialize,
    Serialize,
};
use worker::Env;

use crate::{
    api::AppState,
    errors::{
        AppError,
        AppResult,
    },
    infra::{
        config::env_text,
        crypto::ct_eq,
        jwt,
    },
    models::user::UserDB,
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

fn unauthorized() -> AppError {
    AppError::Unauthorized {
        message: "Owner setup authorization is required".into(),
    }
}

fn normalize_owner_email(raw: &str) -> AppResult<String> {
    let invalid = || {
        AppError::bad_request(
            "ALLOWED_EMAILS must contain exactly one plain email address",
        )
    };
    if raw.chars().any(char::is_control) || !raw.is_ascii() {
        return Err(invalid());
    }
    let email = raw.trim().to_ascii_lowercase();
    let mut parts = email.split('@');
    let local = parts.next().ok_or_else(invalid)?;
    let domain = parts.next().ok_or_else(invalid)?;
    if parts.next().is_some() ||
        email.len() > 254 ||
        local.is_empty() ||
        local.len() > 64 ||
        local.starts_with('.') ||
        local.ends_with('.') ||
        local.contains("..") ||
        !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() ||
                matches!(byte, b'.' | b'_' | b'+' | b'-')
        }) ||
        domain.len() > 253 ||
        !domain.contains('.') ||
        !domain.split('.').all(|label| {
            !label.is_empty() &&
                label.len() <= 63 &&
                !label.starts_with('-') &&
                !label.ends_with('-') &&
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid());
    }
    Ok(email)
}

pub(crate) fn owner_email(env: &Env) -> AppResult<String> {
    let raw = env_text(env, "ALLOWED_EMAILS").ok_or_else(|| {
        AppError::bad_request("ALLOWED_EMAILS must specify the owner email")
    })?;
    normalize_owner_email(&raw)
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
    if !valid_setup_secret(supplied) || !ct_eq(&expected, supplied) {
        return Err(unauthorized());
    }
    Ok(())
}

fn secure_cookie(domain: &str) -> AppResult<bool> {
    let url = url::Url::parse(domain).map_err(|_error| {
        AppError::bad_request("Owner setup requires a valid DOMAIN")
    })?;
    if url.scheme() == "https" {
        return Ok(true);
    }
    let loopback = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if url.scheme() == "http" && loopback {
        return Ok(false);
    }
    Err(AppError::bad_request(
        "Owner setup requires HTTPS outside localhost",
    ))
}

fn check_origin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    if let Some(origin) = headers.get(header::ORIGIN) {
        let expected = url::Url::parse(state.get_domain())
            .map_err(|_error| AppError::Internal)?
            .origin()
            .ascii_serialization();
        if origin.to_str().ok() != Some(expected.as_str()) {
            return Err(unauthorized());
        }
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
        for item in value.to_str().map_err(|_error| unauthorized())?.split(';')
        {
            let Some((name, value)) = item.trim().split_once('=') else {
                continue;
            };
            if name == COOKIE_NAME && token.replace(value).is_some() {
                return Err(unauthorized());
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
            leeway: 0,
            validate_iat: true,
            expected_aud: Some(domain.into()),
            ..Default::default()
        },
    )
    .map_err(|_error| unauthorized())?
    .claims;
    if claims.purpose != PURPOSE ||
        claims.sub != owner ||
        claims.aud != domain ||
        claims.exp.checked_sub(claims.iat) != Some(TTL_SECONDS) ||
        claims.nbf != claims.iat
    {
        return Err(unauthorized());
    }
    Ok(())
}

fn verify_credential(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
) -> AppResult<()> {
    check_origin(state, headers)?;
    if let Some(token) = headers.get(TOKEN_HEADER) {
        return verify_secret(
            &state.env,
            token.to_str().map_err(|_error| unauthorized())?,
        );
    }
    verify_cookie(
        cookie_value(headers)?.ok_or_else(unauthorized)?,
        &state.config.jwt_secret,
        owner,
        state.get_domain(),
    )
}

async fn require_empty(state: &AppState) -> AppResult<()> {
    if UserDB::exists_any(&state.get_db()).await? {
        return Err(AppError::conflict("The owner account already exists"));
    }
    Ok(())
}

fn cookie(domain: &str, token: &str, max_age: i64) -> AppResult<String> {
    let secure = if secure_cookie(domain)? {
        "; Secure"
    } else {
        ""
    };
    Ok(format!(
        "{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; \
         Max-Age={max_age}{secure}"
    ))
}

pub(crate) async fn issue_cookie(
    state: &AppState,
    headers: &HeaderMap,
    token: &str,
) -> AppResult<String> {
    check_origin(state, headers)?;
    secure_cookie(state.get_domain())?;
    require_empty(state).await?;
    let email = owner_email(&state.env)?;
    verify_secret(&state.env, token)?;
    let now = crate::infra::time::now_seconds();
    let proof = SetupClaims {
        sub:     email,
        aud:     state.get_domain().into(),
        purpose: PURPOSE.into(),
        exp:     now.checked_add(TTL_SECONDS).ok_or(AppError::Internal)?,
        nbf:     now,
        iat:     now,
    };
    let signed = jwt::encode(&proof, state.config.jwt_secret.as_bytes())?;
    cookie(state.get_domain(), &signed, TTL_SECONDS)
}

pub(crate) async fn authorize_registration(
    state: &AppState,
    headers: &HeaderMap,
    requested_email: &str,
) -> AppResult<String> {
    secure_cookie(state.get_domain())?;
    require_empty(state).await?;
    let owner = owner_email(&state.env)?;
    verify_credential(state, headers, &owner)?;
    if normalize_owner_email(requested_email)? != owner {
        return Err(unauthorized());
    }
    Ok(owner)
}

pub(crate) async fn registration_enabled(
    state: &AppState,
    headers: &HeaderMap,
) -> AppResult<bool> {
    if !headers.contains_key(TOKEN_HEADER) && cookie_value(headers)?.is_none() {
        return Ok(false);
    }
    if UserDB::exists_any(&state.get_db()).await? {
        return Ok(false);
    }
    let owner = owner_email(&state.env)?;
    secure_cookie(state.get_domain())?;
    Ok(verify_credential(state, headers, &owner).is_ok())
}

pub(crate) fn clear_cookie(state: &AppState) -> AppResult<String> {
    cookie(state.get_domain(), "", 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_email_is_one_plain_normalized_address() {
        assert_eq!(
            normalize_owner_email(" Owner+vault@Example.TEST ").unwrap(),
            "owner+vault@example.test"
        );
        for invalid in [
            "",
            "*",
            "a*@example.test",
            "a?@example.test",
            "a@b.test,c@d.test",
            "a@b.test\nc@d.test",
            "a@b.test;",
            "a@@b.test",
            "a@localhost",
            ".a@b.test",
            "a..b@b.test",
            "a@-b.test",
            "a@b..test",
            "a @b.test",
        ] {
            assert!(normalize_owner_email(invalid).is_err(), "{invalid:?}");
        }
    }

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
        let now = crate::infra::time::now_seconds();
        let mut proof = SetupClaims {
            sub:     "owner@example.test".into(),
            aud:     "https://vault.test".into(),
            purpose: PURPOSE.into(),
            exp:     now + TTL_SECONDS,
            nbf:     now,
            iat:     now,
        };
        let signed = jwt::encode(&proof, secret.as_bytes()).unwrap();
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
                &jwt::encode(&proof, secret.as_bytes()).unwrap(),
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
                &jwt::encode(&proof, secret.as_bytes()).unwrap(),
                secret,
                &proof.sub,
                &proof.aud
            )
            .is_err()
        );
    }

    #[test]
    fn only_loopback_http_can_omit_secure_and_duplicate_cookies_fail() {
        assert!(
            cookie("https://vault.test", "test", 600)
                .unwrap()
                .contains("; Secure")
        );
        assert!(
            !cookie("http://localhost:8787", "test", 600)
                .unwrap()
                .contains("; Secure")
        );
        assert!(cookie("http://127.0.0.2:8787", "test", 600).is_ok());
        assert!(cookie("http://[::1]:8787", "test", 600).is_ok());
        assert!(cookie("http://vault.test", "test", 600).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{COOKIE_NAME}=one; {COOKIE_NAME}=two")
                .parse()
                .unwrap(),
        );
        assert!(cookie_value(&headers).is_err());
    }
}
