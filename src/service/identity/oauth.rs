//! OAuth cookies and signed token responses.
use axum::http::HeaderMap;
use serde::Serialize;
use serde_json::Value;

use crate::{
    errors::{AppError, AppResult},
    infra::jwt,
    models::identity::{device::SessionSnapshot, user::UserRow},
    service::identity::{
        jwt_keys::JwtKeys,
        session::{Claims, ClaimsExtensions, TokenUse},
    },
};

const MAX_NAME_CLAIM_BYTES: usize = 1024;

/// OAuth clients use camelCase, underscores and compact field spellings.
pub fn normalize_form_key(key: &str) -> String {
    key.bytes()
        .filter(|byte| *byte != b'_')
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

pub fn allows_token_cookie_origin(headers: &HeaderMap, domain: &str) -> bool {
    if headers
        .get("sec-fetch-site")
        .is_some_and(|value| !matches!(value.to_str().ok(), Some("same-origin" | "none")))
    {
        return false;
    }
    headers
        .get("origin")
        .is_none_or(|value| value.to_str().ok() == Some(domain))
}

pub fn read_token_cookie(headers: &HeaderMap, name: &str) -> AppResult<Option<String>> {
    let mut token = None;
    for header in &headers.get_all("cookie") {
        let raw = header
            .to_str()
            .map_err(|_error| AppError::bad_request("Invalid token cookie"))?;
        for item in raw.split(';') {
            if let Some((key, value)) = item.trim().split_once('=')
                && key == name
            {
                if token.is_some() || value.is_empty() {
                    return Err(AppError::bad_request("Duplicate or empty token cookie"));
                }
                token = Some(value.to_owned());
            }
        }
    }
    Ok(token)
}

pub fn refresh_cookie_header(domain: &str, token: &str) -> AppResult<axum::http::HeaderValue> {
    token_cookie_header(domain, "bw_refresh_token", token, 2_592_000)
}

pub fn token_cookie_header(
    domain: &str,
    name: &str,
    token: &str,
    max_age_seconds: i64,
) -> AppResult<axum::http::HeaderValue> {
    let secure = if domain.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    axum::http::HeaderValue::from_str(&format!(
        "{name}={token}; Path=/identity/connect/token; HttpOnly; \
         SameSite=Strict; Max-Age={max_age_seconds}{secure}"
    ))
    .map_err(|error| AppError::internal_debug("Failed to build OAuth token cookie", error))
}

/// Signed access and refresh tokens for a single account generation and device
/// session.
pub(crate) struct IssuedTokens {
    access_token: String,
    refresh_token: String,
    expires_in_seconds: i64,
}

#[derive(Serialize)]
pub(crate) struct TokenResponse {
    access_token: String,
    expires_in: i64,
    token_type: &'static str,
    pub(crate) refresh_token: String,
    scope: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct LoginTokenResponse {
    #[serde(flatten)]
    pub(crate) tokens: TokenResponse,
    key: String,
    private_key: String,
    account_keys: Value,
    kdf: i32,
    kdf_iterations: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf_memory: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf_parallelism: Option<i32>,
    reset_master_password: bool,
    force_password_reset: bool,
    master_password_policy: MasterPasswordPolicy,
    pub(crate) user_decryption_options: UserDecryptionOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) two_factor_token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MasterPasswordPolicy {
    object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct UserDecryptionOptions {
    has_master_password: bool,
    master_password_unlock: Option<MasterPasswordUnlock>,
    object: &'static str,
    #[serde(rename = "WebAuthnPrfOption", skip_serializing_if = "Option::is_none")]
    pub(crate) webauthn_prf_option: Option<WebauthnPrfOption>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MasterPasswordUnlock {
    kdf: UnlockKdf,
    master_key_wrapped_user_key: String,
    master_key_encrypted_user_key: String,
    salt: String,
    contained_key_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct UnlockKdf {
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct WebauthnPrfOption {
    pub(crate) encrypted_user_key: String,
    pub(crate) encrypted_private_key: String,
}

impl IssuedTokens {
    pub(crate) fn issue(
        user: &UserRow,
        session: &SessionSnapshot<'_>,
        keys: &JwtKeys,
        duration_seconds: u64,
    ) -> AppResult<Self> {
        // Keep oversized legacy profile names from exhausting the JWT budget.
        let name = user
            .name
            .as_deref()
            .filter(|name| name.len() <= MAX_NAME_CLAIM_BYTES)
            .unwrap_or("User");
        let session_claims = |purpose, duration| {
            Claims::for_session(
                session,
                ClaimsExtensions {
                    is_premium: Some(true),
                    name: Some(name.to_owned()),
                    email: Some(user.email.clone()),
                    is_email_verified: Some(user.is_email_verified),
                    amr: Some(std::collections::HashSet::from(["Application".to_string()])),
                    device: None,
                },
                purpose,
                duration,
            )
        };
        let access_claims = session_claims(
            TokenUse::Access,
            i64::try_from(duration_seconds).unwrap_or(3600),
        );
        let refresh_claims = session_claims(TokenUse::Refresh, 30 * 24 * 60 * 60);

        let access_token = jwt::encode(&access_claims, keys.access_secret.as_bytes())?;

        let refresh_token = jwt::encode(&refresh_claims, keys.refresh_secret.as_bytes())?;

        let expires_in_seconds = access_claims.exp - crate::utils::time::now_seconds();

        Ok(Self {
            access_token,
            refresh_token,
            expires_in_seconds,
        })
    }

    pub(crate) fn refresh_response(self) -> TokenResponse {
        TokenResponse {
            access_token: self.access_token,
            expires_in: self.expires_in_seconds,
            token_type: "Bearer",
            refresh_token: self.refresh_token,
            scope: "api offline_access",
        }
    }

    pub(crate) fn login_response(
        self,
        user: &UserRow,
        two_factor_token: Option<String>,
    ) -> LoginTokenResponse {
        let account_keys =
            crate::service::identity::account_keys::account_keys_response(user, "Object");
        let has_master_password = !user.master_password_hash.is_empty();
        let master_password_unlock = has_master_password.then(|| MasterPasswordUnlock {
            kdf: UnlockKdf {
                kdf_type: user.kdf_type,
                iterations: user.kdf_iterations,
                memory: user.kdf_memory,
                parallelism: user.kdf_parallelism,
            },
            master_key_wrapped_user_key: user.key.clone(),
            master_key_encrypted_user_key: user.key.clone(),
            salt: user.email.clone(),
            contained_key_id: user.user_key_id.clone(),
        });
        LoginTokenResponse {
            tokens: self.refresh_response(),
            key: user.key.clone(),
            private_key: user.private_key.clone(),
            account_keys,
            kdf: user.kdf_type,
            kdf_iterations: user.kdf_iterations,
            kdf_memory: user.kdf_memory,
            kdf_parallelism: user.kdf_parallelism,
            reset_master_password: false,
            force_password_reset: false,
            master_password_policy: MasterPasswordPolicy {
                object: "masterPasswordPolicy",
            },
            user_decryption_options: UserDecryptionOptions {
                has_master_password,
                master_password_unlock,
                object: "userDecryptionOptions",
                webauthn_prf_option: None,
            },
            two_factor_token,
        }
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[test]
    fn cookie_authority_is_limited_to_the_configured_origin() {
        let mut headers = HeaderMap::new();
        assert!(allows_token_cookie_origin(&headers, "https://vault.test"));
        headers.insert(
            "origin",
            "https://vault.test".parse().expect("valid auth fixture"),
        );
        headers.insert(
            "sec-fetch-site",
            "same-origin".parse().expect("valid auth fixture"),
        );
        assert!(allows_token_cookie_origin(&headers, "https://vault.test"));
        headers.insert(
            "sec-fetch-site",
            "same-site".parse().expect("valid auth fixture"),
        );
        assert!(!allows_token_cookie_origin(&headers, "https://vault.test"));
        headers.remove("sec-fetch-site");
        headers.insert(
            "origin",
            "https://other.test".parse().expect("valid auth fixture"),
        );
        assert!(!allows_token_cookie_origin(&headers, "https://vault.test"));
        headers.insert(
            "cookie",
            "bw_refresh_token=one; bw_refresh_token=two"
                .parse()
                .expect("valid auth fixture"),
        );
        assert!(read_token_cookie(&headers, "bw_refresh_token").is_err());
        let cookie =
            refresh_cookie_header("https://vault.test", "token").expect("valid auth fixture");
        assert!(
            cookie
                .to_str()
                .expect("valid auth fixture")
                .contains("HttpOnly; SameSite=Strict")
        );
        assert!(
            cookie
                .to_str()
                .expect("valid auth fixture")
                .ends_with("; Secure")
        );
    }
}
