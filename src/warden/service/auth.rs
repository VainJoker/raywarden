use chrono::{
    Duration,
    Utc,
};
use serde_json::{
    Map,
    Value,
    json,
};

use crate::{
    errors::AppError,
    infra::jwtor as jwt,
    models::user::User,
    warden::{
        AppState,
        service::claims::Claims,
    },
};

/// Generates the JSON error response for 2FA required.
///
/// Kept here so handlers don't need to know the exact Bitwarden-ish payload.
pub fn json_err_twofactor(providers: &[i32]) -> Value {
    serde_json::json!({
        "error": "invalid_grant",
        "error_description": "Two factor required.",
        "TwoFactorProviders": providers.iter().map(std::string::ToString::to_string).collect::<Vec<String>>(),
        "TwoFactorProviders2": {},
        "MasterPasswordPolicy": {
            "Object": "masterPasswordPolicy"
        }
    })
}

/// Generate access + refresh tokens and format the response.
///
/// Contract:
/// - Inputs: validated `User`, `state` (for secrets), optional remember token.
/// - Outputs: `TokenResponse`-shaped JSON (built in the handler today).
/// - Errors: `AppError::Internal` for signing failures.
pub fn generate_tokens(
    user: &User,
    state: &AppState,
) -> Result<(String, String, i64), AppError> {
    // Align with the project's Claims shape (infra/jwtor.rs)
    let mut amr = std::collections::HashSet::new();
    amr.insert("Application".to_string());

    let access_claims = Claims::new(
        user.id.clone(),
        user.email.clone(),
        user.name.clone().unwrap_or_else(|| "User".to_string()),
        true,
        true,
        amr.clone(),
        None,
        Duration::hours(1).num_seconds(),
    );

    let refresh_claims = Claims::new(
        user.id.clone(),
        user.email.clone(),
        user.name.clone().unwrap_or_else(|| "User".to_string()),
        true,
        true,
        amr,
        None,
        Duration::days(30).num_seconds(),
    );

    let jwt_secret = state.config.jwt_secret.clone();
    let access_token = jwt::encode(&access_claims, jwt_secret.as_bytes())
        .map_err(|e| {
            log::warn!("access token encode failed: {e}");
            AppError::Internal
        })?;

    let jwt_refresh_secret = state.config.jwt_refresh_secret.clone();
    let refresh_token =
        jwt::encode(&refresh_claims, jwt_refresh_secret.as_bytes()).map_err(
            |e| {
                log::warn!("refresh token encode failed: {e}");
                AppError::Internal
            },
        )?;

    let expires_in = access_claims.exp - Utc::now().timestamp();

    Ok((access_token, refresh_token, expires_in))
}

/// Helper for building the response body map for token responses.
///
/// This is intentionally low-level to avoid introducing a new DTO layer.
pub fn token_response_json(
    user: &User,
    access_token: &str,
    refresh_token: &str,
    expires_in: i64,
    two_factor_token: Option<String>,
) -> Value {
    let mut map = Map::new();

    map.insert("access_token".to_string(), json!(access_token));
    map.insert("expires_in".to_string(), json!(expires_in));
    map.insert("token_type".to_string(), json!(bearer_token_type()));
    map.insert("refresh_token".to_string(), json!(refresh_token));

    map.insert("Key".to_string(), json!(user.key));
    map.insert("PrivateKey".to_string(), json!(user.private_key));
    map.insert("Kdf".to_string(), json!(user.kdf_type));
    map.insert("KdfIterations".to_string(), json!(user.kdf_iterations));
    if let Some(v) = user.kdf_memory {
        map.insert("KdfMemory".to_string(), json!(v));
    }
    if let Some(v) = user.kdf_parallelism {
        map.insert("KdfParallelism".to_string(), json!(v));
    }

    map.insert("ResetMasterPassword".to_string(), json!(false));
    map.insert("ForcePasswordReset".to_string(), json!(false));

    map.insert(
        "UserDecryptionOptions".to_string(),
        json!({
            "has_master_password": true,
            "object": "userDecryptionOptions"
        }),
    );

    if let Some(t) = two_factor_token {
        map.insert("TwoFactorToken".to_string(), json!(t));
    }

    Value::Object(map)
}

#[allow(clippy::missing_const_for_fn)]
pub const fn bearer_token_type() -> &'static str {
    "Bearer"
}
