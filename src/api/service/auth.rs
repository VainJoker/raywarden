use axum::http::HeaderMap;
use serde_json::{
    Map,
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::AppError,
    infra::jwt,
    models::{
        device::DeviceDB,
        user::UserDB,
    },
};

pub(crate) fn request_device_type(
    headers: &HeaderMap,
) -> Result<i32, AppError> {
    let value = headers
        .get("device-type")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::bad_request("Missing device-type header"))?;
    value
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|value| (0..=40).contains(value))
        .ok_or_else(|| AppError::bad_request("Invalid device-type header"))
}

/// Generate access + refresh tokens and format the response.
///
/// Contract:
/// - Inputs: validated `User`, `state` (for secrets), optional remember token.
/// - Outputs: `TokenResponse`-shaped JSON (built in the handler today).
/// - Errors: `AppError::Internal` for signing failures.
pub fn generate_tokens(
    user: &UserDB,
    state: &AppState,
    device: &DeviceDB,
) -> Result<(String, String, i64), AppError> {
    // Align with the project's Claims shape (infra/jwt.rs)
    let mut amr = std::collections::HashSet::new();
    amr.insert("Application".to_string());

    let mut access_claims = Claims::new(
        user.id.clone(),
        user.email.clone(),
        user.name.clone().unwrap_or_else(|| "User".to_string()),
        true,
        user.email_verified,
        amr.clone(),
        Some(device.identifier.clone()),
        i64::try_from(state.config.jwt_duration_seconds).unwrap_or(3600),
    );

    let mut refresh_claims = Claims::new(
        user.id.clone(),
        user.email.clone(),
        user.name.clone().unwrap_or_else(|| "User".to_string()),
        true,
        user.email_verified,
        amr,
        Some(device.identifier.clone()),
        30 * 24 * 60 * 60,
    );

    access_claims.sstamp.clone_from(&user.security_stamp);
    access_claims
        .session_token
        .clone_from(&device.session_token);
    access_claims.token_use = "access".to_string();
    refresh_claims.sstamp.clone_from(&user.security_stamp);
    refresh_claims
        .session_token
        .clone_from(&device.session_token);
    refresh_claims.token_use = "refresh".to_string();

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

    let expires_in = access_claims.exp - crate::infra::time::now_seconds();

    Ok((access_token, refresh_token, expires_in))
}

/// Helper for building the response body map for token responses.
///
/// This is intentionally low-level to avoid introducing a new DTO layer.
pub fn token_response_json(
    user: &UserDB,
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
    map.insert("scope".to_string(), json!("api offline_access"));

    map.insert("Key".to_string(), json!(user.key));
    map.insert("PrivateKey".to_string(), json!(user.private_key));
    let mut account_keys = crate::models::account_keys::response(user);
    if let Some(object) = account_keys.as_object_mut() {
        if let Some(value) = object.remove("object") {
            object.insert("Object".into(), value);
        }
    }
    for name in ["publicKeyEncryptionKeyPair", "signatureKeyPair"] {
        if let Some(object) =
            account_keys.get_mut(name).and_then(Value::as_object_mut)
        {
            if let Some(value) = object.remove("object") {
                object.insert("Object".into(), value);
            }
        }
    }
    map.insert("AccountKeys".into(), account_keys);
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
            "HasMasterPassword": !user.master_password_hash.is_empty(),
            "MasterPasswordUnlock": {
                "Kdf": { "KdfType": user.kdf_type, "Iterations": user.kdf_iterations, "Memory": user.kdf_memory, "Parallelism": user.kdf_parallelism },
                "MasterKeyWrappedUserKey": user.key,
                "MasterKeyEncryptedUserKey": user.key,
                "Salt": user.email, "ContainedKeyId": user.user_key_id
            },
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

pub(crate) fn parse_client_version(
    value: &str,
) -> Option<((u64, u64, u64), bool)> {
    let identifiers = |part: &str| {
        !part.is_empty() &&
            part.split('.').all(|id| {
                !id.is_empty() &&
                    id.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
    };
    let (value, build) = value
        .split_once('+')
        .map_or((value, None), |(core, build)| (core, Some(build)));
    if build.is_some_and(|value| !identifiers(value)) {
        return None;
    }
    let (core, pre) = value
        .split_once('-')
        .map_or((value, None), |(core, pre)| (core, Some(pre)));
    if pre.is_some_and(|value| {
        !identifiers(value) ||
            value.split('.').any(|id| {
                id.len() > 1 &&
                    id.starts_with('0') &&
                    id.bytes().all(|c| c.is_ascii_digit())
            })
    }) {
        return None;
    }
    let pieces = core.split('.').collect::<Vec<_>>();
    if pieces.len() != 3 {
        return None;
    }
    let number = |part: &str| {
        if part.is_empty() ||
            !part.bytes().all(|b| b.is_ascii_digit()) ||
            (part.len() > 1 && part.starts_with('0'))
        {
            None
        } else {
            part.parse().ok()
        }
    };
    Some((
        (number(pieces[0])?, number(pieces[1])?, number(pieces[2])?),
        pre.is_some(),
    ))
}
