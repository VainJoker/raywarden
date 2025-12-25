use axum::{
    Json,
    extract::State,
    http::HeaderMap,
};
use chrono::Utc;
use glob_match::glob_match;
use serde_json::{
    Value,
    json,
};
use uuid::Uuid;

use crate::{
    errors::AppError,
    infra::cryptor::{
        generate_salt,
        hash_password_for_storage,
    },
    models::user::{
        PreloginResponse,
        RegisterRequest,
        User,
    },
    warden::{
        AppState,
        service::{
            kdf::{
                DEFAULT_PBKDF2_ITERATIONS,
                KDF_TYPE_ARGON2ID,
                KDF_TYPE_PBKDF2,
                ensure_supported_kdf,
            },
            rate,
            user,
        },
    },
};

#[worker::send]
pub async fn prelogin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;

    let ip = rate::client_ip(&headers);
    let rate_limit_key = format!("prelogin:{ip}");
    rate::check_rate_limit(&state, rate_limit_key).await?;

    let params = user::get_kdf_params_by_email(&state, email).await?;

    Ok(Json(PreloginResponse {
        kdf:             params.kdf_type.unwrap_or(KDF_TYPE_PBKDF2),
        kdf_iterations:  params
            .kdf_iterations
            .unwrap_or(DEFAULT_PBKDF2_ITERATIONS),
        kdf_memory:      params.kdf_memory,
        kdf_parallelism: params.kdf_parallelism,
    }))
}

#[worker::send]
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    log::info!("Register request for email: {}", payload.email);

    let ip = rate::client_ip(&headers);
    let rate_limit_key = format!("register:{ip}");
    rate::check_rate_limit(&state, rate_limit_key).await?;

    let allowed_emails = &state.config.allowed_emails;
    if let Some(allowed_emails) = allowed_emails &&
        !allowed_emails
            .iter()
            .any(|pattern| glob_match(pattern, &payload.email))
    {
        return Err(AppError::Unauthorized(
            "Not allowed to signup".to_string(),
        ));
    }

    ensure_supported_kdf(
        payload.kdf,
        payload.kdf_iterations,
        payload.kdf_memory,
        payload.kdf_parallelism,
    )?;

    // Generate salt and hash the password with server-side PBKDF2
    let password_salt = generate_salt()?;
    let hashed_password = hash_password_for_storage(
        &payload.master_password_hash,
        &password_salt,
    )
    .await?;

    let now = Utc::now().to_rfc3339();

    // Only store kdf_memory and kdf_parallelism for Argon2id, clear for PBKDF2
    let (kdf_memory, kdf_parallelism) = if payload.kdf == KDF_TYPE_ARGON2ID {
        (payload.kdf_memory, payload.kdf_parallelism)
    } else {
        (None, None)
    };

    let user = User {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        avatar_color: None,
        email: payload.email.to_lowercase(),
        email_verified: false,
        master_password_hash: hashed_password,
        master_password_hint: payload.master_password_hint,
        password_salt: Some(password_salt),
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        security_stamp: Uuid::new_v4().to_string(),
        totp_recover: None,
        created_at: now.clone(),
        updated_at: now,
    };

    user::insert_user(&state, &user).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn send_verification_email() -> Result<Json<String>, AppError> {
    Ok(Json("fixed-token-to-mock".to_string()))
}
