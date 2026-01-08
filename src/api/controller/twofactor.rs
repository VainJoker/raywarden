use axum::{
    Json,
    extract::State,
};
use serde_json::Value;

use crate::{
    api::{
        AppState,
        service::claims::AuthUser,
    },
    errors::{
        AppError,
        AuthError,
    },
    infra::cryptor::{
        base32_decode,
        ct_eq,
        generate_recovery_code,
        generate_totp_secret,
        validate_totp,
    },
    models::{
        twofactor::{
            DisableAuthenticatorData,
            DisableTwoFactorData,
            EnableAuthenticatorData,
            RecoverTwoFactor,
            TwoFactorDB,
            TwoFactorType,
        },
        user::{
            PasswordOrOtpData,
            UserDB,
        },
    },
};

/// GET /api/two-factor - Get all enabled 2FA providers for current user
#[worker::send]
pub async fn get_twofactor(
    State(state): State<AppState>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let twofactors = TwoFactorDB::list_user_twofactors(&db, &user_id).await?;
    let twofactors: Vec<Value> = twofactors
        .iter()
        .map(crate::models::twofactor::TwoFactorDB::to_json_provider)
        .collect();

    Ok(Json(serde_json::json!({
        "data": twofactors,
        "object": "list",
        "continuationToken": null,
    })))
}

/// POST /api/two-factor/get-authenticator - Get or generate TOTP secret
#[worker::send]
pub async fn get_authenticator(
    State(state): State<AppState>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    // Verify master password
    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user in get_authenticator",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    validate_password_or_otp(&user, &data).await?;

    let existing = TwoFactorDB::get_for_user_by_type(
        &db,
        &user_id,
        TwoFactorType::Authenticator as i32,
    )
    .await?;

    let (enabled, key) = match existing {
        Some(tf) => (true, tf.data),
        None => (false, generate_totp_secret()?),
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// POST /api/two-factor/authenticator - Activate TOTP
#[worker::send]
pub async fn activate_authenticator(
    State(state): State<AppState>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    // Verify master password
    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user in disable_twofactor",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    validate_password_or_otp(&user, &PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp:                  data.otp,
    })
    .await?;

    let key = data.key.to_uppercase();

    // Validate key format (Base32, 20 bytes = 32 characters without padding)
    let decoded_key = base32_decode(&key)?;
    if decoded_key.len() != 20 {
        return Err(AppError::Params("Invalid key length".to_string()));
    }

    let existing = TwoFactorDB::get_for_user_by_type(
        &db,
        &user_id,
        TwoFactorType::Authenticator as i32,
    )
    .await?;

    // Get last_used from existing record to prevent replay during
    // reconfiguration
    let previous_last_used = existing.as_ref().map_or(0, |tf| tf.last_used);

    // Validate TOTP code and capture time step for replay protection
    let allow_drift = state.config.authenticator_disable_time_drift;
    let last_used_step =
        validate_totp(&data.token, &key, previous_last_used, allow_drift)
            .await?;

    // Delete existing TOTP and any remember-device tokens bound to it to avoid
    // stale bypass
    TwoFactorDB::delete_types_for_user(&db, &user_id, &[
        TwoFactorType::Authenticator as i32,
        TwoFactorType::Remember as i32,
    ])
    .await?;

    // Create new TOTP entry
    let mut twofactor = TwoFactorDB::new(
        user_id.clone(),
        TwoFactorType::Authenticator,
        key.clone(),
    );
    twofactor.last_used = last_used_step;

    TwoFactorDB::insert_twofactor(&db, &twofactor).await?;

    // Generate recovery code if not exists
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// PUT /api/two-factor/authenticator - Same as POST
#[worker::send]
pub async fn activate_authenticator_put(
    state: State<AppState>,
    auth_user: AuthUser,
    json: Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    activate_authenticator(state, auth_user, json).await
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[worker::send]
pub async fn disable_twofactor(
    State(state): State<AppState>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    // Verify master password
    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user in disable_twofactor",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    validate_password_or_otp(&user, &PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp:                  data.otp,
    })
    .await?;

    let type_ = data.r#type;

    // Delete the specified 2FA type
    TwoFactorDB::delete_type_for_user(&db, &user_id, type_).await?;

    log::info!("User {} disabled 2FA type {}", user_id, type_);

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": type_,
        "object": "twoFactorProvider"
    })))
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[worker::send]
pub async fn disable_authenticator(
    State(state): State<AppState>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    if data.r#type != TwoFactorType::Authenticator as i32 {
        return Err(AppError::Params("Invalid two factor type".to_string()));
    }

    // Verify master password (OTP not supported in this minimal implementation)
    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user in disable_authenticator",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    validate_password_or_otp(&user, &PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp:                  data.otp,
    })
    .await?;

    // Fetch existing TOTP and verify key matches before deleting
    let existing =
        TwoFactorDB::get_for_user_by_type(&db, &user_id, data.r#type).await?;

    let Some(tf) = existing else {
        return Err(AppError::Params("TOTP not configured".to_string()));
    };

    // Compare keys case-insensitively (key is stored uppercased during
    // activation)
    if !ct_eq(&tf.data, &data.key.to_uppercase()) {
        return Err(AppError::Auth(AuthError::InvalidTotp));
    }

    TwoFactorDB::delete_type_for_user(&db, &user_id, data.r#type).await?;

    log::info!(
        "User {} disabled authenticator (2FA type {})",
        user_id,
        data.r#type
    );

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": data.r#type,
        "object": "twoFactorProvider"
    })))
}

/// PUT /api/two-factor/disable - Same as POST
#[worker::send]
pub async fn disable_twofactor_put(
    state: State<AppState>,
    auth_user: AuthUser,
    json: Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    disable_twofactor(state, auth_user, json).await
}

/// POST /api/two-factor/get-recover - Get recovery code
#[worker::send]
pub async fn get_recover(
    State(state): State<AppState>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    // Verify master password
    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user in get_recover",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    validate_password_or_otp(&user, &data).await?;

    Ok(Json(serde_json::json!({
        "code": user.totp_recover,
        "object": "twoFactorRecover"
    })))
}

/// POST /api/two-factor/recover - Use recovery code to disable all 2FA
#[worker::send]
pub async fn recover(
    State(state): State<AppState>,
    Json(data): Json<RecoverTwoFactor>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    // Get user by email
    let user = UserDB::fetch_by_email_with(
        &db,
        &data.email,
        "Failed to fetch user by email for 2FA recover",
        || {
            AppError::Auth(AuthError::InvalidCredentials(
                "Username or password is incorrect".to_string(),
            ))
        },
    )
    .await?;

    // Verify master password
    let verification = user
        .verify_master_password(&data.master_password_hash)
        .await?;
    if !verification.is_valid() {
        return Err(AppError::Auth(AuthError::InvalidCredentials(
            "Username or password is incorrect".to_string(),
        )));
    }

    // Check recovery code (case-insensitive)
    let is_valid = user.totp_recover.as_ref().is_some_and(|stored_code| {
        ct_eq(
            &stored_code.to_uppercase(),
            &data.recovery_code.to_uppercase(),
        )
    });

    if !is_valid {
        return Err(AppError::Auth(AuthError::InvalidTotp));
    }

    // Delete all 2FA methods
    TwoFactorDB::delete_for_user(&db, &user.id).await?;

    // Clear recovery code
    UserDB::clear_recovery_code(&db, &user.id).await?;

    log::info!("User {} recovered 2FA using recovery code", user.id);

    Ok(Json(serde_json::json!({})))
}

// Helper functions

async fn validate_password_or_otp(
    user: &UserDB,
    data: &PasswordOrOtpData,
) -> Result<(), AppError> {
    if let Some(ref password_hash) = data.master_password_hash {
        let verification = user.verify_master_password(password_hash).await?;
        if verification.is_valid() {
            return Ok(());
        }
    }

    // OTP validation would be handled here if we had protected actions support
    // For now, master password is required

    Err(AppError::Auth(AuthError::InvalidPassword))
}

async fn generate_recovery_code_for_user(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    // Check if recovery code already exists
    let user = UserDB::fetch_by_id_with(
        db,
        user_id,
        "Failed to fetch user in generate recovery code",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    if user.totp_recover.is_none() {
        let recovery_code = generate_recovery_code()?;
        UserDB::set_recovery_code(db, user_id, &recovery_code).await?;
    }

    Ok(())
}

/// Clear recovery code when no real 2FA providers remain.
async fn clear_recovery_if_no_twofactor(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<(), AppError> {
    let remaining = TwoFactorDB::list_user_twofactors(db, user_id).await?;
    let has_real_twofactor = remaining
        .iter()
        .any(|tf| tf.atype != TwoFactorType::Remember as i32);

    if !has_real_twofactor {
        UserDB::clear_recovery_code(db, user_id).await?;
    }

    Ok(())
}
