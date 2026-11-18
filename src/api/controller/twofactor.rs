use axum::{
    Json,
    extract::State,
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use sha2::{
    Digest as _,
    Sha256,
};

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            twofactor,
        },
    },
    errors::{
        AppError,
        AuthError,
    },
    infra::{
        admin_notify::{
            self,
            Event,
        },
        crypto::{
            base32_decode,
            ct_eq,
            generate_recovery_code,
            generate_totp_secret,
            validate_totp,
        },
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
    claims: Claims,
) -> Result<Json<Value>, AppError> {
    let user_id = claims.sub.clone();
    let db = state.get_db();
    let twofactors = TwoFactorDB::list_user_twofactors(&db, &user_id).await?;
    let twofactors: Vec<Value> = twofactors
        .iter()
        .filter(|factor| {
            factor.enabled && factor.atype != TwoFactorType::Remember as i32
        })
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
    claims: Claims,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let user_id = claims.sub.clone();
    let db = state.get_db();

    validate_password_or_otp(&state, &claims, &data).await?;

    let existing = TwoFactorDB::get_for_user_by_type(
        &db,
        &user_id,
        TwoFactorType::Authenticator as i32,
    )
    .await?;

    let (enabled, key) = match existing {
        Some(tf) => (tf.enabled, tf.data),
        None => (false, generate_totp_secret()?),
    };

    let now = crate::infra::time::now_seconds();
    let proof = AuthenticatorProof {
        sub:           claims.sub.clone(),
        sstamp:        claims.sstamp.clone(),
        session_token: claims.session_token.clone(),
        purpose:       "authenticator-factor".into(),
        state_hash:    authenticator_state(&key, enabled),
        exp:           now + 300,
        nbf:           now,
        iat:           now,
    };
    let token =
        crate::infra::jwt::encode(&proof, state.config.jwt_secret.as_bytes())?;
    Ok(Json(serde_json::json!({
        "enabled": enabled, "key": key, "object": "twoFactorAuthenticator",
        "authenticator": { "enabled": enabled, "key": key },
        "userVerificationToken": token,
    })))
}

/// POST /api/two-factor/authenticator - Activate TOTP
#[worker::send]
pub async fn activate_authenticator(
    State(state): State<AppState>,
    claims: Claims,
    Json(data): Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let key = data.key.trim().to_uppercase();
    if base32_decode(&key)?.len() != 20 {
        return Err(AppError::bad_request("Invalid key length"));
    }
    let existing =
        TwoFactorDB::get_for_user_by_type(&db, &claims.sub, 0).await?;
    let proof = PasswordOrOtpData {
        master_password_hash:    data.master_password_hash,
        otp:                     data.otp,
        user_verification_token: data.user_verification_token,
    };
    verify_authenticator_action(&state, &claims, &proof, &key, false).await?;
    if proof.user_verification_token.is_some() &&
        existing.as_ref().is_some_and(|v| v.enabled)
    {
        return Err(AppError::bad_request("Authenticator is already enabled"));
    }
    let previous_step = existing
        .as_ref()
        .filter(|v| ct_eq(&v.data, &key))
        .map_or(0, |v| v.last_used);
    let step = validate_totp(
        &data.token,
        &key,
        previous_step,
        !state.config.authenticator_disable_time_drift,
    )
    .await?;
    let mut value = TwoFactorDB::new(
        claims.sub.clone(),
        TwoFactorType::Authenticator,
        key.clone(),
    );
    value.last_used = step;
    let session = claims.session_snapshot()?;
    TwoFactorDB::replace_authenticator(
        &db,
        &session,
        existing.as_ref(),
        &value,
    )
    .await?;
    generate_recovery_code_for_user(&db, &claims.sub).await?;
    admin_notify::emit(&state.env, Event::TwoFactorEnable, &claims.sub).await;
    Ok(Json(serde_json::json!({
        "enabled": true, "key": key, "object": "twoFactorAuthenticator",
        "authenticator": { "enabled": true, "key": key },
    })))
}

/// PUT /api/two-factor/authenticator - Same as POST
#[worker::send]
pub async fn activate_authenticator_put(
    state: State<AppState>,
    auth_user: Claims,
    json: Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    activate_authenticator(state, auth_user, json).await
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[worker::send]
pub async fn disable_twofactor(
    State(state): State<AppState>,
    claims: Claims,
    Json(data): Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    let user_id = claims.sub.clone();
    let db = state.get_db();

    let proof = PasswordOrOtpData {
        master_password_hash:    data.master_password_hash,
        otp:                     data.otp,
        user_verification_token: data.user_verification_token,
    };
    let provider =
        TwoFactorDB::get_for_user_by_type(&db, &user_id, data.r#type).await?;
    let was_enabled = provider.as_ref().is_some_and(|factor| factor.enabled);
    // Only TOTP uses the existing snapshot write. Other providers retain
    // their original deletion and Remember-token cleanup paths.
    let existing =
        provider.filter(|_| data.r#type == TwoFactorType::Authenticator as i32);
    if let Some(factor) = existing.as_ref() {
        verify_authenticator_action(
            &state,
            &claims,
            &proof,
            &factor.data,
            factor.enabled,
        )
        .await?;
    } else if data.r#type == TwoFactorType::Email as i32 {
        twofactor::verify_email_factor_action(&state, &claims, &proof).await?;
    } else {
        validate_password_or_otp(&state, &claims, &proof).await?;
    }

    crate::models::email::EmailDB::invalidate_user(&db, &user_id).await?;
    let type_ = data.r#type;
    if type_ == TwoFactorType::Webauthn as i32 {
        crate::models::webauthn::CredentialDB::purge_2fa(&db, &user_id).await?;
    }

    // Delete the specified 2FA type
    if let Some(factor) = existing.as_ref() {
        let session = claims.session_snapshot()?;
        TwoFactorDB::delete_authenticator_snapshot(&db, &session, factor)
            .await?;
    } else {
        TwoFactorDB::delete_types_for_user(&db, &user_id, &[
            type_,
            TwoFactorType::Remember as i32,
        ])
        .await?;
    }

    log::info!("User {} disabled 2FA type {}", user_id, type_);

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    if was_enabled {
        admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub)
            .await;
    }
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
    claims: Claims,
    Json(data): Json<DisableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    if data.r#type != TwoFactorType::Authenticator as i32 {
        return Err(AppError::bad_request("Invalid two factor type"));
    }
    let existing = TwoFactorDB::get_for_user_by_type(&db, &claims.sub, 0)
        .await?
        .ok_or_else(|| AppError::bad_request("TOTP not configured"))?;
    let key = data.key.trim().to_uppercase();
    let proof = PasswordOrOtpData {
        master_password_hash:    data.master_password_hash,
        otp:                     data.otp,
        user_verification_token: data.user_verification_token,
    };
    verify_authenticator_action(
        &state,
        &claims,
        &proof,
        &key,
        existing.enabled,
    )
    .await?;
    if !ct_eq(&existing.data, &key) {
        return Err(AuthError::InvalidTotp.into());
    }
    let session = claims.session_snapshot()?;
    TwoFactorDB::delete_authenticator_snapshot(&db, &session, &existing)
        .await?;
    clear_recovery_if_no_twofactor(&db, &claims.sub).await?;
    admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub).await;
    Ok(Json(
        serde_json::json!({ "enabled": false, "type": 0, "object": "twoFactorProvider" }),
    ))
}

/// PUT /api/two-factor/disable - Same as POST
#[worker::send]
pub async fn disable_twofactor_put(
    state: State<AppState>,
    auth_user: Claims,
    json: Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    disable_twofactor(state, auth_user, json).await
}

/// POST /api/two-factor/get-recover - Get recovery code
#[worker::send]
pub async fn get_recover(
    State(state): State<AppState>,
    claims: Claims,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let user_id = claims.sub.clone();
    let db = state.get_db();

    // Verify master password
    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user in get_recover",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    validate_password_or_otp(&state, &claims, &data).await?;

    admin_notify::emit(
        &state.env,
        Event::TwoFactorRecoveryCodeView,
        &claims.sub,
    )
    .await;
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
    crate::models::email::EmailDB::invalidate_user(&db, &user.id).await?;
    crate::models::webauthn::CredentialDB::purge_2fa(&db, &user.id).await?;
    TwoFactorDB::delete_for_user(&db, &user.id).await?;

    // Clear recovery code
    UserDB::clear_recovery_code(&db, &user.id).await?;

    log::info!("User {} recovered 2FA using recovery code", user.id);

    admin_notify::emit(&state.env, Event::TwoFactorRecover, &user.id).await;
    Ok(Json(serde_json::json!({})))
}

// Helper functions

async fn validate_password_or_otp(
    state: &AppState,
    claims: &Claims,
    data: &PasswordOrOtpData,
) -> Result<(), AppError> {
    crate::api::service::email::verify_password_or_otp(state, claims, data)
        .await
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
        .any(|tf| tf.enabled && matches!(tf.atype, 0 | 1 | 7));

    if !has_real_twofactor {
        UserDB::clear_recovery_code(db, user_id).await?;
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct AuthenticatorProof {
    sub:           String,
    sstamp:        String,
    session_token: String,
    purpose:       String,
    state_hash:    String,
    exp:           i64,
    nbf:           i64,
    iat:           i64,
}

fn authenticator_state(key: &str, enabled: bool) -> String {
    hex::encode(Sha256::digest(format!(
        "{}:{}",
        u8::from(enabled),
        key.trim().to_uppercase()
    )))
}

async fn verify_authenticator_action(
    state: &AppState,
    claims: &Claims,
    data: &PasswordOrOtpData,
    key: &str,
    enabled: bool,
) -> Result<(), AppError> {
    let Some(token) = data.user_verification_token.as_deref() else {
        return validate_password_or_otp(state, claims, data).await;
    };
    if data.master_password_hash.is_some() || data.otp.is_some() {
        return Err(AppError::bad_request(
            "Provide exactly one verification method",
        ));
    }
    let proof = crate::infra::jwt::decode::<AuthenticatorProof>(
        token,
        state.config.jwt_secret.as_bytes(),
        &crate::infra::jwt::ValidationOptions {
            leeway: 0,
            ..Default::default()
        },
    )?
    .claims;
    if proof.sub != claims.sub ||
        proof.sstamp != claims.sstamp ||
        proof.session_token != claims.session_token ||
        proof.purpose != "authenticator-factor" ||
        !ct_eq(&proof.state_hash, &authenticator_state(key, enabled))
    {
        return Err(AuthError::InvalidCredentials(
            "Invalid authenticator proof".into(),
        )
        .into());
    }
    Ok(())
}

#[worker::send]
pub async fn device_verification_settings(_claims: Claims) -> Json<Value> {
    Json(
        serde_json::json!({"isDeviceVerificationSectionEnabled": false,
        "unknownDeviceVerificationEnabled": false, "object": "deviceVerificationSettings"}),
    )
}

#[cfg(test)]
mod proof_tests {
    use super::authenticator_state;

    #[test]
    fn authenticator_proof_binds_the_key_and_enabled_state() {
        assert_eq!(
            authenticator_state(" abc ", false),
            authenticator_state("ABC", false)
        );
        assert_ne!(
            authenticator_state("ABC", true),
            authenticator_state("ABC", false)
        );
        assert_ne!(
            authenticator_state("ABC", false),
            authenticator_state("ABD", false)
        );
    }
}
