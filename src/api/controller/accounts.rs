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
    api::{
        AppState,
        service::{
            claims::Claims,
            kdf::{
                DEFAULT_PBKDF2_ITERATIONS,
                KDF_TYPE_ARGON2ID,
                KDF_TYPE_PBKDF2,
                ensure_supported_kdf,
                validate_rotation_metadata,
            },
            rate,
            user,
        },
    },
    errors::{
        AppError,
        AuthError,
    },
    infra::cryptor::{
        generate_salt,
        hash_password_for_storage,
    },
    models::{
        cipher::CipherDB,
        folder::FolderDB,
        sync::Profile,
        twofactor::TwoFactorDB,
        user::{
            AvatarData,
            ChangeKdfRequest,
            ChangePasswordRequest,
            PasswordOrOtpData,
            PreloginResponse,
            ProfileData,
            RegisterRequest,
            RotateKeyRequest,
            UserDB,
        },
    },
};

#[worker::send]
pub async fn prelogin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"].as_str().ok_or_else(|| {
        AppError::Auth(AuthError::InvalidCredentials(
            "Missing email".to_string(),
        ))
    })?;

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
        return Err(AppError::Auth(AuthError::InvalidCredentials(
            "Email is not allowed".to_string(),
        )));
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

    let user = UserDB {
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
        equivalent_domains: "[]".to_string(),
        excluded_globals: "[]".to_string(),
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

#[worker::send]
pub async fn revision_date(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<i64>, AppError> {
    let db = state.get_db();
    let revision_date = UserDB::revision_date_ms(&db, &claims.sub).await?;
    Ok(Json(revision_date))
}

/// GET /api/auth-requests/pending
///
/// Stub: always returns an empty list.
#[worker::send]
pub async fn get_auth_requests_pending(
    _claims: Claims,
) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "data": [],
        "continuationToken": null,
        "object": "list"
    })))
}

#[worker::send]
pub async fn get_profile(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Profile>, AppError> {
    let db = state.get_db();
    let user_id = claims.sub;

    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user for profile",
        || AppError::Auth(AuthError::AccountLocked),
    )
    .await?;

    let two_factor_enabled =
        TwoFactorDB::two_factor_enabled(&db, &user_id).await?;
    let profile = Profile::from_user(user, two_factor_enabled);

    Ok(Json(profile))
}

#[worker::send]
pub async fn post_profile(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ProfileData>,
) -> Result<Json<Profile>, AppError> {
    if payload.name.len() > 50 {
        return Err(AppError::Params(
            "The field Name must be a string with a maximum length of 50."
                .to_string(),
        ));
    }

    let db = state.get_db();
    let user_id = &claims.sub;

    let mut user = UserDB::fetch_by_id_with(
        &db,
        user_id,
        "Failed to fetch user for profile update",
        || AppError::Auth(AuthError::AccountLocked),
    )
    .await?;
    let now = Utc::now().to_rfc3339();

    user.name = Some(payload.name);
    user.updated_at.clone_from(&now);

    UserDB::update_profile_name(&db, user_id, &user.name, &now).await?;

    let two_factor_enabled =
        TwoFactorDB::two_factor_enabled(&db, user_id).await?;
    let profile = Profile::from_user(user, two_factor_enabled);

    Ok(Json(profile))
}

#[worker::send]
pub async fn put_profile(
    claims: Claims,
    state: State<AppState>,
    json: Json<ProfileData>,
) -> Result<Json<Profile>, AppError> {
    post_profile(claims, state, json).await
}

#[worker::send]
pub async fn put_avatar(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<AvatarData>,
) -> Result<Json<Profile>, AppError> {
    if let Some(color) = &payload.avatar_color &&
        color.len() != 7
    {
        return Err(AppError::Params(
            "The field AvatarColor must be a HTML/Hex color code with a \
             length of 7 characters"
                .to_string(),
        ));
    }

    let db = state.get_db();
    let user_id = &claims.sub;

    let mut user = UserDB::fetch_by_id_with(
        &db,
        user_id,
        "Failed to fetch user for avatar update",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    let now = Utc::now().to_rfc3339();

    user.avatar_color = payload.avatar_color;
    user.updated_at.clone_from(&now);

    UserDB::update_avatar_color(&db, user_id, &user.avatar_color, &now).await?;

    let two_factor_enabled =
        TwoFactorDB::two_factor_enabled(&db, user_id).await?;
    let profile = Profile::from_user(user, two_factor_enabled);

    Ok(Json(profile))
}

#[worker::send]
pub async fn delete_account(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let user_id = &claims.sub;

    // Get the user from the database
    let user = UserDB::fetch_by_id_with(
        &db,
        user_id,
        "Failed to fetch user for account deletion",
        || AppError::NotFound {
            resource: "User not found".to_string(),
        },
    )
    .await?;

    // Verify the master password hash
    let provided_hash = payload.master_password_hash.ok_or_else(|| {
        AppError::Params("Missing master password hash".to_string())
    })?;

    let verification = user.verify_master_password(&provided_hash).await?;

    if !verification.is_valid() {
        return Err(AppError::Auth(AuthError::InvalidPassword));
    }

    // if attachments::attachments_enabled(env.as_ref()) {
    //     let bucket = attachments::require_bucket(env.as_ref())?;
    //     let keys = attachments::list_attachment_keys_for_user(&db,
    // user_id).await?;     attachments::delete_r2_objects(&bucket,
    // &keys).await?; }

    // Delete all user's ciphers
    CipherDB::purge_user_ciphers(&db, user_id).await?;

    // Delete all user's folders
    FolderDB::purge_user_folders(&db, user_id).await?;

    // Delete the user
    UserDB::delete_user(&db, user_id).await?;

    Ok(Json(json!({})))
}

/// POST /accounts/password - Change master password
#[worker::send]
pub async fn post_password(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let user_id = &claims.sub;

    // Get the user from the database
    let user = UserDB::fetch_by_id_with(
        &db,
        user_id,
        "Failed to fetch user for password change",
        || AppError::NotFound {
            resource: "User not found".to_string(),
        },
    )
    .await?;

    // Verify the current master password
    let verification = user
        .verify_master_password(&payload.master_password_hash)
        .await?;

    if !verification.is_valid() {
        return Err(AppError::Auth(AuthError::InvalidPassword));
    }

    // Generate new salt and hash the new password
    let new_salt = generate_salt()?;
    let new_hashed_password =
        hash_password_for_storage(&payload.new_master_password_hash, &new_salt)
            .await?;

    // Generate new security stamp and update timestamp
    let new_security_stamp = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Update user record
    UserDB::update_master_password(
        &db,
        user_id,
        &new_hashed_password,
        &new_salt,
        &payload.key,
        &payload.master_password_hint,
        &new_security_stamp,
        &now,
    )
    .await?;

    Ok(Json(json!({})))
}

/// POST /accounts/key-management/rotate-user-account-keys - Rotate user
/// encryption keys
#[worker::send]
pub async fn post_rotatekey(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<RotateKeyRequest>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let user_id = &claims.sub;
    let batch_size = state.config.import_batch_size as usize;

    // Get the user from the database
    let user = UserDB::fetch_by_id_with(
        &db,
        user_id,
        "Failed to fetch user for key rotation",
        || AppError::NotFound {
            resource: "User not found".to_string(),
        },
    )
    .await?;

    // Verify the current master password
    let verification = user
        .verify_master_password(&payload.old_master_key_authentication_hash)
        .await?;

    if !verification.is_valid() {
        return Err(AppError::Auth(AuthError::InvalidPassword));
    }

    let unlock_data = &payload.account_unlock_data.master_password_unlock_data;

    validate_rotation_metadata(
        &user,
        unlock_data,
        &payload.account_keys.account_public_key,
    )?;

    // Validate KDF parameters
    ensure_supported_kdf(
        unlock_data.kdf_type,
        unlock_data.kdf_iterations,
        unlock_data.kdf_memory,
        unlock_data.kdf_parallelism,
    )?;

    // Validate data integrity using D1 batch operations
    // Step 1: Ensure all personal ciphers have id (required for key rotation)
    // Step 2: Count check - ensure request has exactly the same number of items
    // as DB Step 3: EXCEPT check - ensure request has exactly the same IDs
    // as DB
    let personal_ciphers: Vec<_> = payload
        .account_data
        .ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .cloned()
        .collect();

    let request_cipher_ids: Vec<String> = personal_ciphers
        .iter()
        .filter_map(|c| c.id.clone())
        .collect();

    // All personal ciphers must have an id for key rotation
    if personal_ciphers.len() != request_cipher_ids.len() {
        log::error!(
            "All ciphers must have an id for key rotation: {:?} != {:?}",
            personal_ciphers.len(),
            request_cipher_ids.len()
        );
        return Err(AppError::Params(
            "All ciphers must have an id for key rotation".to_string(),
        ));
    }

    // Filter out null folder IDs (Bitwarden client bug: https://github.com/bitwarden/clients/issues/8453)
    let request_folder_ids: Vec<String> = payload
        .account_data
        .folders
        .iter()
        .filter_map(|f| f.id.clone())
        .collect();

    let cipher_ids_json =
        serde_json::to_string(&request_cipher_ids).map_err(|e| {
            log::error!("Error serializing cipher IDs for rotation: {e}");
            AppError::Internal
        })?;
    let folder_ids_json =
        serde_json::to_string(&request_folder_ids).map_err(|e| {
            log::error!("Error serializing folder IDs for rotation: {e}");
            AppError::Internal
        })?;

    UserDB::validate_rotation_state(
        &db,
        user_id,
        &cipher_ids_json,
        &folder_ids_json,
    )
    .await?;

    let now = Utc::now().to_rfc3339();

    UserDB::rotate_folders(
        &db,
        user_id,
        &payload.account_data.folders,
        &now,
        batch_size,
    )
    .await?;

    UserDB::rotate_personal_ciphers(
        &db,
        user_id,
        &personal_ciphers,
        &now,
        batch_size,
    )
    .await?;

    // Generate new salt and hash the new password
    let new_salt = generate_salt()?;
    let new_hashed_password = hash_password_for_storage(
        &unlock_data.master_key_authentication_hash,
        &new_salt,
    )
    .await?;

    // Generate new security stamp
    let new_security_stamp = Uuid::new_v4().to_string();

    // Only store kdf_memory and kdf_parallelism for Argon2id, clear for PBKDF2
    let (kdf_memory, kdf_parallelism) =
        if unlock_data.kdf_type == KDF_TYPE_ARGON2ID {
            (unlock_data.kdf_memory, unlock_data.kdf_parallelism)
        } else {
            (None, None)
        };

    UserDB::update_account_keys_after_rotation(
        &db,
        user_id,
        &new_hashed_password,
        &new_salt,
        &unlock_data.master_key_encrypted_user_key,
        &payload.account_keys.user_key_encrypted_account_private_key,
        unlock_data.kdf_type,
        unlock_data.kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        &new_security_stamp,
        &now,
    )
    .await?;

    Ok(Json(json!({})))
}

/// POST /accounts/kdf - Change KDF settings (PBKDF2 <-> Argon2id)
///
/// API Format History:
/// - Bitwarden switched to complex format in v2025.10.0
/// - Vaultwarden followed in PR #6458, WITHOUT backward compatibility
/// - We implement backward compatibility to support both formats
///
/// Supports two request formats:
///
/// 1. Simple/Legacy format (Bitwarden < v2025.10.0, e.g. web vault 2025.07):
/// { "kdf": 0, "kdfIterations": 650000, "key": "...", "masterPasswordHash":
/// "...", "newMasterPasswordHash": "..." }
///
/// 2. Complex format (Bitwarden >= v2025.10.0, e.g. official client 2025.11.x):
/// { "authenticationData": {...}, "unlockData": {...}, "key": "...",
/// "masterPasswordHash": "...", "newMasterPasswordHash": "..." }
#[worker::send]
pub async fn post_kdf(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ChangeKdfRequest>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let user_id = &claims.sub;

    // Get the user from the database
    let user = UserDB::fetch_by_id_with(
        &db,
        user_id,
        "Failed to fetch user for KDF change",
        || AppError::NotFound {
            resource: "User not found".to_string(),
        },
    )
    .await?;

    // Verify the current master password
    let verification = user
        .verify_master_password(&payload.master_password_hash)
        .await?;

    if !verification.is_valid() {
        return Err(AppError::Auth(AuthError::InvalidPassword));
    }

    // Additional validation for complex format
    if let (Some(auth_data), Some(unlock_data)) =
        (&payload.authentication_data, &payload.unlock_data)
    {
        // KDF settings must match between authentication and unlock
        if auth_data.kdf != unlock_data.kdf {
            return Err(AppError::Params(
                "KDF settings must be equal for authentication and unlock"
                    .to_string(),
            ));
        }
        // Salt (email) must match
        if user.email != auth_data.salt || user.email != unlock_data.salt {
            return Err(AppError::Params(
                "Invalid master password salt".to_string(),
            ));
        }
    }

    // Extract KDF parameters from either format
    let (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) =
        payload.get_kdf_params().ok_or_else(|| {
            AppError::Params("Missing KDF parameters".to_string())
        })?;

    // Validate new KDF parameters
    ensure_supported_kdf(
        kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
    )?;

    // Generate new salt and hash the new password
    let new_salt = generate_salt()?;
    let new_hashed_password =
        hash_password_for_storage(payload.get_new_password_hash(), &new_salt)
            .await?;

    // Generate new security stamp
    let new_security_stamp = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Determine kdf_memory and kdf_parallelism based on KDF type
    let (final_kdf_memory, final_kdf_parallelism) =
        if kdf_type == KDF_TYPE_ARGON2ID {
            (kdf_memory, kdf_parallelism)
        } else {
            // For PBKDF2, clear these fields
            (None, None)
        };

    // Get the new encrypted user key
    let new_key = payload.get_new_key();

    // Update user record with new KDF settings and password
    UserDB::update_kdf_settings(
        &db,
        user_id,
        &new_hashed_password,
        &new_salt,
        new_key,
        kdf_type,
        kdf_iterations,
        final_kdf_memory,
        final_kdf_parallelism,
        &new_security_stamp,
        &now,
    )
    .await?;

    Ok(Json(json!({})))
}
