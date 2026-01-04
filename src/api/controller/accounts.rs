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
use worker::{
    D1PreparedStatement,
    query,
};

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
        DatabaseError,
    },
    infra::cryptor::{
        generate_salt,
        hash_password_for_storage,
    },
    models::{
        cipher::CipherData,
        sync::Profile,
        user::{
            AvatarData,
            ChangeKdfRequest,
            ChangePasswordRequest,
            PasswordOrOtpData,
            PreloginResponse,
            ProfileData,
            RegisterRequest,
            RotateKeyRequest,
            User,
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

#[worker::send]
pub async fn revision_date(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<i64>, AppError> {
    let db = state.get_db();

    // get the user's updated_at timestamp
    let updated_at: Option<String> = db
        .prepare("SELECT updated_at FROM users WHERE id = ?1")
        .bind(&[claims.sub.into()])?
        .first(Some("updated_at"))
        .await
        .map_err(|e| {
            log::error!("Database error fetching revision date: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch revision date".to_string(),
            ))
        })?;

    // convert the timestamp to a millisecond-level Unix timestamp
    let revision_date = updated_at
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(&ts).ok())
        .map_or_else(
            || chrono::Utc::now().timestamp_millis(),
            |dt| dt.timestamp_millis(),
        );

    Ok(Json(revision_date))
}

#[worker::send]
pub async fn get_profile(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Profile>, AppError> {
    let db = state.get_db();
    let user_id = claims.sub;

    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::Auth(AuthError::AccountLocked))?;

    let profile = Profile::from_user(user);

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

    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|e| {
            log::error!("Database error fetching user for profile update: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch user for profile update".to_string(),
            ))
        })?
        .ok_or_else(|| AppError::Auth(AuthError::AccountLocked))?;

    let mut user: User = serde_json::from_value(user_value).map_err(|e| {
        log::error!("Error deserializing user for profile update: {e}");
        AppError::Internal
    })?;
    let now = Utc::now().to_rfc3339();

    user.name = Some(payload.name);
    user.updated_at.clone_from(&now);

    query!(
        &db,
        "UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3",
        user.name,
        now,
        user_id
    )
    .map_err(|e| {
        log::error!("Database error updating user profile: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update user profile".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Database error running update user profile query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to run update user profile query".to_string(),
        ))
    })?;

    let profile = Profile::from_user(user);

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

    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|e| {
            log::error!("Database error fetching user for avatar update: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch user for avatar update".to_string(),
            ))
        })?
        .ok_or_else(|| AppError::Auth(AuthError::UserNotFound))?;

    let mut user: User = serde_json::from_value(user_value).map_err(|e| {
        log::error!("Error deserializing user for avatar update: {e}");
        AppError::Internal
    })?;
    let now = Utc::now().to_rfc3339();

    user.avatar_color = payload.avatar_color;
    user.updated_at.clone_from(&now);

    query!(
        &db,
        "UPDATE users SET avatar_color = ?1, updated_at = ?2 WHERE id = ?3",
        user.avatar_color,
        now,
        user_id
    )
    .map_err(|e| {
        log::error!("Database error updating user avatar: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update user avatar".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Database error running update user avatar query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to run update user avatar query".to_string(),
        ))
    })?;

    let profile = Profile::from_user(user);

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
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|e| {
            log::error!(
                "Database error fetching user for account deletion: {e}"
            );
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch user for account deletion".to_string(),
            ))
        })?
        .ok_or_else(|| AppError::NotFound {
            resource: "User not found".to_string(),
        })?;
    let user: User = serde_json::from_value(user).map_err(|e| {
        log::error!("Error deserializing user for account deletion: {e}");
        AppError::Internal
    })?;

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
    query!(&db, "DELETE FROM ciphers WHERE user_id = ?1", user_id)
        .map_err(|e| {
            log::error!("Database error deleting user ciphers: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to delete user ciphers".to_string(),
            ))
        })?
        .run()
        .await?;

    // Delete all user's folders
    query!(&db, "DELETE FROM folders WHERE user_id = ?1", user_id)
        .map_err(|e| {
            log::error!("Database error deleting user folders: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to delete user folders".to_string(),
            ))
        })?
        .run()
        .await?;

    // Delete the user
    query!(&db, "DELETE FROM users WHERE id = ?1", user_id)
        .map_err(|e| {
            log::error!("Database error deleting user record: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to delete user".to_string(),
            ))
        })?
        .run()
        .await?;

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
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|e| {
            log::error!(
                "Database error fetching user for password change: {e}"
            );
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch user for password change".to_string(),
            ))
        })?
        .ok_or_else(|| AppError::NotFound {
            resource: "User not found".to_string(),
        })?;
    let user: User = serde_json::from_value(user).map_err(|e| {
        log::error!("Error deserializing user for password change: {e}");
        AppError::Internal
    })?;

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
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, key \
         = ?3, master_password_hint = ?4, security_stamp = ?5, updated_at = \
         ?6 WHERE id = ?7",
        new_hashed_password,
        new_salt,
        payload.key,
        payload.master_password_hint,
        new_security_stamp,
        now,
        user_id
    )
    .map_err(|e| {
        log::error!("Database error updating master password: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update master password".to_string(),
        ))
    })?
    .run()
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
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|e| {
            log::error!("Database error fetching user for key rotation: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch user for key rotation".to_string(),
            ))
        })?
        .ok_or_else(|| AppError::NotFound {
            resource: "User not found".to_string(),
        })?;
    let user: User = serde_json::from_value(user).map_err(|e| {
        log::error!("Error deserializing user for key rotation: {e}");
        AppError::Internal
    })?;

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

    // Batch: 2 COUNT queries + 2 EXCEPT queries
    let validation_results = db
        .batch(vec![
            // Count ciphers in DB
            db.prepare(
                "SELECT COUNT(*) AS cnt FROM ciphers WHERE user_id = ?1 AND \
                 organization_id IS NULL",
            )
            .bind(&[user_id.clone().into()])?,
            // Count folders in DB
            db.prepare(
                "SELECT COUNT(*) AS cnt FROM folders WHERE user_id = ?1",
            )
            .bind(&[user_id.clone().into()])?,
            // DB cipher IDs EXCEPT request cipher IDs (finds missing)
            db.prepare(
                "SELECT id FROM ciphers WHERE user_id = ?1 AND \
                 organization_id IS NULL
                 EXCEPT
                 SELECT value FROM json_each(?2) LIMIT 1",
            )
            .bind(&[user_id.clone().into(), cipher_ids_json.into()])?,
            // DB folder IDs EXCEPT request folder IDs (finds missing)
            db.prepare(
                "SELECT id FROM folders WHERE user_id = ?1
                 EXCEPT
                 SELECT value FROM json_each(?2) LIMIT 1",
            )
            .bind(&[user_id.clone().into(), folder_ids_json.into()])?,
        ])
        .await?;

    // Check counts match
    let db_cipher_count = validation_results[0]
        .results::<Value>()?
        .first()
        .and_then(|v| v.get("cnt")?.as_i64())
        .unwrap_or(0) as usize;
    let db_folder_count = validation_results[1]
        .results::<Value>()?
        .first()
        .and_then(|v| v.get("cnt")?.as_i64())
        .unwrap_or(0) as usize;

    if db_cipher_count != request_cipher_ids.len() ||
        db_folder_count != request_folder_ids.len()
    {
        log::error!(
            "Cipher or folder count mismatch in rotation request: {:?} != \
             {:?} or {:?} != {:?}",
            db_cipher_count,
            request_cipher_ids.len(),
            db_folder_count,
            request_folder_ids.len()
        );
        return Err(AppError::Params(
            "All existing ciphers and folders must be included in the rotation"
                .to_string(),
        ));
    }

    // Check EXCEPT results (if count matches but IDs differ)
    let has_missing_ciphers =
        !validation_results[2].results::<Value>()?.is_empty();
    let has_missing_folders =
        !validation_results[3].results::<Value>()?.is_empty();

    if has_missing_ciphers || has_missing_folders {
        log::error!(
            "Missing ciphers or folders in rotation request: \
             {has_missing_ciphers:?} or {has_missing_folders:?}"
        );
        return Err(AppError::Params(
            "All existing ciphers and folders must be included in the rotation"
                .to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();

    // Update all folders with new encrypted names (batch operation)
    // Skip null folder IDs (Bitwarden client bug: https://github.com/bitwarden/clients/issues/8453)
    let mut folder_statements: Vec<D1PreparedStatement> =
        Vec::with_capacity(payload.account_data.folders.len());
    for folder in &payload.account_data.folders {
        // Skip null folder id entries
        let Some(folder_id) = &folder.id else {
            continue;
        };
        let stmt = query!(
            &db,
            "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 AND \
             user_id = ?4",
            folder.name,
            now,
            folder_id,
            user_id
        )
        .map_err(|e| {
            log::error!("Database error updating folder during rotation: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to update folder during rotation".to_string(),
            ))
        })?;
        folder_statements.push(stmt);
    }

    // batch_size == 0 means "no chunking"; use a single batch
    if batch_size == 0 {
        db.batch(folder_statements).await?;
    } else {
        for chunk in folder_statements.chunks(batch_size) {
            db.batch(chunk.to_vec()).await?;
        }
    }

    // Update all ciphers with new encrypted data (batch operation)
    // Only update personal ciphers (organization_id is None)
    let mut cipher_statements: Vec<D1PreparedStatement> =
        Vec::with_capacity(personal_ciphers.len());
    for cipher in personal_ciphers {
        // id is guaranteed to exist (validated above)
        let cipher_id = cipher.id.as_ref().expect("Cipher id missing");

        let cipher_data = CipherData {
            name:        cipher.name.clone(),
            notes:       cipher.notes.clone(),
            type_fields: cipher.type_fields.clone(),
        };

        let data = serde_json::to_string(&cipher_data).map_err(|e| {
            log::error!("Error serializing cipher data for rotation: {e}");
            AppError::Internal
        })?;

        let stmt = query!(
            &db,
            "UPDATE ciphers SET data = ?1, folder_id = ?2, favorite = ?3, \
             updated_at = ?4 WHERE id = ?5 AND user_id = ?6",
            data,
            cipher.folder_id,
            cipher.favorite.unwrap_or(false),
            now,
            cipher_id,
            user_id
        )
        .map_err(|e| {
            log::error!("Database error updating cipher during rotation: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to update cipher during rotation".to_string(),
            ))
        })?;
        cipher_statements.push(stmt);
    }

    // batch_size == 0 means "no chunking"; use a single batch
    if batch_size == 0 {
        db.batch(cipher_statements).await?;
    } else {
        for chunk in cipher_statements.chunks(batch_size) {
            db.batch(chunk.to_vec()).await?;
        }
    }

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

    // Update user record with new keys and password
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, key \
         = ?3, private_key = ?4, kdf_type = ?5, kdf_iterations = ?6, \
         kdf_memory = ?7, kdf_parallelism = ?8, security_stamp = ?9, \
         updated_at = ?10 WHERE id = ?11",
        new_hashed_password,
        new_salt,
        unlock_data.master_key_encrypted_user_key,
        payload.account_keys.user_key_encrypted_account_private_key,
        unlock_data.kdf_type,
        unlock_data.kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        new_security_stamp,
        now,
        user_id
    )
    .map_err(|e| {
        log::error!(
            "Database error updating user account keys during rotation: {e}"
        );
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update user account keys".to_string(),
        ))
    })?
    .run()
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
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|e| {
            log::error!("Database error fetching user for KDF change: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch user for KDF change".to_string(),
            ))
        })?
        .ok_or_else(|| AppError::NotFound {
            resource: "User not found".to_string(),
        })?;
    let user: User = serde_json::from_value(user).map_err(|e| {
        log::error!("Error deserializing user for KDF change: {e}");
        AppError::Internal
    })?;

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
    query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, key \
         = ?3, kdf_type = ?4, kdf_iterations = ?5, kdf_memory = ?6, \
         kdf_parallelism = ?7, security_stamp = ?8, updated_at = ?9 WHERE id \
         = ?10",
        new_hashed_password,
        new_salt,
        new_key,
        kdf_type,
        kdf_iterations,
        final_kdf_memory,
        final_kdf_parallelism,
        new_security_stamp,
        now,
        user_id
    )
    .map_err(|e| {
        log::error!("Database error updating KDF settings: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update KDF settings".to_string(),
        ))
    })?
    .run()
    .await?;

    Ok(Json(json!({})))
}
