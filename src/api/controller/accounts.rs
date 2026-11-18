use axum::{
    Json,
    extract::State,
    http::{
        HeaderMap,
        HeaderValue,
        header,
    },
    response::{
        IntoResponse as _,
        Response,
    },
};
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
            setup,
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
            generate_salt,
            hash_password_for_storage,
        },
    },
    models::{
        sync::Profile,
        twofactor::TwoFactorDB,
        user::{
            AvatarData,
            ChangeKdfRequest,
            ChangePasswordRequest,
            KdfParams,
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

    let email = email.trim().to_lowercase();
    let params = UserDB::kdf_params_by_email(&state.get_db(), &email).await?;

    Ok(Json(PreloginResponse {
        kdf:             params.kdf_type.unwrap_or(KDF_TYPE_PBKDF2),
        kdf_iterations:  params
            .kdf_iterations
            .unwrap_or(DEFAULT_PBKDF2_ITERATIONS),
        kdf_memory:      params.kdf_memory,
        kdf_parallelism: params.kdf_parallelism,
        kdf_settings:    KdfParams {
            kdf_type:    params.kdf_type.unwrap_or(KDF_TYPE_PBKDF2),
            iterations:  params
                .kdf_iterations
                .unwrap_or(DEFAULT_PBKDF2_ITERATIONS),
            memory:      params.kdf_memory,
            parallelism: params.kdf_parallelism,
        },
        salt:            email,
    }))
}

#[worker::send]
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Response, AppError> {
    log::info!("Registration request received");

    let ip = rate::client_ip(&headers);
    let rate_limit_key = format!("register:{ip}");
    rate::check_rate_limit(&state, rate_limit_key).await?;

    let owner_email =
        setup::authorize_registration(&state, &headers, &payload.email).await?;
    crate::api::service::email::enforce_registration_verification(
        &state,
        &owner_email,
        payload.email_verification_token.as_deref(),
    )
    .await?;

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

    let now = crate::infra::time::now_rfc3339();

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
        email: owner_email,
        email_verified:
            crate::api::service::email::registration_verification_required(
                &state,
            ),
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
        user_key_id: payload.user_key_id,
        signed_public_key: payload.account_keys.signed_public_key,
        security_state: payload.account_keys.security_state,
        security_version: payload.account_keys.security_version,
        signature_key_pair: payload.account_keys.signature_key_pair,
        v2_upgrade_token: None,
        security_stamp_exceptions: None,
        equivalent_domains: "[]".to_string(),
        excluded_globals: "[]".to_string(),
        totp_recover: None,
        created_at: now.clone(),
        updated_at: now,
    };

    let clear_cookie = HeaderValue::from_str(&setup::clear_cookie(&state)?)
        .map_err(|_| AppError::Internal)?;
    UserDB::insert(&state.get_db(), &user).await?;
    let mut response = Json(json!({})).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_cookie);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
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

#[worker::send]
pub async fn get_tasks(_claims: Claims) -> Json<Value> {
    Json(json!({ "data": [], "object": "list", "continuationToken": null }))
}

#[worker::send]
pub async fn verify_password(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    rate::check_rate_limit(&state, format!("verify-password:{}", claims.sub))
        .await?;
    let hash = payload
        .master_password_hash
        .ok_or_else(|| AppError::bad_request("Missing master password hash"))?;
    let db = state.get_db();
    let user = UserDB::fetch_by_id_with(
        &db,
        &claims.sub,
        "Failed to fetch user for password verification",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    if !user.verify_master_password(&hash).await?.is_valid() {
        return Err(AuthError::InvalidPassword.into());
    }
    Ok(Json(json!({ "Object": "masterPasswordPolicy" })))
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
    let now = crate::infra::time::now_rfc3339();

    user.name = Some(payload.name);
    user.updated_at.clone_from(&now);

    UserDB::update_profile_name(&db, user_id, &user.name, &now).await?;

    let two_factor_enabled =
        TwoFactorDB::two_factor_enabled(&db, user_id).await?;
    let profile = Profile::from_user(user, two_factor_enabled);

    admin_notify::emit(&state.env, Event::AccountSettingsChanged, &claims.sub)
        .await;
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
    let now = crate::infra::time::now_rfc3339();

    user.avatar_color = payload.avatar_color;
    user.updated_at.clone_from(&now);

    UserDB::update_avatar_color(&db, user_id, &user.avatar_color, &now).await?;

    let two_factor_enabled =
        TwoFactorDB::two_factor_enabled(&db, user_id).await?;
    let profile = Profile::from_user(user, two_factor_enabled);

    admin_notify::emit(&state.env, Event::AccountSettingsChanged, &claims.sub)
        .await;
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

    crate::api::service::email::verify_password_or_otp(
        &state, &claims, &payload,
    )
    .await?;

    crate::api::service::notifications::publish_user_update(
        &state.env,
        user_id,
        crate::api::service::notifications::UpdateType::LogOut,
        &crate::infra::time::now_rfc3339(),
        claims.device(),
    )
    .await;
    crate::api::service::push::unregister_user(&state.env, user_id).await;
    UserDB::delete_user(&db, user_id).await?;
    if let Err(error) =
        crate::infra::storage::cleanup::drain(&state.env, &db).await
    {
        log::warn!("Account deleted; object cleanup will retry: {error}");
    }

    admin_notify::emit(&state.env, Event::AccountDeleted, user_id).await;
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

    // Update user record
    crate::api::service::account_keys::change_credentials(
        &state,
        &claims,
        &user,
        &new_hashed_password,
        &new_salt,
        &payload.key,
        user.kdf_type,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism,
        payload.master_password_hint.as_deref(),
    )
    .await?;

    admin_notify::emit(&state.env, Event::PasswordChange, &claims.sub).await;
    Ok(Json(json!({})))
}

/// Password change and account-key rotation use one guarded transaction.
#[worker::send]
pub async fn post_rotatekey(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<RotateKeyRequest>,
) -> Result<Json<Value>, AppError> {
    let user = UserDB::fetch_by_id_with(
        &state.get_db(),
        &claims.sub,
        "Failed to read rotation owner",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    if !user
        .verify_master_password(&payload.old_master_key_authentication_hash)
        .await?
        .is_valid()
    {
        return Err(AuthError::InvalidPassword.into());
    }
    let unlock = &payload.account_unlock_data.master_password_unlock_data;
    validate_rotation_metadata(
        &user,
        unlock,
        &payload.account_keys.account_public_key,
    )?;
    ensure_supported_kdf(
        unlock.kdf_type,
        unlock.kdf_iterations,
        unlock.kdf_memory,
        unlock.kdf_parallelism,
    )?;
    if !payload
        .account_unlock_data
        .emergency_access_unlock_data
        .is_empty() ||
        !payload
            .account_unlock_data
            .organization_account_recovery_unlock_data
            .is_empty() ||
        !payload
            .account_unlock_data
            .device_key_unlock_data
            .is_empty()
    {
        return Err(AppError::bad_request(
            "Unsupported account recovery or trusted-device unlock data",
        ));
    }
    let keys = payload.account_keys.validate()?;
    if keys.is_v2() && unlock.contained_key_id != payload.new_user_key_id {
        return Err(AppError::bad_request(
            "Contained key id must match the new user key id",
        ));
    }
    let salt = generate_salt()?;
    let hash = hash_password_for_storage(
        &unlock.master_key_authentication_hash,
        &salt,
    )
    .await?;
    let memory = if unlock.kdf_type == KDF_TYPE_ARGON2ID {
        unlock.kdf_memory
    } else {
        None
    };
    let parallelism = if unlock.kdf_type == KDF_TYPE_ARGON2ID {
        unlock.kdf_parallelism
    } else {
        None
    };
    let new_key_id = payload.new_user_key_id.clone().or_else(|| {
        if !keys.is_v2() {
            user.user_key_id.clone()
        } else {
            None
        }
    });
    let input = crate::api::service::account_keys::RotationInput {
        keys,
        data: payload.account_data,
        wrapped_user_key: unlock.master_key_encrypted_user_key.clone(),
        old_user_key_id: payload.old_user_key_id.or_else(|| {
            if !user.is_v2() {
                user.user_key_id.clone()
            } else {
                None
            }
        }),
        new_user_key_id: new_key_id,
        upgrade: None,
        passkeys: payload.account_unlock_data.passkey_unlock_data,
        password: Some((
            hash,
            salt,
            unlock.kdf_type,
            unlock.kdf_iterations,
            memory,
            parallelism,
            unlock.master_password_hint.clone(),
        )),
    };
    crate::api::service::account_keys::rotate(&state, &claims, &user, input)
        .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_rotate_user_keys(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let user = UserDB::fetch_by_id_with(
        &state.get_db(),
        &claims.sub,
        "Failed to read rotation owner",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    let method = &payload["unlockMethodData"];
    if method["unlockMethod"] != 1 ||
        method
            .get("keyConnectorKeyWrappedUserKey")
            .is_some_and(|v| !v.is_null())
    {
        return Err(AppError::bad_request(
            "Only master password unlock is supported",
        ));
    }
    let unlock: crate::models::user::UnlockData =
        serde_json::from_value(method["masterPasswordUnlockData"].clone())
            .map_err(|_| {
                AppError::bad_request("MasterPasswordUnlockData is required")
            })?;
    if unlock.salt != user.email ||
        unlock.kdf.kdf_type != user.kdf_type ||
        unlock.kdf.iterations != user.kdf_iterations ||
        unlock.kdf.memory != user.kdf_memory ||
        unlock.kdf.parallelism != user.kdf_parallelism ||
        user.master_password_hash.is_empty()
    {
        return Err(AppError::bad_request(
            "Invalid master password unlock data",
        ));
    }
    let state_keys = &payload["wrappedAccountCryptographicState"];
    let pair = &state_keys["publicKeyEncryptionKeyPair"];
    let keys:crate::models::account_keys::AccountKeysData=serde_json::from_value(json!({"userKeyEncryptedAccountPrivateKey":pair["wrappedPrivateKey"],"accountPublicKey":pair["publicKey"],"publicKeyEncryptionKeyPair":pair,"signatureKeyPair":state_keys["signatureKeyPair"],"securityState":state_keys["securityState"]})).map_err(|_|AppError::bad_request("Invalid V2 account keys"))?;
    let keys = keys.validate()?;
    if !keys.is_v2() {
        return Err(AppError::bad_request("V2 account keys are required"));
    }
    let old = payload["oldUserKeyId"].as_str().map(str::to_string);
    let new = payload["newUserKeyId"].as_str().map(str::to_string);
    if unlock.contained_key_id != new {
        return Err(AppError::bad_request(
            "Contained key id must match the new user key id",
        ));
    }
    let common = &payload["unlockData"];
    for field in [
        "emergencyAccessUnlockData",
        "organizationAccountRecoveryUnlockData",
        "deviceKeyUnlockData",
    ] {
        if common[field]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            return Err(AppError::bad_request("Unsupported unlock method"));
        }
    }
    let data = serde_json::from_value(payload["accountData"].clone())
        .map_err(|_| AppError::bad_request("Invalid account rotation data"))?;
    let input = crate::api::service::account_keys::RotationInput {
        keys,
        data,
        wrapped_user_key: unlock.master_key_wrapped_user_key,
        old_user_key_id: old,
        new_user_key_id: new,
        upgrade: common
            .get("v2UpgradeToken")
            .filter(|v| !v.is_null())
            .cloned(),
        passkeys: common["passkeyUnlockData"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
        password: None,
    };
    crate::api::service::account_keys::rotate(&state, &claims, &user, input)
        .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn get_key_rotation_data(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let keys = crate::models::webauthn::CredentialDB::list(
        &state.get_db(),
        &claims.sub,
        "login",
    )
    .await?;
    let passkeys=keys.into_iter().filter(|key|key.encrypted_user_key.as_ref().is_some_and(|s|!s.is_empty())&&key.encrypted_private_key.as_ref().is_some_and(|s|!s.is_empty())).map(|key|json!({"id":key.slot.to_string(),"encryptedPublicKey":key.encrypted_public_key,"encryptedUserKey":key.encrypted_user_key,"object":"passkeyKeyData"})).collect::<Vec<_>>();
    Ok(Json(
        json!({"organizationPasswordResetKeyData":[],"emergencyAccessKeyData":[],"trustedDeviceKeyData":[],"passkeyKeyData":passkeys,"object":"keyRotationData"}),
    ))
}

#[worker::send]
pub async fn get_account_public_keys(
    _claims: Claims,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Value>, AppError> {
    let user = UserDB::fetch_by_id_with(
        &state.get_db(),
        &id,
        "Failed to read public keys",
        || AppError::not_found("User"),
    )
    .await?;
    if user.public_key.is_empty() {
        return Err(AppError::not_found("Public key"));
    }
    let signature = user
        .signature_key_pair
        .as_deref()
        .and_then(|v| serde_json::from_str::<Value>(v).ok())
        .filter(|_| user.is_v2());
    Ok(Json(
        json!({"publicKey":user.public_key,"signedPublicKey":user.signed_public_key,"verifyingKey":signature.as_ref().map(|v|v["verifyingKey"].clone()),"object":"publicKeys"}),
    ))
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
    crate::api::service::account_keys::change_credentials(
        &state,
        &claims,
        &user,
        &new_hashed_password,
        &new_salt,
        new_key,
        kdf_type,
        kdf_iterations,
        final_kdf_memory,
        final_kdf_parallelism,
        user.master_password_hint.as_deref(),
    )
    .await?;

    admin_notify::emit(&state.env, Event::KdfChange, &claims.sub).await;
    Ok(Json(json!({})))
}
