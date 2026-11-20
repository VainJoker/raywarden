use axum::{
    Json,
    extract::{
        Path,
        State,
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        common::response::{
            ApiResponse,
            EmptyObject,
        },
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    models::identity::{
        account_keys::AccountKeysStore,
        user::UserRow,
    },
    service::identity::{
        account_keys::RotateAccountKeysRequest,
        kdf::{
            KDF_TYPE_ARGON2ID,
            ensure_supported_kdf,
        },
        session::Claims,
        user::KdfParams,
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct AccountKeyPairResponse {
    key:          String,
    private_key:  String,
    public_key:   String,
    account_keys: Value,
    object:       &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_key_pair(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<AccountKeyPairResponse>> {
    key_pair(&state, &claims.sub).await
}

async fn key_pair(
    state: &AppState,
    user_id: &str,
) -> AppResult<ApiResponse<AccountKeyPairResponse>> {
    let user = UserRow::fetch_by_id_with(
        state.database(),
        user_id,
        "Failed to fetch account keys",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    if user.private_key.is_empty() || user.public_key.is_empty() {
        return Err(AppError::not_found("Account key pair"));
    }
    let account_keys =
        crate::service::identity::account_keys::account_keys_response(&user);
    Ok(ApiResponse(AccountKeyPairResponse {
        key: user.key,
        private_key: user.private_key,
        public_key: user.public_key,
        account_keys,
        object: "keys",
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyKeyPairPayload {
    encrypted_private_key: String,
    public_key:            String,
}

#[worker::send]
pub(in crate::api) async fn update_key_pair(
    claims: Claims,
    State(state): State<AppState>,
    Json(data): Json<Value>,
) -> AppResult<ApiResponse<AccountKeyPairResponse>> {
    let keys = if let Some(keys) =
        data.get("accountKeys").filter(|v| !v.is_null())
    {
        let parsed: crate::service::identity::account_keys::AccountKeysRequest =
            Deserialize::deserialize(keys).map_err(|_error| {
                AppError::bad_request("Invalid account keys")
            })?;
        let validated = parsed.validate()?;
        if !validated.is_v2() {
            return Err(AppError::bad_request(
                "AccountKeys are only supported for V2 encryption",
            ));
        }
        validated
    } else {
        let pair: LegacyKeyPairPayload = Deserialize::deserialize(&data)
            .map_err(|_error| {
                AppError::bad_request("Both account keys are required")
            })?;
        if pair.encrypted_private_key.trim().is_empty() ||
            pair.public_key.trim().is_empty()
        {
            return Err(AppError::bad_request(
                "Both account keys are required",
            ));
        }
        crate::service::identity::account_keys::ValidatedAccountKeys::from_legacy_pair(
            pair.encrypted_private_key,
            pair.public_key,
        )
    };
    let key_id = data
        .get("userKeyId")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_str()
                .filter(|id| {
                    crate::service::identity::account_keys::is_valid_key_id(id)
                })
                .ok_or_else(|| {
                    AppError::bad_request(
                        "Key id must be 32 lowercase hex characters",
                    )
                })
        })
        .transpose()?;
    let key_id = if keys.is_v2() { key_id } else { None };
    let material = keys.into_persistence_material()?;
    AccountKeysStore::set_initial_material(
        state.database(),
        &claims.sub,
        &claims.sstamp,
        &material,
        key_id,
    )
    .await?;
    key_pair(&state, &claims.sub).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct UpdateUserKeyIdRequest {
    user_key_id: String,
}

#[worker::send]
pub(in crate::api) async fn update_user_key_id(
    claims: Claims,
    State(state): State<AppState>,
    Json(data): Json<UpdateUserKeyIdRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    if !crate::service::identity::account_keys::is_valid_key_id(
        &data.user_key_id,
    ) {
        return Err(AppError::bad_request(
            "Key id must be 32 lowercase hex characters",
        ));
    }
    AccountKeysStore::set_key_id(
        state.database(),
        &claims.sub,
        &data.user_key_id,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct UserPublicKeyResponse {
    user_id:    String,
    public_key: String,
    object:     &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_public_key(
    _claims: Claims,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> AppResult<ApiResponse<UserPublicKeyResponse>> {
    let row = AccountKeysStore::public_key(state.database(), &user_id).await?;
    Ok(ApiResponse(UserPublicKeyResponse {
        user_id:    row.id,
        public_key: row.public_key,
        object:     "userKey",
    }))
}

/// Password change and account-key rotation use one guarded transaction.
#[worker::send]
pub(in crate::api) async fn rotate_account_keys(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<RotateAccountKeysRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = UserRow::fetch_by_id_with(
        state.database(),
        &claims.sub,
        "Failed to read rotation owner",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    if !crate::service::identity::user::verify_master_password(
        &user,
        &payload.old_master_key_authentication_hash,
    )
    .await?
    .is_valid()
    {
        return Err(AuthError::InvalidPassword.into());
    }
    let unlock = &payload.account_unlock_data.master_password_unlock_data;
    payload.validate_rotation_metadata(&user)?;
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
    let password = crate::service::identity::user::stored_password_for_user(
        &unlock.master_key_authentication_hash,
        &user,
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
        if keys.is_v2() {
            None
        } else {
            user.user_key_id.clone()
        }
    });
    let input = crate::service::identity::account_keys::RotationInput {
        keys,
        data: payload.account_data,
        wrapped_user_key: unlock.master_key_encrypted_user_key.clone(),
        old_user_key_id: payload.old_user_key_id.or_else(|| {
            if crate::service::identity::user::is_v2(&user) {
                None
            } else {
                user.user_key_id.clone()
            }
        }),
        new_user_key_id: new_key_id,
        upgrade: None,
        passkeys: payload.account_unlock_data.passkey_unlock_data,
        password: Some(
            crate::service::identity::account_keys::RotationPassword {
                password,
                kdf: KdfParams {
                    kdf_type: unlock.kdf_type,
                    iterations: unlock.kdf_iterations,
                    memory,
                    parallelism,
                },
                hint: unlock.master_password_hint.clone(),
            },
        ),
    };
    input.apply(&state, &claims, &user).await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn rotate_user_keys(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = UserRow::fetch_by_id_with(
        state.database(),
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
    let unlock: crate::service::identity::user::MasterPasswordUnlockPayload =
        Deserialize::deserialize(&method["masterPasswordUnlockData"]).map_err(
            |_error| {
                AppError::bad_request("MasterPasswordUnlockData is required")
            },
        )?;
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
    let keys: crate::service::identity::account_keys::AccountKeysRequest =
        serde_json::from_value(json!({
            "userKeyEncryptedAccountPrivateKey": pair["wrappedPrivateKey"],
            "accountPublicKey": pair["publicKey"],
            "publicKeyEncryptionKeyPair": pair,
            "signatureKeyPair": state_keys["signatureKeyPair"],
            "securityState": state_keys["securityState"],
        }))
        .map_err(|_error| AppError::bad_request("Invalid V2 account keys"))?;
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
    let data = Deserialize::deserialize(&payload["accountData"]).map_err(
        |_error| AppError::bad_request("Invalid account rotation data"),
    )?;
    let input = crate::service::identity::account_keys::RotationInput {
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
    input.apply(&state, &claims, &user).await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct KeyRotationDataResponse {
    organization_password_reset_key_data: [(); 0],
    emergency_access_key_data: [(); 0],
    trusted_device_key_data: [(); 0],
    passkey_key_data: Vec<PasskeyKeyData>,
    object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyKeyData {
    id:                   String,
    encrypted_public_key: Option<String>,
    encrypted_user_key:   Option<String>,
    object:               &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_key_rotation_data(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<KeyRotationDataResponse>> {
    let keys = crate::models::identity::webauthn::WebauthnCredentialRow::list(
        state.database(),
        &claims.sub,
        "login",
    )
    .await?;
    let passkey_key_data = keys
        .into_iter()
        .filter(|key| {
            key.encrypted_user_key
                .as_ref()
                .is_some_and(|s| !s.is_empty()) &&
                key.encrypted_private_key
                    .as_ref()
                    .is_some_and(|s| !s.is_empty())
        })
        .map(|key| PasskeyKeyData {
            id:                   key.slot.to_string(),
            encrypted_public_key: key.encrypted_public_key,
            encrypted_user_key:   key.encrypted_user_key,
            object:               "passkeyKeyData",
        })
        .collect();
    Ok(ApiResponse(KeyRotationDataResponse {
        organization_password_reset_key_data: [],
        emergency_access_key_data: [],
        trusted_device_key_data: [],
        passkey_key_data,
        object: "keyRotationData",
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct AccountPublicKeysResponse {
    public_key:        String,
    signed_public_key: Option<String>,
    verifying_key:     Value,
    object:            &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_account_public_keys(
    _claims: Claims,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> AppResult<ApiResponse<AccountPublicKeysResponse>> {
    let user = UserRow::fetch_by_id_with(
        state.database(),
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
        .filter(|_| crate::service::identity::user::is_v2(&user));
    Ok(ApiResponse(AccountPublicKeysResponse {
        public_key:        user.public_key,
        signed_public_key: user.signed_public_key,
        verifying_key:     signature
            .map_or(Value::Null, |v| v["verifyingKey"].clone()),
        object:            "publicKeys",
    }))
}
