use std::sync::Arc;

use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    api::{
        AppState,
        common::{
            extract::Path,
            json::Json,
            response::{ApiResponse, EmptyObject},
        },
    },
    errors::{AppError, AppResult, AuthError},
    models::identity::{account_keys, user::UserRow},
    service::identity::{
        account_keys::{
            AccountRotationContext, PasskeyUnlockItem, RotateAccountKeysRequest,
            RotateAccountPayload, SignatureKeyPair, WrappedRotationKeys,
        },
        kdf::ValidatedKdfParams,
        session::Claims,
        user::{KdfParams, MasterPasswordUnlockPayload},
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct AccountKeyPairResponse {
    key: String,
    private_key: String,
    public_key: String,
    account_keys: Value,
    object: &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_key_pair(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<ApiResponse<AccountKeyPairResponse>> {
    let user = UserRow::fetch_by_id_with(
        state.database(),
        &claims.sub,
        "Failed to fetch account keys",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    if user.private_key.is_empty() || user.public_key.is_empty() {
        return Err(AppError::not_found("Account key pair"));
    }
    let account_keys =
        crate::service::identity::account_keys::account_keys_response(&user, "object");
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
pub(in crate::api) struct UpdateUserKeyIdRequest {
    user_key_id: String,
}

#[worker::send]
pub(in crate::api) async fn update_user_key_id(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<UpdateUserKeyIdRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    if !crate::service::identity::account_keys::is_valid_key_id(&data.user_key_id) {
        return Err(AppError::bad_request(
            "Key id must be 32 lowercase hex characters",
        ));
    }
    let session = claims.session_snapshot()?;
    account_keys::set_key_id(state.database(), &session, &data.user_key_id).await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct UserPublicKeyResponse {
    user_id: String,
    public_key: String,
    object: &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_public_key(
    _claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> AppResult<ApiResponse<UserPublicKeyResponse>> {
    let row = account_keys::public_key(state.database(), &user_id).await?;
    Ok(ApiResponse(UserPublicKeyResponse {
        user_id: row.id,
        public_key: row.public_key,
        object: "userKey",
    }))
}

/// Password change and account-key rotation use one guarded transaction.
#[worker::send]
pub(in crate::api) async fn rotate_account_keys(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RotateAccountKeysRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = UserRow::fetch_by_id_with(
        state.database(),
        &claims.sub,
        "Failed to read rotation owner",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    crate::service::identity::user::require_master_password(
        &user,
        &payload.old_master_key_authentication_hash,
    )
    .await?;
    let unlock = &payload.account_unlock_data.master_password_unlock_data;
    payload.validate_rotation_metadata(&user)?;
    let kdf = KdfParams::from(ValidatedKdfParams::try_from(KdfParams {
        kdf_type: unlock.kdf_type,
        iterations: unlock.kdf_iterations,
        memory: unlock.kdf_memory,
        parallelism: unlock.kdf_parallelism,
    })?);
    if !payload
        .account_unlock_data
        .emergency_access_unlock_data
        .is_empty()
        || !payload
            .account_unlock_data
            .organization_account_recovery_unlock_data
            .is_empty()
        || !payload
            .account_unlock_data
            .device_key_unlock_data
            .is_empty()
    {
        return Err(AppError::bad_request(
            "Unsupported account recovery or trusted-device unlock data",
        ));
    }
    let keys = payload.account_keys.into_validated()?;
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
    let passkeys = payload.account_unlock_data.passkey_unlock_data;
    let unlock = payload.account_unlock_data.master_password_unlock_data;
    let new_key_id = payload.new_user_key_id.or_else(|| {
        if keys.is_v2() {
            None
        } else {
            user.user_key_id.clone()
        }
    });
    let input = crate::service::identity::account_keys::RotationInput {
        keys,
        data: payload.account_data,
        wrapped_user_key: unlock.master_key_encrypted_user_key,
        old_user_key_id: payload.old_user_key_id.or_else(|| {
            if crate::service::identity::user::is_v2(&user) {
                None
            } else {
                user.user_key_id.clone()
            }
        }),
        new_user_key_id: new_key_id,
        upgrade: None,
        passkeys,
        password: Some(crate::service::identity::account_keys::RotationPassword {
            password,
            kdf,
            hint: unlock.master_password_hint,
        }),
    };
    input
        .apply(AccountRotationContext {
            db: state.database(),
            env: &state.env,
            claims: &claims,
            user: &user,
        })
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct RotateUserKeysRequest {
    unlock_method_data: RotationUnlockMethod,
    wrapped_account_cryptographic_state: WrappedRotationKeys,
    #[serde(default)]
    old_user_key_id: Option<String>,
    #[serde(default)]
    new_user_key_id: Option<String>,
    #[serde(default)]
    unlock_data: RotationUnlockData,
    account_data: RotateAccountPayload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotationUnlockMethod {
    unlock_method: i32,
    key_connector_key_wrapped_user_key: Option<serde::de::IgnoredAny>,
    master_password_unlock_data: Option<MasterPasswordUnlockPayload>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotationUnlockData {
    #[serde(default)]
    emergency_access_unlock_data: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    organization_account_recovery_unlock_data: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    device_key_unlock_data: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    passkey_unlock_data: Vec<PasskeyUnlockItem>,
    v2_upgrade_token: Option<Value>,
}

#[worker::send]
pub(in crate::api) async fn rotate_user_keys(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RotateUserKeysRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = UserRow::fetch_by_id_with(
        state.database(),
        &claims.sub,
        "Failed to read rotation owner",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    if payload.unlock_method_data.unlock_method != 1
        || payload
            .unlock_method_data
            .key_connector_key_wrapped_user_key
            .is_some()
    {
        return Err(AppError::bad_request(
            "Only master password unlock is supported",
        ));
    }
    let unlock = payload
        .unlock_method_data
        .master_password_unlock_data
        .ok_or_else(|| AppError::bad_request("MasterPasswordUnlockData is required"))?;
    if unlock.salt != user.email
        || unlock.kdf.kdf_type != user.kdf_type
        || unlock.kdf.iterations != user.kdf_iterations
        || unlock.kdf.memory != user.kdf_memory
        || unlock.kdf.parallelism != user.kdf_parallelism
        || user.master_password_hash.is_empty()
    {
        return Err(AppError::bad_request("Invalid master password unlock data"));
    }
    let keys = payload
        .wrapped_account_cryptographic_state
        .into_validated()?;
    if !keys.is_v2() {
        return Err(AppError::bad_request("V2 account keys are required"));
    }
    if unlock.contained_key_id != payload.new_user_key_id {
        return Err(AppError::bad_request(
            "Contained key id must match the new user key id",
        ));
    }
    let common = payload.unlock_data;
    if !common.emergency_access_unlock_data.is_empty()
        || !common.organization_account_recovery_unlock_data.is_empty()
        || !common.device_key_unlock_data.is_empty()
    {
        return Err(AppError::bad_request("Unsupported unlock method"));
    }
    let input = crate::service::identity::account_keys::RotationInput {
        keys,
        data: payload.account_data,
        wrapped_user_key: unlock.master_key_wrapped_user_key,
        old_user_key_id: payload.old_user_key_id,
        new_user_key_id: payload.new_user_key_id,
        upgrade: common.v2_upgrade_token,
        passkeys: common.passkey_unlock_data,
        password: None,
    };
    input
        .apply(AccountRotationContext {
            db: state.database(),
            env: &state.env,
            claims: &claims,
            user: &user,
        })
        .await?;
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
    id: String,
    encrypted_public_key: Option<String>,
    encrypted_user_key: Option<String>,
    object: &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_key_rotation_data(
    claims: Claims,
    State(state): State<Arc<AppState>>,
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
                .is_some_and(|s| !s.is_empty())
                && key
                    .encrypted_private_key
                    .as_ref()
                    .is_some_and(|s| !s.is_empty())
        })
        .map(|key| PasskeyKeyData {
            id: key.slot.to_string(),
            encrypted_public_key: key.encrypted_public_key,
            encrypted_user_key: key.encrypted_user_key,
            object: "passkeyKeyData",
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
    public_key: String,
    signed_public_key: Option<String>,
    verifying_key: Option<String>,
    object: &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_account_public_keys(
    _claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<AccountPublicKeysResponse>> {
    let user =
        UserRow::fetch_by_id_with(state.database(), &id, "Failed to read public keys", || {
            AppError::not_found("User")
        })
        .await?;
    if user.public_key.is_empty() {
        return Err(AppError::not_found("Public key"));
    }
    let verifying_key = user
        .signature_key_pair
        .as_deref()
        .filter(|_| crate::service::identity::user::is_v2(&user))
        .and_then(|raw| serde_json::from_str::<SignatureKeyPair>(raw).ok())
        .map(|pair| pair.verifying_key);
    Ok(ApiResponse(AccountPublicKeysResponse {
        public_key: user.public_key,
        signed_public_key: user.signed_public_key,
        verifying_key,
        object: "publicKeys",
    }))
}
