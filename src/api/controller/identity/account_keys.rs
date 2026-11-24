use std::sync::Arc;

use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    api::{
        AppState,
        common::{
            json::Json,
            response::{ApiResponse, EmptyObject},
        },
    },
    errors::{AppError, AppResult, AuthError},
    models::identity::{account_keys, user::UserRow},
    service::identity::{
        account_keys::{
            AccountKeysRequest, AccountRotationContext, PasskeyUnlockItem,
            RotateAccountKeysRequest, RotateAccountPayload, SignatureKeyPair, ValidatedAccountKeys,
            WrappedRotationKeys, is_valid_key_id,
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
    let account_keys = crate::service::identity::account_keys::account_keys_response(&user);
    Ok(ApiResponse(AccountKeyPairResponse {
        key: user.key,
        private_key: user.private_key,
        public_key: user.public_key,
        account_keys,
        object: "keys",
    }))
}

/// Parse optional legacy fields without changing which operation reports an invalid field.
#[derive(Deserialize)]
#[serde(untagged)]
enum CompatibleField<T> {
    Valid(T),
    Invalid(serde::de::IgnoredAny),
}

impl<T> CompatibleField<T> {
    fn into_valid(self) -> Option<T> {
        match self {
            Self::Valid(value) => Some(value),
            Self::Invalid(_) => None,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateKeyPairFields {
    account_keys: Option<CompatibleField<AccountKeysRequest>>,
    encrypted_private_key: Option<CompatibleField<String>>,
    public_key: Option<CompatibleField<String>>,
    user_key_id: Option<CompatibleField<String>>,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(in crate::api) struct UpdateKeyPairRequest(CompatibleField<UpdateKeyPairFields>);

#[worker::send]
pub(in crate::api) async fn update_key_pair(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(UpdateKeyPairRequest(data)): Json<UpdateKeyPairRequest>,
) -> AppResult<ApiResponse<AccountKeyPairResponse>> {
    let fields = data.into_valid().unwrap_or_default();
    let keys = if let Some(keys) = fields.account_keys {
        let validated = keys
            .into_valid()
            .ok_or_else(|| AppError::bad_request("Invalid account keys"))?
            .into_validated()?;
        if !validated.is_v2() {
            return Err(AppError::bad_request(
                "AccountKeys are only supported for V2 encryption",
            ));
        }
        validated
    } else {
        let required = || AppError::bad_request("Both account keys are required");
        let private = fields
            .encrypted_private_key
            .and_then(CompatibleField::into_valid)
            .filter(|key| !key.trim().is_empty())
            .ok_or_else(required)?;
        let public = fields
            .public_key
            .and_then(CompatibleField::into_valid)
            .filter(|key| !key.trim().is_empty())
            .ok_or_else(required)?;
        ValidatedAccountKeys::from_legacy_pair(private, public)
    };
    let key_id = fields
        .user_key_id
        .map(|id| {
            id.into_valid()
                .filter(|id| is_valid_key_id(id))
                .ok_or_else(|| AppError::bad_request("Key id must be 32 lowercase hex characters"))
        })
        .transpose()?;
    let key_id = if keys.is_v2() {
        key_id.as_deref()
    } else {
        None
    };
    let material = keys.into_persistence_material()?;
    let session = claims.session_snapshot()?;
    account_keys::set_initial_material(state.database(), &session, &material, key_id).await?;
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
        password: Some(crate::service::identity::account_keys::RotationPassword {
            password,
            kdf,
            hint: unlock.master_password_hint.clone(),
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

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateUserKeyFields {
    unlock_method_data: Option<CompatibleField<RotationUnlockMethod>>,
    wrapped_account_cryptographic_state: Option<CompatibleField<WrappedRotationKeys>>,
    old_user_key_id: Option<CompatibleField<String>>,
    new_user_key_id: Option<CompatibleField<String>>,
    unlock_data: Option<CompatibleField<RotationUnlockData>>,
    account_data: Option<CompatibleField<RotateAccountPayload>>,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(in crate::api) struct RotateUserKeysRequest(CompatibleField<RotateUserKeyFields>);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotationUnlockMethod {
    unlock_method: Option<CompatibleField<i32>>,
    key_connector_key_wrapped_user_key: Option<serde::de::IgnoredAny>,
    master_password_unlock_data: Option<CompatibleField<MasterPasswordUnlockPayload>>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotationUnlockData {
    emergency_access_unlock_data: Option<CompatibleField<Vec<serde::de::IgnoredAny>>>,
    organization_account_recovery_unlock_data: Option<CompatibleField<Vec<serde::de::IgnoredAny>>>,
    device_key_unlock_data: Option<CompatibleField<Vec<serde::de::IgnoredAny>>>,
    passkey_unlock_data: Option<CompatibleField<Vec<PasskeyUnlockItem>>>,
    v2_upgrade_token: Option<Value>,
}

#[worker::send]
pub(in crate::api) async fn rotate_user_keys(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(RotateUserKeysRequest(payload)): Json<RotateUserKeysRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = UserRow::fetch_by_id_with(
        state.database(),
        &claims.sub,
        "Failed to read rotation owner",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    let payload = payload.into_valid().unwrap_or_default();
    let method = payload
        .unlock_method_data
        .and_then(CompatibleField::into_valid)
        .filter(|method| method.key_connector_key_wrapped_user_key.is_none())
        .ok_or_else(|| AppError::bad_request("Only master password unlock is supported"))?;
    if method.unlock_method.and_then(CompatibleField::into_valid) != Some(1) {
        return Err(AppError::bad_request(
            "Only master password unlock is supported",
        ));
    }
    let unlock = method
        .master_password_unlock_data
        .and_then(CompatibleField::into_valid)
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
        .and_then(CompatibleField::into_valid)
        .ok_or_else(|| AppError::bad_request("Invalid V2 account keys"))?
        .into_validated()?;
    if !keys.is_v2() {
        return Err(AppError::bad_request("V2 account keys are required"));
    }
    let old = payload
        .old_user_key_id
        .and_then(CompatibleField::into_valid);
    let new = payload
        .new_user_key_id
        .and_then(CompatibleField::into_valid);
    if unlock.contained_key_id != new {
        return Err(AppError::bad_request(
            "Contained key id must match the new user key id",
        ));
    }
    let common = payload
        .unlock_data
        .and_then(CompatibleField::into_valid)
        .unwrap_or_default();
    if [
        common.emergency_access_unlock_data,
        common.organization_account_recovery_unlock_data,
        common.device_key_unlock_data,
    ]
    .into_iter()
    .flatten()
    .filter_map(CompatibleField::into_valid)
    .any(|items| !items.is_empty())
    {
        return Err(AppError::bad_request("Unsupported unlock method"));
    }
    let data = payload
        .account_data
        .and_then(CompatibleField::into_valid)
        .ok_or_else(|| AppError::bad_request("Invalid account rotation data"))?;
    let input = crate::service::identity::account_keys::RotationInput {
        keys,
        data,
        wrapped_user_key: unlock.master_key_wrapped_user_key,
        old_user_key_id: old,
        new_user_key_id: new,
        upgrade: common.v2_upgrade_token,
        passkeys: common
            .passkey_unlock_data
            .and_then(CompatibleField::into_valid)
            .unwrap_or_default(),
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
    axum::extract::Path(id): axum::extract::Path<String>,
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
