use axum::{
    Json,
    extract::{
        Path,
        State,
    },
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    models::{
        account_keys::AccountKeysDB,
        user::UserDB,
    },
};

#[worker::send]
pub async fn get_keys(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let user = UserDB::fetch_by_id_with(
        &state.get_db(),
        &claims.sub,
        "Failed to fetch account keys",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    if user.private_key.is_empty() || user.public_key.is_empty() {
        return Err(AppError::not_found("Account key pair"));
    }
    Ok(Json(
        json!({"key": user.key, "privateKey": user.private_key, "publicKey": user.public_key,
        "accountKeys": crate::models::account_keys::response(&user), "object": "keys"}),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPairData {
    encrypted_private_key: String,
    public_key:            String,
}

#[worker::send]
pub async fn post_keys(
    claims: Claims,
    State(state): State<AppState>,
    Json(data): Json<Value>,
) -> AppResult<Json<Value>> {
    let keys = if let Some(keys) =
        data.get("accountKeys").filter(|v| !v.is_null())
    {
        let parsed: crate::models::account_keys::AccountKeysData =
            serde_json::from_value(keys.clone())
                .map_err(|_| AppError::bad_request("Invalid account keys"))?;
        let validated = parsed.validate()?;
        if !validated.is_v2() {
            return Err(AppError::bad_request(
                "AccountKeys are only supported for V2 encryption",
            ));
        }
        validated
    } else {
        let pair: KeyPairData =
            serde_json::from_value(data.clone()).map_err(|_| {
                AppError::bad_request("Both account keys are required")
            })?;
        if pair.encrypted_private_key.trim().is_empty() ||
            pair.public_key.trim().is_empty()
        {
            return Err(AppError::bad_request(
                "Both account keys are required",
            ));
        }
        crate::models::account_keys::ValidatedAccountKeys {
            private_key:        pair.encrypted_private_key,
            public_key:         pair.public_key,
            signed_public_key:  None,
            security_state:     None,
            security_version:   None,
            signature_key_pair: None,
        }
    };
    let key_id = data
        .get("userKeyId")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_str()
                .filter(|id| crate::models::account_keys::is_valid_key_id(id))
                .ok_or_else(|| {
                    AppError::bad_request(
                        "Key id must be 32 lowercase hex characters",
                    )
                })
        })
        .transpose()?;
    AccountKeysDB::set_initial_material(
        &state.get_db(),
        &claims.sub,
        &claims.sstamp,
        &keys,
        if keys.is_v2() { key_id } else { None },
    )
    .await?;
    get_keys(claims, State(state)).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyId {
    user_key_id: String,
}

#[worker::send]
pub async fn post_user_key_id(
    claims: Claims,
    State(state): State<AppState>,
    Json(data): Json<UserKeyId>,
) -> AppResult<Json<Value>> {
    if !crate::models::account_keys::is_valid_key_id(&data.user_key_id) {
        return Err(AppError::bad_request(
            "Key id must be 32 lowercase hex characters",
        ));
    }
    AccountKeysDB::set_key_id(&state.get_db(), &claims.sub, &data.user_key_id)
        .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn get_public_key(
    _claims: Claims,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> AppResult<Json<Value>> {
    let row = AccountKeysDB::public_key(&state.get_db(), &user_id).await?;
    Ok(Json(
        json!({"userId": row.id, "publicKey": row.public_key, "object": "userKey"}),
    ))
}

#[worker::send]
pub async fn events(
    _claims: Claims,
    Json(_events): Json<Vec<Value>>,
) -> Json<Value> {
    Json(json!({}))
}

#[worker::send]
pub async fn apple_association() -> Json<Value> {
    Json(
        json!({"webcredentials": {"apps": ["LTZ2PFU5D6.com.8bit.bitwarden", "LTZ2PFU5D6.com.8bit.bitwarden.beta"]}}),
    )
}
