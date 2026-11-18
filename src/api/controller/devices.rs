use axum::{
    Json,
    extract::{
        Path,
        State,
    },
    http::HeaderMap,
};
use base64::{
    Engine as _,
    engine::general_purpose::{
        URL_SAFE,
        URL_SAFE_NO_PAD,
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
        service::{
            claims::Claims,
            push,
            rate,
        },
    },
    errors::AppError,
    models::{
        auth_request::AuthRequestDB,
        device::DeviceDB,
        user::UserDB,
    },
};

#[worker::send]
pub async fn get_devices(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let devices = DeviceDB::list_for_user(&db, &claims.sub).await?;
    let requests =
        AuthRequestDB::list_pending_for_user(&db, &claims.sub).await?;
    let data: Vec<Value> = devices.iter().map(|device| {
        let mut value = device.to_json();
        value["devicePendingAuthRequest"] = requests.iter().find(|request| request.request_device_identifier == device.identifier).map_or(Value::Null, |request| json!({ "id": request.id, "creationDate": request.creation_date }));
        value
    }).collect();
    Ok(Json(
        json!({ "data": data, "continuationToken": null, "object": "list" }),
    ))
}

#[worker::send]
pub async fn get_known_device(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<bool>, AppError> {
    rate::check_rate_limit(
        &state,
        format!("known-device:{}", rate::client_ip(&headers)),
    )
    .await?;
    let encoded = headers
        .get("x-request-email")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let identifier = headers
        .get("x-device-identifier")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let email = decode_email(encoded)?;
    if identifier.is_empty() {
        return Ok(Json(false));
    }
    let db = state.get_db();
    let user = UserDB::fetch_by_email_with(
        &db,
        &email,
        "Failed to find known device user",
        || AppError::not_found("User"),
    )
    .await;
    match user {
        Ok(user) => Ok(Json(
            DeviceDB::find_for_user(&db, &user.id, identifier)
                .await?
                .is_some(),
        )),
        Err(AppError::NotFound { .. }) => Ok(Json(false)),
        Err(error) => Err(error),
    }
}

fn decode_email(encoded: &str) -> Result<String, AppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .map_err(|_| AppError::bad_request("Invalid X-Request-Email header"))?;
    String::from_utf8(bytes)
        .map(|email| email.trim().to_lowercase())
        .map_err(|_| AppError::bad_request("Invalid X-Request-Email header"))
}

#[worker::send]
pub async fn get_device(
    claims: Claims,
    State(state): State<AppState>,
    Path(device_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let device =
        DeviceDB::find_for_user(&state.get_db(), &claims.sub, &device_id)
            .await?
            .ok_or_else(|| AppError::not_found("Device"))?;
    Ok(Json(device.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushToken {
    push_token: String,
}

async fn set_token(
    state: &AppState,
    claims: &Claims,
    device_id: &str,
    token: Option<&str>,
) -> Result<Json<Value>, AppError> {
    if claims.device() != Some(device_id) {
        return Err(AppError::bad_request(
            "Can only update the authenticated device",
        ));
    }
    if token.is_none() {
        if let Err(error) =
            push::unregister_device(&state.env, &claims.sub, device_id).await
        {
            log::warn!("Push device unregistration failed: {error}");
        }
    }
    DeviceDB::set_push_token(&state.get_db(), &claims.sub, device_id, token)
        .await?;
    if token.is_some() {
        push::register_device(&state.env, &claims.sub, device_id).await?;
    }
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_device_token(
    claims: Claims,
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    Json(data): Json<PushToken>,
) -> Result<Json<Value>, AppError> {
    let token = data.push_token.trim();
    if token.is_empty() || token.len() > 4096 {
        return Err(AppError::bad_request("Invalid push token"));
    }
    set_token(&state, &claims, &device_id, Some(token)).await
}

#[worker::send]
pub async fn put_device_token(
    claims: Claims,
    state: State<AppState>,
    path: Path<String>,
    payload: Json<PushToken>,
) -> Result<Json<Value>, AppError> {
    post_device_token(claims, state, path, payload).await
}

#[worker::send]
pub async fn put_clear_device_token(
    claims: Claims,
    State(state): State<AppState>,
    Path(device_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    set_token(&state, &claims, &device_id, None).await
}

#[worker::send]
pub async fn post_clear_device_token(
    claims: Claims,
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<Value>, AppError> {
    put_clear_device_token(claims, state, path).await
}

#[worker::send]
pub async fn delete_device(
    claims: Claims,
    State(state): State<AppState>,
    Path(device_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    if let Err(error) =
        push::unregister_device(&state.env, &claims.sub, &device_id).await
    {
        log::warn!("Push device unregistration failed: {error}");
    }
    DeviceDB::delete_for_user(&state.get_db(), &claims.sub, &device_id).await?;
    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_device_accepts_padded_and_unpadded_email() {
        for engine in [URL_SAFE, URL_SAFE_NO_PAD] {
            assert_eq!(
                decode_email(&engine.encode(" User@Example.com ")).unwrap(),
                "user@example.com"
            );
        }
        assert!(decode_email("%bad").is_err());
    }
}
