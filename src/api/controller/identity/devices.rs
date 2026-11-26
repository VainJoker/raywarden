use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, State},
    http::request::Parts,
};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        AppState,
        common::{
            extract::{ClientIp, Path},
            json::Json,
            response::{ApiResponse, EmptyObject, ListResponse},
        },
    },
    errors::{AppError, AppResult},
    models::identity::{auth_request::AuthRequestRow, device::DeviceRow},
    service::{
        identity::{session::Claims, user::AccountVerificationRequest},
        notifications::{admin as admin_notify, admin::Event},
        rate_limit,
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct DeviceResponse {
    id: String,
    identifier: String,
    name: String,
    #[serde(rename = "type")]
    device_type: i32,
    creation_date: String,
    last_active_date: String,
    is_trusted: bool,
    encrypted_public_key: Option<String>,
    encrypted_user_key: Option<String>,
    object: &'static str,
}

impl From<DeviceRow> for DeviceResponse {
    fn from(row: DeviceRow) -> Self {
        Self {
            identifier: row.device_id.clone(),
            id: row.device_id,
            name: row.name,
            device_type: row.device_type,
            creation_date: row.created_at,
            last_active_date: row.updated_at,
            is_trusted: false,
            encrypted_public_key: None,
            encrypted_user_key: None,
            object: "device",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct DeviceListItem {
    #[serde(flatten)]
    device: DeviceResponse,
    device_pending_auth_request: Option<PendingDeviceAuthRequest>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingDeviceAuthRequest {
    id: String,
    creation_date: String,
}

#[worker::send]
pub(in crate::api) async fn list_devices(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<ApiResponse<ListResponse<DeviceListItem>>> {
    let db = state.database();
    let devices = DeviceRow::list_for_user(db, &claims.sub).await?;
    let requests = AuthRequestRow::list_pending_for_user(db, &claims.sub).await?;
    let data = devices
        .into_iter()
        .map(|device| {
            let device_pending_auth_request = requests
                .iter()
                .find(|request| request.request_device_id == device.device_id)
                .map(|request| PendingDeviceAuthRequest {
                    id: request.id.clone(),
                    creation_date: request.created_at.clone(),
                });
            DeviceListItem {
                device: device.into(),
                device_pending_auth_request,
            }
        })
        .collect::<Vec<_>>();
    Ok(ApiResponse(data.into()))
}

pub(in crate::api) struct KnownDeviceHeaders {
    email: AppResult<String>,
    identifier: String,
}

impl<S: Send + Sync> FromRequestParts<S> for KnownDeviceHeaders {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let text = |header| {
            parts
                .headers
                .get(header)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
        };
        std::future::ready(Ok(Self {
            email: decode_email(text("x-request-email")),
            identifier: text("x-device-identifier").to_owned(),
        }))
    }
}

#[worker::send]
pub(in crate::api) async fn get_known_device(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    KnownDeviceHeaders { email, identifier }: KnownDeviceHeaders,
) -> AppResult<ApiResponse<bool>> {
    rate_limit::check_auth_attempt(&state.env, format!("known-device:{ip}")).await?;
    let email = email?;
    if identifier.is_empty() {
        return Ok(ApiResponse(false));
    }
    let db = state.database();
    let user = crate::service::identity::user::fetch_by_email_with(
        db,
        &email,
        "Failed to find known device user",
        || AppError::not_found("User"),
    )
    .await;
    match user {
        Ok(user) => Ok(ApiResponse(
            DeviceRow::find_for_user(db, &user.id, &identifier)
                .await?
                .is_some(),
        )),
        Err(AppError::NotFound { .. }) => Ok(ApiResponse(false)),
        Err(error) => Err(error),
    }
}

fn decode_email(encoded: &str) -> AppResult<String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .map_err(|_error| AppError::bad_request("Invalid X-Request-Email header"))?;
    String::from_utf8(bytes)
        .map(|email| email.trim().to_lowercase())
        .map_err(|_error| AppError::bad_request("Invalid X-Request-Email header"))
}

#[worker::send]
pub(in crate::api) async fn get_device(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> AppResult<ApiResponse<DeviceResponse>> {
    let device = DeviceRow::find_for_user(state.database(), &claims.sub, &device_id)
        .await?
        .ok_or_else(|| AppError::not_found("Device"))?;
    Ok(ApiResponse(device.into()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct SetDevicePushTokenRequest {
    push_token: String,
}

async fn set_token(
    state: &AppState,
    claims: &Claims,
    device_id: &str,
    token: Option<&str>,
) -> AppResult<ApiResponse<EmptyObject>> {
    if claims.device() != Some(device_id) {
        return Err(AppError::bad_request(
            "Can only update the authenticated device",
        ));
    }
    DeviceRow::set_push_token(state.database(), &claims.sub, device_id, token).await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn set_device_push_token(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Json(data): Json<SetDevicePushTokenRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let token = data.push_token.trim();
    if token.is_empty() || token.len() > 4096 {
        return Err(AppError::bad_request("Invalid push token"));
    }
    set_token(&state, &claims, &device_id, Some(token)).await
}

#[worker::send]
pub(in crate::api) async fn clear_device_push_token(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> AppResult<ApiResponse<EmptyObject>> {
    set_token(&state, &claims, &device_id, None).await
}

#[worker::send]
pub(in crate::api) async fn delete_device(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> AppResult<ApiResponse<EmptyObject>> {
    DeviceRow::delete_for_user(state.database(), &claims.sub, &device_id).await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn revoke_all_sessions(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let db = state.database();
    let authorization = state
        .email_verifier()
        .prepare_account_action(&claims, &payload)
        .await?;
    let stamp = uuid::Uuid::new_v4().to_string();
    DeviceRow::revoke_all_with_stamp(db, &authorization, &stamp).await?;
    crate::service::notifications::publish_account_logout(
        &state.env,
        &claims,
        &crate::utils::time::now_rfc3339(),
    )
    .await;
    admin_notify::emit(&state.env, Event::AccountSecurityChanged, &claims.sub).await;
    Ok(ApiResponse(EmptyObject {}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_device_accepts_padded_and_unpadded_email() {
        for engine in [URL_SAFE, URL_SAFE_NO_PAD] {
            assert_eq!(
                decode_email(&engine.encode(" User@Example.com ")).expect("valid devices fixture"),
                "user@example.com"
            );
        }
        assert!(decode_email("%bad").is_err());
    }
}
