use axum::{
    Json,
    extract::Path,
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};

use crate::errors::AppError;

/// GET /devices
///
/// Returns an empty list of devices.
/// Device tracking is not implemented in this minimal Bitwarden-compatible
/// server. This does not affect authentication since we use stateless JWT
/// tokens. Clients will show "No devices currently logged in" in the device
/// management settings.
#[worker::send]
pub async fn get_devices() -> Json<Value> {
    Json(json!({
        "data": [],
        "continuationToken": null,
        "object": "list"
    }))
}

/// GET /devices/knowndevice
///
/// Checks if a device is known to the server.
/// Always returns false since we don't track devices.
/// This is used by clients to determine if a device has been previously used.
/// X-Request-Email and X-Device-Identifier headers are expected but we ignore
/// them.
#[worker::send]
pub async fn get_known_device() -> Json<bool> {
    // Always return false - we don't track devices
    Json(false)
}

/// GET /`devices/identifier/{device_id`}
///
/// Returns information about a specific device.
/// Since we don't track devices, we return a 404-like error.
/// However, to avoid client errors, we return an empty device stub.
#[worker::send]
pub async fn get_device(
    Path(device_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    // Return a minimal device stub to prevent client errors
    // The client may request device info after login
    Ok(Json(json!({
        "id": device_id,
        "name": "Unknown Device",
        "type": 0,
        "identifier": device_id,
        "creationDate": "2000-01-01T00:00:00.000Z",
        "object": "device"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushToken {
    #[allow(dead_code)]
    push_token: String,
}

/// POST /`devices/identifier/{device_id}/token`
///
/// Registers a push token for a device.
/// We accept but ignore this since push notifications are not implemented.
#[worker::send]
pub async fn post_device_token(
    Path(_device_id): Path<String>,
    Json(_data): Json<PushToken>,
) -> Json<Value> {
    // Accept but ignore - push notifications not implemented
    Json(json!({}))
}

/// PUT /`devices/identifier/{device_id}/token`
///
/// Updates a push token for a device.
/// We accept but ignore this since push notifications are not implemented.
#[worker::send]
pub async fn put_device_token(
    Path(_device_id): Path<String>,
    Json(_data): Json<PushToken>,
) -> Json<Value> {
    // Accept but ignore - push notifications not implemented
    Json(json!({}))
}

/// PUT /devices/identifier/{device_id}/clear-token
///
/// Clears the push token for a device.
/// We accept but ignore this since push notifications are not implemented.
#[worker::send]
pub async fn put_clear_device_token(
    Path(_device_id): Path<String>,
) -> Json<Value> {
    // Accept but ignore - push notifications not implemented
    Json(json!({}))
}

/// POST /devices/identifier/{device_id}/clear-token
///
/// Clears the push token for a device.
/// We accept but ignore this since push notifications are not implemented.
#[worker::send]
pub async fn post_clear_device_token(
    Path(_device_id): Path<String>,
) -> Json<Value> {
    // Accept but ignore - push notifications not implemented
    Json(json!({}))
}
