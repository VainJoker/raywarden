//! HTTP status, safe client diagnostics, and JSON serialization for application failures.
use axum::{
    Json,
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};

use super::{AppError, AuthError};

#[derive(Clone)]
struct PendingServerErrorLog(String);

#[derive(Clone)]
struct AttachRayId(Map<String, Value>);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        use StatusCode as Status;

        // The numeric client codes are independent of enum layout.
        let (status, code) = match self {
            Self::OAuth { error, description } => {
                return render_envelope(
                    Status::BAD_REQUEST,
                    json!({
                        "error": error,
                        "error_description": description,
                    }),
                );
            }
            Self::IdentityChallenge(value) => {
                return (Status::BAD_REQUEST, Json(value)).into_response();
            }
            Self::Params(_) | Self::InvalidTokenParams(_) | Self::UnsupportedGrantType => {
                (Status::BAD_REQUEST, 9002)
            }
            Self::BadRequest { .. } | Self::InvalidTokenRequest { .. } => (Status::BAD_REQUEST, 5),
            Self::Conflict { .. } => (Status::CONFLICT, 6),
            Self::UnprocessableEntity { .. } => (Status::UNPROCESSABLE_ENTITY, 7),
            Self::PayloadTooLarge { .. } => (Status::PAYLOAD_TOO_LARGE, 8),
            Self::UnsupportedMediaType { .. } => (Status::UNSUPPORTED_MEDIA_TYPE, 16),
            Self::NotFound { .. } => (Status::NOT_FOUND, 10),
            Self::TooManyRequests { .. } => (Status::TOO_MANY_REQUESTS, 11),
            Self::ServiceUnavailable { .. } => (Status::SERVICE_UNAVAILABLE, 12),
            Self::Unauthorized { .. } => (Status::UNAUTHORIZED, 9003),
            Self::Jwt(_) => (Status::UNAUTHORIZED, 4),
            Self::Auth(ref error) => {
                let status = match error {
                    AuthError::InvalidCredentials(_)
                    | AuthError::InvalidPassword
                    | AuthError::MissingToken
                    | AuthError::InvalidTotp => Status::UNAUTHORIZED,
                    AuthError::InsufficientPermissions | AuthError::AccountLocked => {
                        Status::FORBIDDEN
                    }
                    AuthError::InvalidKdf(_) => Status::BAD_REQUEST,
                    AuthError::UserNotFound => Status::NOT_FOUND,
                };
                (status, 2)
            }
            Self::Config(_) => (Status::INTERNAL_SERVER_ERROR, 0),
            Self::Worker { .. } => (Status::INTERNAL_SERVER_ERROR, 9001),
            Self::Database(_) => (Status::INTERNAL_SERVER_ERROR, 1),
            Self::Crypto(_) => (Status::INTERNAL_SERVER_ERROR, 3),
            Self::Upstream { .. } => (Status::INTERNAL_SERVER_ERROR, 15),
            Self::Internal { .. } => (Status::INTERNAL_SERVER_ERROR, 13),
        };

        let mut value = json!({
            "object": "error",
            "code": code,
            "message": self.to_string(),
        });
        let oauth = match &self {
            Self::InvalidTokenRequest { message } | Self::InvalidTokenParams(message) => {
                Some(("invalid_request", message.as_ref()))
            }
            Self::UnsupportedGrantType => {
                Some(("unsupported_grant_type", "Unsupported grant_type"))
            }
            _ => None,
        };
        if let Some((error, description)) = oauth {
            value["error"] = error.into();
            value["error_description"] = description.into();
        }
        let mut response = render_envelope(status, value);
        if status.is_server_error() && !matches!(self, Self::ServiceUnavailable { .. }) {
            response
                .extensions_mut()
                .insert(PendingServerErrorLog(format!("{self:?}")));
        }
        response
    }
}

fn render_envelope(status: StatusCode, value: Value) -> Response {
    let attach = value.as_object().cloned().map(AttachRayId);
    let mut response = (status, Json(value)).into_response();
    if let Some(attach) = attach {
        response.extensions_mut().insert(attach);
    }
    response
}

/// Normalize Cloudflare's `CF-Ray` header (e.g. `a5f72d126a84fd0c-HKG`) to the
/// canonical ray ID shown in Workers `$metadata.rayId`.
pub(crate) fn extract_ray_id(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    let id = raw.split('-').next().unwrap_or(raw).trim();
    (!id.is_empty() && id.len() <= 64 && id.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then(|| id.to_owned())
}

pub(crate) fn extract_ray_id_from_headers(headers: &HeaderMap) -> Option<String> {
    extract_ray_id(headers.get("cf-ray").and_then(|value| value.to_str().ok()))
}

/// Emit any deferred 5xx server error log and inject `rayId` into JSON error
/// envelopes when `CF-Ray` was present on the request.
pub(crate) fn finalize_error_response(response: &mut Response, ray_id: Option<&str>, head: bool) {
    if let Some(PendingServerErrorLog(log_line)) = response.extensions_mut().remove() {
        match ray_id {
            Some(ray_id) => {
                log::error!(target: "api", "Application error [rayId={ray_id}]: {log_line}");
            }
            None => log::error!(target: "api", "Application error: {log_line}"),
        }
    }
    if let Some(ray_id) = ray_id
        && let Some(AttachRayId(mut map)) = response.extensions_mut().remove()
    {
        map.insert("rayId".to_owned(), Value::String(ray_id.to_owned()));
        if let Ok(bytes) = serde_json::to_vec(&Value::Object(map)) {
            if head {
                response
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, bytes.len().into());
            } else {
                response.headers_mut().remove(header::CONTENT_LENGTH);
                *response.body_mut() = Body::from(bytes);
            }
        }
    }
    if head {
        *response.body_mut() = Body::empty();
    }
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt as _;
    use serde_json::Value;

    use super::*;
    use crate::errors::{ConfigError, CryptoError, DatabaseError, JwtError};

    fn body(response: Response) -> (StatusCode, Vec<u8>) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .now_or_never()
            .expect("ready")
            .expect("valid body");
        (status, bytes.to_vec())
    }

    fn error_response(error: AppError) -> (StatusCode, Value) {
        let response = error.into_response();
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let (status, bytes) = body(response);
        (status, serde_json::from_slice(&bytes).expect("valid JSON"))
    }

    #[test]
    fn errors_preserve_statuses_codes_and_wire_envelopes() {
        for (error, status, code) in [
            (AppError::Params("bad".into()), 400, 9002),
            (AppError::bad_request("bad"), 400, 5),
            (AppError::conflict("stale"), 409, 6),
            (
                AppError::UnprocessableEntity {
                    message: "bad".into(),
                },
                422,
                7,
            ),
            (
                AppError::PayloadTooLarge {
                    message: "large".into(),
                },
                413,
                8,
            ),
            (
                AppError::UnsupportedMediaType {
                    message: "bad".into(),
                },
                415,
                16,
            ),
            (AppError::not_found("item"), 404, 10),
            (AppError::service_unavailable("down"), 503, 12),
            (
                AppError::TooManyRequests {
                    message: "wait".into(),
                },
                429,
                11,
            ),
            (
                AppError::Unauthorized {
                    message: "required".into(),
                },
                401,
                9003,
            ),
            (AppError::Jwt(JwtError::Expired), 401, 4),
            (AppError::Auth(AuthError::InvalidPassword), 401, 2),
            (AppError::Auth(AuthError::InsufficientPermissions), 403, 2),
            (AppError::Auth(AuthError::UserNotFound), 404, 2),
            (AppError::Auth(AuthError::InvalidKdf("bad".into())), 400, 2),
            (AppError::Config(ConfigError::Missing("DOMAIN")), 500, 0),
            (
                AppError::from(worker::Error::RustError("fail".into())),
                500,
                9001,
            ),
            (DatabaseError::query_failed("Failed", "SQLITE_BUSY"), 500, 1),
            (AppError::Crypto(CryptoError::HmacFailed("key")), 500, 3),
            (AppError::internal("state"), 500, 13),
            (AppError::upstream("empty"), 500, 15),
        ] {
            let (actual_status, payload) = error_response(error);
            assert_eq!(
                (actual_status.as_u16(), payload["code"].as_i64()),
                (status, Some(code))
            );
        }

        let ray = extract_ray_id(Some("a5f72d126a84fd0c-HKG"));
        assert_eq!(ray.as_deref(), Some("a5f72d126a84fd0c"));
        let mut resp = AppError::bad_request("Invalid").into_response();
        finalize_error_response(&mut resp, ray.as_deref(), false);
        let (_, get_bytes) = body(resp);
        let parsed: Value = serde_json::from_slice(&get_bytes).expect("json");
        assert_eq!(
            parsed,
            json!({"object":"error","code":5,"message":"Invalid request: Invalid","rayId":"a5f72d126a84fd0c"})
        );

        let mut head = AppError::bad_request("Invalid").into_response();
        finalize_error_response(&mut head, ray.as_deref(), true);
        assert_eq!(
            head.headers()[header::CONTENT_LENGTH],
            get_bytes.len().to_string()
        );
        assert_eq!(body(head).1, Vec::<u8>::new());

        let (_, oauth) = error_response(AppError::OAuth {
            error: "invalid_grant",
            description: "Invalid login",
        });
        assert_eq!(
            oauth,
            json!({"error":"invalid_grant","error_description":"Invalid login"})
        );
    }

    #[test]
    fn display_hides_internals_while_debug_keeps_diagnostics() {
        for (error, expected_display, secret_detail) in [
            (
                AppError::from(worker::Error::RustError("private platform".into())),
                "Worker runtime error: Cloudflare platform operation failed",
                "private platform",
            ),
            (
                AppError::r2_error(worker::Error::RustError("private r2".into())),
                "Worker runtime error: R2 object storage operation failed",
                "private r2",
            ),
            (
                DatabaseError::invalid_result("D1 row 1: private", "mismatch"),
                "Internal server error: Stored database record does not match expected schema",
                "private: mismatch",
            ),
            (
                AppError::internal_with_context("Failed to sign JWT token", "private key"),
                "Internal server error: Failed to sign JWT token",
                "private key",
            ),
        ] {
            assert_eq!(error.to_string(), expected_display);
            assert!(format!("{error:?}").contains(secret_detail));
            let (_, payload) = error_response(error);
            assert!(!payload.to_string().contains("private"));
        }
    }
}
