//! HTTP status and JSON serialization for application failures.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::{AppError, AuthError};

enum ErrorBody {
    Legacy {
        message: String,
        oauth_error: &'static str,
        description: std::borrow::Cow<'static, str>,
    },
    OAuth {
        error: &'static str,
        description: &'static str,
    },
    IdentityChallenge(serde_json::Value),
}

struct ErrorSpec {
    status: StatusCode,
    body: ErrorBody,
    code: u32,
}

impl ErrorSpec {
    fn legacy(error: &AppError, status: StatusCode, code: u32) -> Self {
        let message = if status.is_server_error() {
            if !matches!(error, AppError::ServiceUnavailable) {
                log::error!(target: "api", "Application error: {error}");
            }
            "Internal server error".to_owned()
        } else {
            error.to_string()
        };
        Self {
            status,
            body: ErrorBody::Legacy {
                message,
                oauth_error: "",
                description: "".into(),
            },
            code,
        }
    }

    fn oauth_legacy(
        error: &AppError,
        code: u32,
        oauth_error: &'static str,
        description: std::borrow::Cow<'static, str>,
    ) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: ErrorBody::Legacy {
                message: error.to_string(),
                oauth_error,
                description,
            },
            code,
        }
    }
}

impl AppError {
    /// The numeric client codes are independent of enum layout.
    fn into_spec(self) -> ErrorSpec {
        use StatusCode as Status;

        let (status, code) = match self {
            Self::OAuth { error, description } => {
                return ErrorSpec {
                    status: Status::BAD_REQUEST,
                    code: 9,
                    body: ErrorBody::OAuth { error, description },
                };
            }
            Self::IdentityChallenge(value) => {
                return ErrorSpec {
                    status: Status::BAD_REQUEST,
                    code: 14,
                    body: ErrorBody::IdentityChallenge(value),
                };
            }
            Self::InvalidTokenRequest { ref message } => {
                return ErrorSpec::oauth_legacy(&self, 5, "invalid_request", message.clone());
            }
            Self::InvalidTokenParams(ref message) => {
                return ErrorSpec::oauth_legacy(&self, 9002, "invalid_request", message.clone());
            }
            Self::UnsupportedGrantType => {
                return ErrorSpec::oauth_legacy(
                    &self,
                    9002,
                    "unsupported_grant_type",
                    "Unsupported grant_type".into(),
                );
            }
            Self::Params(_) => (Status::BAD_REQUEST, 9002),
            Self::BadRequest { .. } => (Status::BAD_REQUEST, 5),
            Self::Conflict { .. } => (Status::CONFLICT, 6),
            Self::UnprocessableEntity { .. } => (Status::UNPROCESSABLE_ENTITY, 7),
            Self::PayloadTooLarge { .. } => (Status::PAYLOAD_TOO_LARGE, 8),
            Self::NotFound { .. } => (Status::NOT_FOUND, 10),
            Self::TooManyRequests { .. } => (Status::TOO_MANY_REQUESTS, 11),
            Self::ServiceUnavailable => (Status::SERVICE_UNAVAILABLE, 12),
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
            Self::Worker(_) => (Status::INTERNAL_SERVER_ERROR, 9001),
            Self::Database(_) => (Status::INTERNAL_SERVER_ERROR, 1),
            Self::Crypto(_) => (Status::INTERNAL_SERVER_ERROR, 3),
            Self::Upstream(_) => (Status::INTERNAL_SERVER_ERROR, 15),
            Self::InternalFailure(_) | Self::Internal => (Status::INTERNAL_SERVER_ERROR, 13),
        };
        ErrorSpec::legacy(&self, status, code)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let ErrorSpec { status, body, code } = self.into_spec();
        let body = match body {
            ErrorBody::OAuth { error, description } => json!({
                "error": error, "error_description": description,
            }),
            ErrorBody::IdentityChallenge(value) => value,
            ErrorBody::Legacy {
                message,
                oauth_error,
                description,
            } => json!({
                "data": null, "msg": message, "code": code,
                "message": message,
                "errorModel": { "message": message, "object": "error" },
                "validationErrors": { "": [message] },
                "error": oauth_error, "error_description": description,
                "exceptionMessage": null, "exceptionStackTrace": null,
                "innerExceptionMessage": null, "object": "error",
            }),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future as _,
        task::{Context, Poll, Waker},
    };

    use serde_json::Value;

    use super::*;
    use crate::errors::{ConfigError, CryptoError, DatabaseError, JwtError};

    fn body(response: Response) -> (StatusCode, Vec<u8>) {
        let status = response.status();
        let mut body = std::pin::pin!(axum::body::to_bytes(response.into_body(), usize::MAX));
        let Poll::Ready(bytes) = body.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
            panic!("fixed JSON/string responses must be ready without I/O");
        };
        (status, bytes.expect("valid response fixture").to_vec())
    }

    fn error_response(error: AppError) -> (StatusCode, Value) {
        let response = error.into_response();
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/json"
        );
        let (status, bytes) = body(response);
        (
            status,
            serde_json::from_slice(&bytes).expect("valid response fixture"),
        )
    }

    #[test]
    fn errors_preserve_http_statuses_and_codes() {
        let cases = [
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
            (AppError::not_found("item"), 404, 10),
            (AppError::ServiceUnavailable, 503, 12),
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
            (AppError::Auth(AuthError::MissingToken), 401, 2),
            (
                AppError::Auth(AuthError::InvalidCredentials("bad".into())),
                401,
                2,
            ),
            (AppError::Auth(AuthError::InvalidPassword), 401, 2),
            (AppError::Auth(AuthError::InvalidTotp), 401, 2),
            (AppError::Auth(AuthError::InsufficientPermissions), 403, 2),
            (AppError::Auth(AuthError::AccountLocked), 403, 2),
            (AppError::Auth(AuthError::UserNotFound), 404, 2),
            (AppError::Auth(AuthError::InvalidKdf("bad".into())), 400, 2),
            (
                AppError::Config(ConfigError::Missing("binding".into())),
                500,
                0,
            ),
            (
                AppError::Worker(worker::Error::RustError("failure".into())),
                500,
                9001,
            ),
            (
                AppError::Database(DatabaseError::QueryFailed("failure".into())),
                500,
                1,
            ),
            (
                AppError::Crypto(CryptoError::HashFailed("hash setup")),
                500,
                3,
            ),
            (AppError::Internal, 500, 13),
            (AppError::Upstream("unavailable".into()), 500, 15),
        ];
        for (error, expected_status, expected_code) in cases {
            let (status, body) = error_response(error);
            assert_eq!(status.as_u16(), expected_status);
            assert_eq!(body["code"], expected_code);
        }
    }

    #[test]
    fn throttled_responses_keep_the_retry_guidance() {
        let message = "Wait 60 seconds before requesting another code";
        let (status, body) = error_response(AppError::TooManyRequests {
            message: message.into(),
        });
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["message"], message);
        assert_eq!(body["msg"], message);
    }

    #[test]
    fn ordinary_errors_keep_the_legacy_and_bitwarden_fields_and_explicit_code() {
        let (status, value) = error_response(AppError::Unauthorized {
            message: "required".into(),
        });
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            value,
            json!({
                "data": null, "msg": "Unauthorized: required", "code": 9003,
                "message": "Unauthorized: required",
                "errorModel": { "message": "Unauthorized: required", "object": "error" },
                "validationErrors": { "": ["Unauthorized: required"] },
                "error": "", "error_description": "",
                "exceptionMessage": null, "exceptionStackTrace": null,
                "innerExceptionMessage": null, "object": "error",
            })
        );
    }

    #[test]
    fn server_error_responses_never_expose_internal_context() {
        for error in [
            AppError::Config(ConfigError::Invalid("private config".into())),
            AppError::Worker(worker::Error::RustError("private platform error".into())),
            AppError::Database(DatabaseError::QueryFailed("private SQL".into())),
            AppError::Crypto(CryptoError::Pbkdf2Failed("private phase")),
        ] {
            let (status, value) = error_response(error);
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(value["message"], "Internal server error");
            assert!(!value.to_string().contains("private"));
        }
        let (status, value) = error_response(DatabaseError::invalid_result(
            "Invalid stored row",
            "private detail",
        ));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(value, error_response(AppError::Internal).1);
    }

    #[test]
    fn oauth_and_identity_challenges_retain_their_specific_wire_shapes() {
        let (status, value) = error_response(AppError::OAuth {
            error: "invalid_grant",
            description: "Invalid login",
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            value,
            json!({"error":"invalid_grant","error_description":"Invalid login"})
        );

        let challenge =
            json!({"error":"invalid_grant","TwoFactorProviders2":{"7":{"challenge":"opaque"}}});
        let (status, value) = error_response(AppError::IdentityChallenge(challenge.clone()));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value, challenge);
    }
}
