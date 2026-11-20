//! HTTP status and JSON serialization for application failures.
use axum::{
    Json,
    http::StatusCode,
    response::{
        IntoResponse,
        Response,
    },
};
use bizerror::BizError as _;
use serde_json::json;

use super::{
    AppError,
    AuthError,
};

const fn status_code(error: &AppError) -> StatusCode {
    match error {
        AppError::Params(_) |
        AppError::BadRequest { .. } |
        AppError::OAuth { .. } |
        AppError::IdentityChallenge(_) => StatusCode::BAD_REQUEST,
        AppError::Conflict { .. } => StatusCode::CONFLICT,
        AppError::UnprocessableEntity { .. } => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        AppError::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        AppError::NotFound { .. } => StatusCode::NOT_FOUND,
        AppError::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
        AppError::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        AppError::Unauthorized { .. } | AppError::Jwt(_) => {
            StatusCode::UNAUTHORIZED
        }
        AppError::Auth(error) => match error {
            AuthError::InvalidCredentials(_) |
            AuthError::InvalidPassword |
            AuthError::MissingToken |
            AuthError::InvalidTotp => StatusCode::UNAUTHORIZED,
            AuthError::InsufficientPermissions | AuthError::AccountLocked => {
                StatusCode::FORBIDDEN
            }
            AuthError::InvalidKdf(_) => StatusCode::BAD_REQUEST,
            AuthError::UserNotFound => StatusCode::NOT_FOUND,
        },
        AppError::Config(_) |
        AppError::Worker(_) |
        AppError::Database(_) |
        AppError::Crypto(_) |
        AppError::Upstream(_) |
        AppError::InternalFailure(_) |
        AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Dependency failures are already logged at their boundary with a
        // bounded warning; avoid a second message on every rejected attempt.
        if !matches!(self, Self::ServiceUnavailable) {
            log::error!(target: "api", "Application error: {self}");
        }
        let status = status_code(&self);
        let code = self.code();
        let body = match self {
            Self::OAuth { error, description } => json!({
                "error": error, "error_description": description,
            }),
            Self::IdentityChallenge(value) => value,
            error => {
                let message = if status.is_server_error() {
                    "Internal server error".to_owned()
                } else {
                    error.to_string()
                };
                json!({
                    "data": null, "msg": message, "code": code,
                    "message": message,
                    "errorModel": { "message": message, "object": "error" },
                    "validationErrors": { "": [message] },
                    "error": "", "error_description": "",
                    "exceptionMessage": null, "exceptionStackTrace": null,
                    "innerExceptionMessage": null, "object": "error",
                })
            }
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future as _,
        task::{
            Context,
            Poll,
            Waker,
        },
    };

    use serde_json::Value;

    use super::*;
    use crate::errors::{
        ConfigError,
        CryptoError,
        DatabaseError,
        JwtError,
    };

    fn body(response: Response) -> (StatusCode, Vec<u8>) {
        let status = response.status();
        let mut body = std::pin::pin!(axum::body::to_bytes(
            response.into_body(),
            usize::MAX
        ));
        let Poll::Ready(bytes) =
            body.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        else {
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
    fn errors_preserve_http_statuses() {
        let cases = [
            (AppError::Params("bad".into()), 400),
            (AppError::bad_request("bad"), 400),
            (AppError::conflict("stale"), 409),
            (
                AppError::UnprocessableEntity {
                    message: "bad".into(),
                },
                422,
            ),
            (
                AppError::PayloadTooLarge {
                    message: "large".into(),
                },
                413,
            ),
            (AppError::not_found("item"), 404),
            (AppError::ServiceUnavailable, 503),
            (
                AppError::TooManyRequests {
                    message: "wait".into(),
                },
                429,
            ),
            (
                AppError::Unauthorized {
                    message: "required".into(),
                },
                401,
            ),
            (AppError::Jwt(JwtError::Expired), 401),
            (AppError::Auth(AuthError::MissingToken), 401),
            (
                AppError::Auth(AuthError::InvalidCredentials("bad".into())),
                401,
            ),
            (AppError::Auth(AuthError::InvalidPassword), 401),
            (AppError::Auth(AuthError::InvalidTotp), 401),
            (AppError::Auth(AuthError::InsufficientPermissions), 403),
            (AppError::Auth(AuthError::AccountLocked), 403),
            (AppError::Auth(AuthError::UserNotFound), 404),
            (AppError::Auth(AuthError::InvalidKdf("bad".into())), 400),
            (
                AppError::Config(ConfigError::Missing("binding".into())),
                500,
            ),
            (
                AppError::Worker(worker::Error::RustError("failure".into())),
                500,
            ),
            (
                AppError::Database(DatabaseError::QueryFailed(
                    "failure".into(),
                )),
                500,
            ),
            (AppError::Crypto(CryptoError::HashFailed("hash setup")), 500),
            (AppError::Internal, 500),
        ];
        for (error, expected) in cases {
            assert_eq!(error.into_response().status().as_u16(), expected);
        }
    }

    #[test]
    fn ordinary_errors_keep_the_legacy_and_bitwarden_fields_and_explicit_code()
    {
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
            AppError::Worker(worker::Error::RustError(
                "private platform error".into(),
            )),
            AppError::Database(DatabaseError::QueryFailed(
                "private SQL".into(),
            )),
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
            error:       "invalid_grant",
            description: "Invalid login",
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            value,
            json!({"error":"invalid_grant","error_description":"Invalid login"})
        );

        let challenge = json!({"error":"invalid_grant","TwoFactorProviders2":{"7":{"challenge":"opaque"}}});
        let (status, value) =
            error_response(AppError::IdentityChallenge(challenge.clone()));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value, challenge);
    }
}
