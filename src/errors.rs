use axum::{
    Json,
    http::StatusCode,
    response::{
        IntoResponse,
        Response,
    },
};
use serde_json::{
    Value,
    json,
};
use thiserror::Error;

/// Convenience type alias for Results returning `AppError`.
pub type AppResult<T> = Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[error("Database query failed")]
    Database,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("JSON Web Token error: {0}")]
    JsonWebToken(String),

    #[error("Internal server error")]
    Internal,

    #[error("Two factor authentication required")]
    TwoFactorRequired(Value),
}

/// Specific JWT error types for detailed error handling
#[derive(Error, Debug, Clone, PartialEq)]
pub enum JwtError {
    /// Token format is invalid (not 3 parts, invalid base64, etc.)
    InvalidFormat(String),
    /// Signature verification failed
    InvalidSignature,
    /// Token has expired (exp claim)
    Expired,
    /// Token is not yet valid (nbf claim)
    NotYetValid,
    /// Token was issued in the future (iat claim)
    IssuedInFuture,
    /// Algorithm mismatch or unsupported algorithm
    InvalidAlgorithm(String),
    /// Required claim is missing
    MissingClaim(String),
    /// JSON serialization/deserialization error
    JsonError(String),
    /// Cryptographic operation failed
    CryptoError(String),
    /// Token too large (`DoS` protection)
    TokenTooLarge,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(msg) => {
                write!(f, "Invalid token format: {msg}")
            }
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::Expired => write!(f, "Token has expired"),
            Self::NotYetValid => write!(f, "Token is not yet valid"),
            Self::IssuedInFuture => {
                write!(f, "Token was issued in the future")
            }
            Self::InvalidAlgorithm(alg) => {
                write!(f, "Invalid or unsupported algorithm: {alg}")
            }
            Self::MissingClaim(claim) => {
                write!(f, "Missing required claim: {claim}")
            }
            Self::JsonError(msg) => write!(f, "JSON error: {msg}"),
            Self::CryptoError(msg) => write!(f, "Crypto error: {msg}"),
            Self::TokenTooLarge => {
                write!(f, "Token exceeds maximum allowed size")
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::TwoFactorRequired(json_body) => {
                // Return 400 Bad Request with the 2FA required JSON response as
                // expected by clients
                (StatusCode::BAD_REQUEST, Json(json_body)).into_response()
            }
            other => {
                let (status, error_message) = match other {
                    Self::Config(msg) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Configuration error: {msg}"),
                    ),
                    Self::Worker(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Worker error: {e}"),
                    ),
                    Self::Database => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Database error".to_string(),
                    ),
                    Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
                    Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
                    Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
                    Self::TooManyRequests(msg) => {
                        (StatusCode::TOO_MANY_REQUESTS, msg)
                    }
                    Self::Crypto(msg) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Crypto error: {msg}"),
                    ),
                    Self::JsonWebToken(_) => {
                        (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
                    }
                    Self::Internal => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_string(),
                    ),
                    Self::TwoFactorRequired(_) => unreachable!(),
                };

                let body = Json(json!({ "error": error_message }));
                (status, body).into_response()
            }
        }
    }
}

impl From<AppError> for worker::Error {
    fn from(err: AppError) -> Self {
        Self::RustError(err.to_string())
    }
}
