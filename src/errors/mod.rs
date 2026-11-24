use std::borrow::Cow;

use serde_json::Value;
use thiserror::Error;

mod database;
mod response;

pub(crate) use database::DbSentinel;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("Worker error: {}", database::worker_error_diagnostic(.0))]
    Worker(#[from] worker::Error),

    #[error("Invalid query parameters: {0}")]
    Params(Cow<'static, str>),

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error("Unauthorized: {message}")]
    Unauthorized { message: Cow<'static, str> },

    #[error(transparent)]
    Auth(#[from] AuthError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Jwt(#[from] JwtError),

    #[error("Invalid request: {message}")]
    BadRequest { message: Cow<'static, str> },

    #[error("Conflict: {message}")]
    Conflict { message: Cow<'static, str> },

    #[error("Unprocessable entity: {message}")]
    UnprocessableEntity { message: Cow<'static, str> },

    #[error("Payload too large: {message}")]
    PayloadTooLarge { message: Cow<'static, str> },

    #[error("OAuth error {error}: {description}")]
    OAuth {
        error: &'static str,
        description: &'static str,
    },

    #[error("Invalid request: {message}")]
    InvalidTokenRequest { message: Cow<'static, str> },

    #[error("Invalid query parameters: {0}")]
    InvalidTokenParams(Cow<'static, str>),

    #[error("Invalid query parameters: Unsupported grant_type")]
    UnsupportedGrantType,

    #[error("Resource not found: {resource}")]
    NotFound { resource: Cow<'static, str> },

    #[error("{message}")]
    TooManyRequests { message: Cow<'static, str> },

    #[error("Service temporarily unavailable")]
    ServiceUnavailable,

    #[error("Internal server error")]
    Internal,

    #[error("Additional identity verification required")]
    IdentityChallenge(Value),

    #[error("{0}")]
    Upstream(String),

    #[error("Internal server error: {0}")]
    InternalFailure(String),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing config: {0}")]
    Missing(String),
    #[error("Invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Query failed: {0}")]
    QueryFailed(String),
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials: {0}")]
    InvalidCredentials(Cow<'static, str>),

    #[error("Account locked")]
    AccountLocked,

    #[error("Missing token")]
    MissingToken,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Invalid KDF parameters : {0}")]
    InvalidKdf(Cow<'static, str>),

    #[error("Invalid TOTP code")]
    InvalidTotp,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("PBKDF2 key derivation failed: {0}")]
    Pbkdf2Failed(&'static str),
    #[error("HMAC computation failed: {0}")]
    HmacFailed(&'static str),
    #[error("Random value generation failed: {0}")]
    RandomGenerationFailed(&'static str),
    #[error("Hashing operation failed: {0}")]
    HashFailed(&'static str),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(&'static str),
    #[error("Invalid Base32 encoding")]
    InvalidBase32,
}

#[derive(Debug, Error)]
pub enum JwtError {
    /// Token format is invalid (not 3 parts, invalid base64, etc.)
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),
    /// Signature verification failed
    #[error("Invalid signature")]
    InvalidSignature,
    /// Token has expired (exp claim)
    #[error("Token has expired")]
    Expired,
    /// Token is not yet valid (nbf claim)
    #[error("Token is not yet valid")]
    NotYetValid,
    /// Token was issued in the future (iat claim)
    #[error("Token was issued in the future")]
    IssuedInFuture,
    /// Algorithm mismatch or unsupported algorithm
    #[error("Invalid or unsupported algorithm: {0}")]
    InvalidAlgorithm(String),
    /// Required claim is missing
    #[error("Missing required claim: {0}")]
    MissingClaim(String),
    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    JsonError(String),
    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    CryptoError(String),
    /// Token too large (`DoS` protection)
    #[error("Token exceeds maximum allowed size")]
    TokenTooLarge,
}

impl AppError {
    /// Discard details from failures that may contain sensitive values.
    pub(crate) fn internal_error<E>(_: E) -> Self {
        Self::Internal
    }

    pub(crate) fn internal_with_context(
        context: impl std::fmt::Display,
        error: impl std::fmt::Display,
    ) -> Self {
        Self::InternalFailure(format!("{context}: {error}"))
    }

    pub(crate) fn kv_error(error: impl std::fmt::Display) -> Self {
        worker_failure(format!("KV operation failed: {error}")).into()
    }

    pub(crate) fn upstream_error(error: impl std::fmt::Display) -> Self {
        Self::Upstream(error.to_string())
    }

    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    pub(crate) fn invalid_token_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::InvalidTokenRequest {
            message: message.into(),
        }
    }

    pub fn not_found(resource: impl Into<Cow<'static, str>>) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    pub fn conflict(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    pub(crate) fn send_unavailable() -> Self {
        Self::not_found("Send does not exist or is no longer available")
    }

    pub(crate) fn auth_request_unavailable() -> Self {
        Self::bad_request("Authentication request is unavailable")
    }

    pub(crate) fn invalid_credentials(message: impl Into<Cow<'static, str>>) -> Self {
        AuthError::InvalidCredentials(message.into()).into()
    }

    pub(crate) fn invalid_api_credentials() -> Self {
        Self::invalid_credentials("Invalid API credentials")
    }

    pub(crate) fn setup_authorization_required() -> Self {
        Self::Unauthorized {
            message: "Owner setup authorization is required".into(),
        }
    }
}

impl From<AppError> for worker::Error {
    fn from(error: AppError) -> Self {
        worker_failure(error.to_string())
    }
}

pub(crate) fn worker_failure(message: impl Into<String>) -> worker::Error {
    worker::Error::RustError(message.into())
}
