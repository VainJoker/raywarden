use std::{borrow::Cow, fmt};

use serde_json::Value;
use thiserror::Error;

mod database;
mod response;

pub(crate) use database::DbSentinel;
pub(crate) use response::{extract_ray_id, extract_ray_id_from_headers, finalize_error_response};

pub type AppResult<T> = Result<T, AppError>;

/// Wraps `worker::Error` so `Debug` logs bounded D1 codes rather than raw JS/SQL causes.
pub struct WorkerSource(pub(super) worker::Error);

impl fmt::Debug for WorkerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        database::fmt_worker_debug(&self.0, f)
    }
}

impl fmt::Display for WorkerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&database::worker_display_message(None, &self.0))
    }
}

impl std::error::Error for WorkerSource {}

/// `Display` renders the safe client-facing message; `Debug` records server-only diagnostics.
#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("{}", database::worker_display_message(*summary, &source.0))]
    Worker {
        summary: Option<&'static str>,
        #[source]
        source: WorkerSource,
    },

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

    #[error("Unsupported media type: {message}")]
    UnsupportedMediaType { message: Cow<'static, str> },

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

    #[error("Service temporarily unavailable: {reason}")]
    ServiceUnavailable { reason: &'static str },

    #[error("Additional identity verification required")]
    IdentityChallenge(Value),

    #[error("Upstream service error: {summary}")]
    Upstream {
        summary: &'static str,
        detail: Option<String>,
    },

    #[error("Internal server error: {summary}")]
    Internal {
        summary: &'static str,
        detail: Option<String>,
    },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing config: {0}")]
    Missing(&'static str),
    #[error("Invalid config: {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Database query failed: {context} (D1: {d1_code})")]
    QueryFailed {
        context: &'static str,
        d1_code: &'static str,
    },
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

    #[error("Invalid KDF parameters: {0}")]
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
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(&'static str),
    #[error("Invalid Base32 encoding")]
    InvalidBase32,
}

#[derive(Debug, Error)]
pub enum JwtError {
    /// Token format is invalid (not 3 parts, invalid base64, etc.)
    #[error("Invalid token format: {0}")]
    InvalidFormat(&'static str),
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
    #[error("Unsupported token algorithm")]
    InvalidAlgorithm { algorithm: String },
    /// Required claim is missing
    #[error("Missing required claim: {0}")]
    MissingClaim(&'static str),
    /// JSON serialization/deserialization error
    #[error("Invalid token claims")]
    JsonError { detail: String },
    /// Cryptographic operation failed
    #[error("Token cryptographic verification failed")]
    CryptoError(&'static str),
    /// Token too large (`DoS` protection)
    #[error("Token exceeds maximum allowed size")]
    TokenTooLarge,
}

impl AppError {
    pub(crate) const fn internal(summary: &'static str) -> Self {
        Self::Internal {
            summary,
            detail: None,
        }
    }

    /// Discard a potentially sensitive error value while keeping a safe summary.
    pub(crate) const fn internal_discard<E>(summary: &'static str) -> impl FnOnce(E) -> Self {
        move |_| Self::internal(summary)
    }

    pub(crate) fn internal_debug(summary: &'static str, error: impl fmt::Debug) -> Self {
        Self::Internal {
            summary,
            detail: Some(format!("{error:?}")),
        }
    }

    pub(crate) fn internal_with_context(summary: &'static str, error: impl fmt::Display) -> Self {
        Self::Internal {
            summary,
            detail: Some(error.to_string()),
        }
    }

    /// Record Serde's structural error category and location in `Debug` without
    /// capturing potentially sensitive field values.
    pub(crate) const fn internal_json(
        summary: &'static str,
    ) -> impl FnOnce(serde_json::Error) -> Self {
        move |error| Self::Internal {
            summary,
            detail: Some(format!(
                "{:?} at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            )),
        }
    }

    pub(crate) const fn service_unavailable(reason: &'static str) -> Self {
        Self::ServiceUnavailable { reason }
    }

    pub(crate) const fn worker_with_context(summary: &'static str, error: worker::Error) -> Self {
        Self::Worker {
            summary: Some(summary),
            source: WorkerSource(error),
        }
    }

    pub(crate) const fn r2_error(error: worker::Error) -> Self {
        Self::worker_with_context("R2 object storage operation failed", error)
    }

    pub(crate) const fn upstream(summary: &'static str) -> Self {
        Self::Upstream {
            summary,
            detail: None,
        }
    }

    pub(crate) fn upstream_with_context(summary: &'static str, error: impl fmt::Display) -> Self {
        Self::Upstream {
            summary,
            detail: Some(error.to_string()),
        }
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

impl From<worker::Error> for AppError {
    fn from(source: worker::Error) -> Self {
        Self::Worker {
            summary: None,
            source: WorkerSource(source),
        }
    }
}

impl From<AppError> for worker::Error {
    fn from(error: AppError) -> Self {
        worker_failure(format!("{error:?}"))
    }
}

pub(crate) fn worker_failure(message: impl Into<String>) -> worker::Error {
    worker::Error::RustError(message.into())
}
