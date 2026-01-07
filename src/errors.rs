use axum::http::StatusCode;
use bizerror::*;
use serde_json::{
    Map,
    Value,
    json,
};
use thiserror::Error as ThisError;

// ============================================================================
// Public Result Alias
// ============================================================================

pub type AppResult<T> = Result<T, AppError>;

// ============================================================================
// Main Application Error
// ============================================================================

#[derive(ThisError, BizError)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[bizcode(9001)]
    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[bizcode(9002)]
    #[error("Invalid query parameters: {0}")]
    Params(String),

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[bizcode(9003)]
    #[error("Unauthorized: {message}")]
    Unauthorized { message: String },

    #[error(transparent)]
    Auth(#[from] AuthError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Jwt(#[from] JwtError),

    #[error("Invalid request: {message}")]
    BadRequest { message: String },

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Rate limit exceeded")]
    TooManyRequests { message: String },

    #[error("Internal server error")]
    Internal,

    #[bizcode(3110)]
    #[error("Two factor authentication required")]
    TwoFactorRequired(Box<[i32]>),
}

#[derive(ThisError, BizError)]
#[bizconfig(auto_start = 1000, auto_increment = 1)]
pub enum ConfigError {
    #[error("Missing config: {0}")]
    Missing(String),
}

#[derive(ThisError, BizError)]
#[bizconfig(auto_start = 2000, auto_increment = 1)]
pub enum DatabaseError {
    #[error("Query failed: {0}")]
    QueryFailed(String),
}

#[derive(ThisError, BizError)]
#[bizconfig(auto_start = 3000, auto_increment = 1)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    #[error("Account locked")]
    AccountLocked,

    #[error("Missing token")]
    MissingToken,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Invalid KDF parameters : {0}")]
    InvalidKDF(String),

    #[error("Invalid TOTP code")]
    InvalidTotp,
}

#[derive(ThisError, BizError)]
#[bizconfig(auto_start = 4000, auto_increment = 1)]
pub enum CryptoError {
    #[error("PBKDF2 key derivation failed")]
    Pbkdf2Failed,
    #[error("HMAC computation failed")]
    HmacFailed,
    #[error("Random value generation failed")]
    RandomGenerationFailed,
    #[error("Hashing operation failed")]
    HashFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Invalid Base32 encoding")]
    InvalidBase32,
}

#[derive(ThisError, BizError)]
#[bizconfig(auto_start = 5000, auto_increment = 1)]
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
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest {
            message: msg.into(),
        }
    }

    pub fn not_found(res: impl Into<String>) -> Self {
        Self::NotFound {
            resource: res.into(),
        }
    }

    pub fn twofactor_json(providers: &[i32]) -> Value {
        let providers2: Map<String, Value> = providers
            .iter()
            .map(|p| (p.to_string(), Value::Null))
            .collect();

        json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": providers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": {
                "Object": "masterPasswordPolicy"
            }
        })
    }
}

/// HTTP status code mapping for different error types
pub trait HttpStatusMapping {
    fn http_status_code(&self) -> StatusCode;
}

impl HttpStatusMapping for AppError {
    fn http_status_code(&self) -> StatusCode {
        match self {
            Self::Params(_) |
            Self::BadRequest { .. } |
            Self::TwoFactorRequired(_) => StatusCode::BAD_REQUEST,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Unauthorized { .. } | Self::Jwt(_) => {
                StatusCode::UNAUTHORIZED
            }
            Self::Auth(auth_err) => auth_err.http_status_code(),
            Self::Config(_) |
            Self::Worker(_) |
            Self::Database(_) |
            Self::Crypto(_) |
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl HttpStatusMapping for AuthError {
    fn http_status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentials(_) |
            Self::InvalidPassword |
            Self::MissingToken |
            Self::InvalidTotp => StatusCode::UNAUTHORIZED,
            Self::InsufficientPermissions | Self::AccountLocked => {
                StatusCode::FORBIDDEN
            }
            Self::InvalidKDF(_) => StatusCode::BAD_REQUEST,
            Self::UserNotFound => StatusCode::NOT_FOUND,
        }
    }
}

impl From<AppError> for worker::Error {
    fn from(err: AppError) -> Self {
        Self::RustError(err.to_string())
    }
}
