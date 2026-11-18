use bizerror::BizError;
use serde_json::Value;
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

    #[error("Conflict: {message}")]
    Conflict { message: String },

    #[error("Unprocessable entity: {message}")]
    UnprocessableEntity { message: String },

    #[error("Payload too large: {message}")]
    PayloadTooLarge { message: String },

    #[error("OAuth error {error}: {description}")]
    OAuth {
        error:       &'static str,
        description: &'static str,
    },

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Rate limit exceeded")]
    TooManyRequests { message: String },

    #[error("Internal server error")]
    Internal,

    #[bizcode(3110)]
    #[error("Two factor authentication required")]
    TwoFactorRequired(Box<[i32]>),

    #[error("Additional identity verification required")]
    IdentityChallenge(Value),
}

#[derive(ThisError, BizError)]
#[bizconfig(auto_start = 1000, auto_increment = 1)]
pub enum ConfigError {
    #[error("Missing config: {0}")]
    Missing(String),
    #[error("Invalid config: {0}")]
    Invalid(String),
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

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }
}

impl From<AppError> for worker::Error {
    fn from(err: AppError) -> Self {
        Self::RustError(err.to_string())
    }
}
