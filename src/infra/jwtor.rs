//! Custom JWT (JSON Web Token) implementation for Cloudflare Workers
//!
//! This module implements RFC 7519 compliant JWT encoding/decoding without
//! external JWT libraries. Uses pure Rust HMAC-SHA256 for synchronous signing
//! (compatible with Axum extractors).
//!
//! ## Security Features
//! - Constant-time signature comparison to prevent timing attacks
//! - Strict algorithm validation (only HS256 supported, rejects "none")
//! - Time-based claims validation (exp, nbf, iat) with configurable leeway
//! - Base64url encoding without padding for RFC compliance
//! - Token length limits to prevent `DoS` attacks
//! - Secure secret handling with minimal memory exposure

use base64::{
    Engine,
    engine::general_purpose::URL_SAFE_NO_PAD,
};
use constant_time_eq::constant_time_eq;
use hmac::{
    Hmac,
    Mac,
};
use log::{
    debug,
    warn,
};
use serde::{
    Deserialize,
    Serialize,
    de::DeserializeOwned,
};
use sha2::Sha256;

use crate::errors::JwtError;

// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// Constants
// ============================================================================

/// JWT token type
const JWT_TYPE: &str = "JWT";
/// Supported signing algorithm
const ALG_HS256: &str = "HS256";
/// Default time leeway in seconds for exp/nbf validation
const DEFAULT_LEEWAY_SECONDS: i64 = 60;
/// Maximum token length (10KB) to prevent `DoS`
const MAX_TOKEN_LENGTH: usize = 10_240;
/// Maximum header/payload size after base64 decode (8KB)
const MAX_DECODED_SIZE: usize = 8_192;

// ============================================================================
// Error Types
// ============================================================================

// ============================================================================
// JWT Header & Standard Claims
// ============================================================================

/// JWT Header as defined in RFC 7519
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    /// Algorithm used for signing (e.g., "HS256")
    pub alg: String,
    /// Token type (always "JWT")
    pub typ: String,
}

impl Default for JwtHeader {
    fn default() -> Self {
        Self {
            alg: ALG_HS256.to_string(),
            typ: JWT_TYPE.to_string(),
        }
    }
}

/// Standard JWT claims as defined in RFC 7519
/// These fields are optional in the standard but commonly used
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StandardClaims {
    /// Subject (user ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Expiration time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Not before time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued at time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

// ============================================================================
// Validation Options
// ============================================================================

/// Options for JWT validation
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Time leeway in seconds for exp/nbf/iat validation
    pub leeway:       i64,
    /// Whether to validate exp claim
    pub validate_exp: bool,
    /// Whether to validate nbf claim
    pub validate_nbf: bool,
    /// Whether to validate iat claim (reject if issued in future)
    pub validate_iat: bool,
    /// Expected issuer (if Some, validates iss claim)
    pub expected_iss: Option<String>,
    /// Expected audience (if Some, validates aud claim)
    pub expected_aud: Option<String>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            leeway:       DEFAULT_LEEWAY_SECONDS,
            validate_exp: true,
            validate_nbf: true,
            validate_iat: false, // iat validation is optional
            expected_iss: None,
            expected_aud: None,
        }
    }
}

// ============================================================================
// HMAC-SHA256 (Pure Rust - Synchronous)
// ============================================================================

/// Computes HMAC-SHA256 using pure Rust (synchronous, Send-safe)
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| {
        JwtError::CryptoError(format!("HMAC initialization failed: {e}"))
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ============================================================================
// Base64url Encoding/Decoding (RFC 7515)
// ============================================================================

/// Encodes bytes to base64url without padding
fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64url (with or without padding) to bytes with size limit
fn base64url_decode(input: &str) -> Result<Vec<u8>, JwtError> {
    // Check decoded size won't exceed limit (base64 expands ~33%)
    if input.len() > MAX_DECODED_SIZE * 4 / 3 {
        return Err(JwtError::TokenTooLarge);
    }

    let decoded = URL_SAFE_NO_PAD.decode(input).map_err(|e| {
        JwtError::InvalidFormat(format!("Invalid base64url: {e}"))
    })?;

    if decoded.len() > MAX_DECODED_SIZE {
        return Err(JwtError::TokenTooLarge);
    }

    Ok(decoded)
}

// ============================================================================
// JWT Encoding
// ============================================================================

/// Encodes claims into a JWT token string (synchronous)
pub fn encode<T: Serialize>(
    claims: &T,
    secret: &[u8],
) -> Result<String, JwtError> {
    // Create header
    let header = JwtHeader::default();
    let header_json = serde_json::to_string(&header).map_err(|e| {
        JwtError::JsonError(format!("Failed to serialize header: {e}"))
    })?;
    let header_b64 = base64url_encode(header_json.as_bytes());

    // Encode claims
    let claims_json = serde_json::to_string(claims).map_err(|e| {
        JwtError::JsonError(format!("Failed to serialize claims: {e}"))
    })?;
    let claims_b64 = base64url_encode(claims_json.as_bytes());

    // Create signing input
    let signing_input = format!("{header_b64}.{claims_b64}");

    // Compute signature using pure Rust HMAC-SHA256
    let signature = hmac_sha256(secret, signing_input.as_bytes())?;
    let signature_b64 = base64url_encode(&signature);

    // Combine into token
    let token = format!("{signing_input}.{signature_b64}");

    // Sanity check final token size
    if token.len() > MAX_TOKEN_LENGTH {
        return Err(JwtError::TokenTooLarge);
    }

    debug!("JWT encoded for claims size={} bytes", claims_json.len());

    Ok(token)
}

// ============================================================================
// JWT Decoding & Validation
// ============================================================================

/// Decoded and verified token data
#[derive(Debug)]
pub struct TokenData<T> {
    pub header: JwtHeader,
    pub claims: T,
}

/// Decodes and validates a JWT token (synchronous)
pub fn decode<T: DeserializeOwned>(
    token: &str,
    secret: &[u8],
    options: &ValidationOptions,
) -> Result<TokenData<T>, JwtError> {
    // DOS protection: check token length first
    if token.len() > MAX_TOKEN_LENGTH {
        return Err(JwtError::TokenTooLarge);
    }

    // Split token into parts (use splitn for efficiency)
    let mut parts = token.splitn(3, '.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| JwtError::InvalidFormat("Missing header".to_string()))?;
    let claims_b64 = parts.next().ok_or_else(|| {
        JwtError::InvalidFormat("Missing payload".to_string())
    })?;
    let signature_b64 = parts.next().ok_or_else(|| {
        JwtError::InvalidFormat("Missing signature".to_string())
    })?;

    // Ensure there are no extra parts
    if parts.next().is_some() {
        return Err(JwtError::InvalidFormat(
            "Token has more than 3 parts".to_string(),
        ));
    }

    // Validate parts are not empty
    if header_b64.is_empty() ||
        claims_b64.is_empty() ||
        signature_b64.is_empty()
    {
        return Err(JwtError::InvalidFormat("Empty token parts".to_string()));
    }

    // SECURITY: Verify signature BEFORE parsing any untrusted data
    let signing_input = format!("{header_b64}.{claims_b64}");
    let expected_signature = hmac_sha256(secret, signing_input.as_bytes())?;
    let provided_signature = base64url_decode(signature_b64)?;

    // CRITICAL: Use constant-time comparison to prevent timing attacks
    if !constant_time_eq(&expected_signature, &provided_signature) {
        warn!("JWT signature mismatch");
        return Err(JwtError::InvalidSignature);
    }

    // Only after signature is verified, decode and parse header
    let header_bytes = base64url_decode(header_b64)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| {
            JwtError::InvalidFormat(format!("Invalid header JSON: {e}"))
        })?;

    // CRITICAL: Validate algorithm to prevent "alg: none" attacks
    if header.alg != ALG_HS256 {
        return Err(JwtError::InvalidAlgorithm(header.alg.clone()));
    }

    // Decode claims
    let claims_bytes = base64url_decode(claims_b64)?;
    let claims: T = serde_json::from_slice(&claims_bytes).map_err(|e| {
        JwtError::JsonError(format!("Invalid claims JSON: {e}"))
    })?;

    // Parse claims as Value to validate time fields
    let claims_value: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|e| {
            JwtError::JsonError(format!("Invalid claims JSON: {e}"))
        })?;

    // Validate time-based claims
    let now = chrono::Utc::now().timestamp();
    validate_time_claims(&claims_value, now, options)?;

    Ok(TokenData { header, claims })
}

/// Validates time-based claims (exp, nbf, iat)
fn validate_time_claims(
    claims: &serde_json::Value,
    now: i64,
    options: &ValidationOptions,
) -> Result<(), JwtError> {
    // Validate exp (expiration) - RFC 7519: "on or after" means >= is expired
    if options.validate_exp &&
        let Some(exp) = claims.get("exp").and_then(serde_json::Value::as_i64) &&
        now >= exp + options.leeway
    {
        return Err(JwtError::Expired);
    }

    // Validate nbf (not before) - RFC 7519: "before" means < is not yet valid
    if options.validate_nbf &&
        let Some(nbf) = claims.get("nbf").and_then(serde_json::Value::as_i64) &&
        now < nbf - options.leeway
    {
        return Err(JwtError::NotYetValid);
    }

    // Validate iat (issued at) - reject if issued in the future
    if options.validate_iat &&
        let Some(iat) = claims.get("iat").and_then(serde_json::Value::as_i64) &&
        iat > now + options.leeway
    {
        return Err(JwtError::IssuedInFuture);
    }

    // Validate iss (issuer) if expected
    if let Some(ref expected_iss) = options.expected_iss {
        let iss = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwtError::MissingClaim("iss".to_string()))?;
        if iss != expected_iss {
            return Err(JwtError::InvalidFormat(format!(
                "Issuer mismatch: expected {expected_iss}, got {iss}"
            )));
        }
    }

    // Validate aud (audience) if expected
    if let Some(ref expected_aud) = options.expected_aud {
        let aud = claims
            .get("aud")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwtError::MissingClaim("aud".to_string()))?;
        if aud != expected_aud {
            return Err(JwtError::InvalidFormat(format!(
                "Audience mismatch: expected {expected_aud}, got {aud}"
            )));
        }
    }

    Ok(())
}