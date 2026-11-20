//! HS256 JWTs for service-issued claims with integer Unix-second timestamps.
//! Authentication, file and proof token purposes are validated by their
//! callers. Verification checks the MAC before interpreting the header or
//! claims.

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
const MAX_TOKEN_BYTES: usize = 10_240;
/// Maximum header/payload size after base64 decode (8KB)
const MAX_DECODED_BYTES: usize = 8_192;

// ============================================================================
// JWT Header
// ============================================================================

/// JWT Header as defined in RFC 7519
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    /// Algorithm used for signing (e.g., "HS256")
    #[serde(rename = "alg")]
    pub algorithm:  String,
    /// Token type (always "JWT")
    #[serde(rename = "typ")]
    pub token_type: String,
}

impl Default for JwtHeader {
    fn default() -> Self {
        Self {
            algorithm:  ALG_HS256.to_string(),
            token_type: JWT_TYPE.to_string(),
        }
    }
}

// ============================================================================
// Validation Options
// ============================================================================

/// Options for JWT validation
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Time leeway in seconds for exp/nbf/iat validation
    pub leeway_seconds:      i64,
    /// Whether to validate exp claim
    pub validate_expiration: bool,
    /// Whether to validate nbf claim
    pub validate_not_before: bool,
    /// Whether to validate iat claim (reject if issued in future)
    pub validate_issued_at:  bool,
    /// Expected issuer (if Some, validates iss claim)
    pub expected_issuer:     Option<String>,
    /// Expected audience (if Some, validates aud claim)
    pub expected_audience:   Option<String>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            leeway_seconds:      DEFAULT_LEEWAY_SECONDS,
            validate_expiration: true,
            validate_not_before: true,
            validate_issued_at:  false, // iat validation is optional
            expected_issuer:     None,
            expected_audience:   None,
        }
    }
}

// ============================================================================
// HMAC-SHA256 (Pure Rust - Synchronous)
// ============================================================================

/// Computes HMAC-SHA256 using pure Rust (synchronous, Send-safe)
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JwtError> {
    if key.is_empty() {
        return Err(JwtError::CryptoError(
            "JWT secret must not be empty".into(),
        ));
    }
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|e| {
            JwtError::CryptoError(format!("HMAC initialization failed: {e}"))
        })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ============================================================================
// Base64url Encoding/Decoding (RFC 7515)
// ============================================================================

/// Encodes bytes to base64url without padding
fn encode_base64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode the unpadded base64url form used by all issued tokens.
fn decode_base64url(input: &str) -> Result<Vec<u8>, JwtError> {
    // Check decoded size won't exceed limit (base64 expands ~33%)
    if input.len() > MAX_DECODED_BYTES * 4 / 3 {
        return Err(JwtError::TokenTooLarge);
    }

    let decoded = URL_SAFE_NO_PAD.decode(input).map_err(|e| {
        JwtError::InvalidFormat(format!("Invalid base64url: {e}"))
    })?;

    if decoded.len() > MAX_DECODED_BYTES {
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
    let header_b64 = encode_base64url(header_json.as_bytes());

    // Encode claims
    let claims_json = serde_json::to_string(claims).map_err(|e| {
        JwtError::JsonError(format!("Failed to serialize claims: {e}"))
    })?;
    if claims_json.len() > MAX_DECODED_BYTES {
        return Err(JwtError::TokenTooLarge);
    }
    let value: serde_json::Value = serde_json::from_str(&claims_json)
        .map_err(|e| JwtError::JsonError(e.to_string()))?;
    if !value.is_object() {
        return Err(JwtError::InvalidFormat(
            "JWT claims must be an object".into(),
        ));
    }
    let claims_b64 = encode_base64url(claims_json.as_bytes());

    // Create signing input
    let signing_input = format!("{header_b64}.{claims_b64}");

    // Compute signature using pure Rust HMAC-SHA256
    let signature = hmac_sha256(secret, signing_input.as_bytes())?;
    let signature_b64 = encode_base64url(&signature);

    // Combine into token
    let token = format!("{signing_input}.{signature_b64}");

    // Sanity check final token size
    if token.len() > MAX_TOKEN_BYTES {
        return Err(JwtError::TokenTooLarge);
    }

    debug!("JWT encoded for claims size={} bytes", claims_json.len());

    Ok(token)
}

// ============================================================================
// JWT Decoding & Validation
// ============================================================================

/// Decodes and validates a JWT token (synchronous)
pub fn decode<T: DeserializeOwned>(
    token: &str,
    secret: &[u8],
    options: &ValidationOptions,
) -> Result<T, JwtError> {
    // DOS protection: check token length first
    if token.len() > MAX_TOKEN_BYTES {
        return Err(JwtError::TokenTooLarge);
    }

    let mut parts = token.split('.');
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
    let provided_signature = decode_base64url(signature_b64)?;

    // CRITICAL: Use constant-time comparison to prevent timing attacks
    if !constant_time_eq(&expected_signature, &provided_signature) {
        warn!("JWT signature mismatch");
        return Err(JwtError::InvalidSignature);
    }

    // Only after signature is verified, decode and parse header
    let header_bytes = decode_base64url(header_b64)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| {
            JwtError::InvalidFormat(format!("Invalid header JSON: {e}"))
        })?;

    // CRITICAL: Validate algorithm to prevent "alg: none" attacks
    if header.algorithm != ALG_HS256 {
        return Err(JwtError::InvalidAlgorithm(header.algorithm.clone()));
    }

    // Decode claims
    let claims_bytes = decode_base64url(claims_b64)?;
    let claims: T = serde_json::from_slice(&claims_bytes).map_err(|e| {
        JwtError::JsonError(format!("Invalid claims JSON: {e}"))
    })?;

    // Parse claims as Value to validate time fields
    let claims_value: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|e| {
            JwtError::JsonError(format!("Invalid claims JSON: {e}"))
        })?;

    // Validate time-based claims
    let now = crate::utils::time::now_seconds();
    validate_time_claims(&claims_value, now, options)?;

    Ok(claims)
}

/// Validates time-based claims (exp, nbf, iat)
fn validate_time_claims(
    claims: &serde_json::Value,
    now: i64,
    options: &ValidationOptions,
) -> Result<(), JwtError> {
    if !claims.is_object() {
        return Err(JwtError::InvalidFormat(
            "JWT claims must be an object".into(),
        ));
    }
    if options.leeway_seconds < 0 {
        return Err(JwtError::InvalidFormat(
            "JWT leeway must not be negative".into(),
        ));
    }
    // A missing exp is an error whenever expiry validation is enabled. Older
    // attachment capabilities only include exp, so nbf/iat remain optional.
    let exp = numeric_date(claims, "exp", options.validate_expiration)?;
    let nbf = numeric_date(claims, "nbf", false)?;
    let iat = numeric_date(claims, "iat", false)?;
    let now = i128::from(now);
    let leeway_seconds = i128::from(options.leeway_seconds);
    if options.validate_expiration &&
        exp.is_some_and(|exp| now >= i128::from(exp) + leeway_seconds)
    {
        return Err(JwtError::Expired);
    }
    if options.validate_not_before &&
        nbf.is_some_and(|nbf| now < i128::from(nbf) - leeway_seconds)
    {
        return Err(JwtError::NotYetValid);
    }
    if options.validate_issued_at &&
        iat.is_some_and(|iat| i128::from(iat) > now + leeway_seconds)
    {
        return Err(JwtError::IssuedInFuture);
    }

    // Validate iss (issuer) if expected
    if let Some(ref expected_issuer) = options.expected_issuer {
        let iss = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwtError::MissingClaim("iss".to_string()))?;
        if iss != expected_issuer {
            return Err(JwtError::InvalidFormat(format!(
                "Issuer mismatch: expected {expected_issuer}, got {iss}"
            )));
        }
    }

    // Validate aud (audience) if expected
    if let Some(ref expected_audience) = options.expected_audience {
        let aud = claims
            .get("aud")
            .ok_or_else(|| JwtError::MissingClaim("aud".into()))?;
        let matches = if let Some(aud) = aud.as_str() {
            aud == expected_audience
        } else if let Some(aud) = aud.as_array() {
            aud.iter().all(serde_json::Value::is_string) &&
                aud.iter()
                    .any(|value| value.as_str() == Some(expected_audience))
        } else {
            false
        };
        if !matches {
            return Err(JwtError::InvalidFormat("Audience mismatch".into()));
        }
    }

    Ok(())
}

fn numeric_date(
    claims: &serde_json::Value,
    name: &str,
    required: bool,
) -> Result<Option<i64>, JwtError> {
    match claims.get(name) {
        None if required => Err(JwtError::MissingClaim(name.into())),
        None => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            JwtError::InvalidFormat(format!(
                "{name} must be an integer Unix timestamp"
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{
        Value,
        json,
    };

    use super::*;

    fn signed(header: &Value, claims: &Value) -> String {
        let header = encode_base64url(
            serde_json::to_string(header)
                .expect("test fixture should be valid")
                .as_bytes(),
        );
        let claims = encode_base64url(
            serde_json::to_string(claims)
                .expect("test fixture should be valid")
                .as_bytes(),
        );
        let signature = encode_base64url(
            &hmac_sha256(
                b"test-secret",
                format!("{header}.{claims}").as_bytes(),
            )
            .expect("test fixture should be valid"),
        );
        format!("{header}.{claims}.{signature}")
    }
    #[test]
    fn expiration_is_required_and_present_dates_cannot_bypass_validation_by_type()
     {
        assert!(
            matches!(validate_time_claims(&json!({}),100,&ValidationOptions::default()),Err(JwtError::MissingClaim(name)) if name=="exp")
        );
        for value in [
            json!(null),
            json!("200"),
            json!(true),
            json!(200.5),
            json!(u64::MAX),
        ] {
            assert!(
                validate_time_claims(
                    &json!({"exp":value}),
                    100,
                    &ValidationOptions::default()
                )
                .is_err()
            );
        }
        for name in ["nbf", "iat"] {
            for value in [json!(null), json!("past"), json!(false), json!(1.5)]
            {
                let mut claims = json!({"exp":200});
                claims[name] = value;
                assert!(
                    validate_time_claims(
                        &claims,
                        100,
                        &ValidationOptions::default()
                    )
                    .is_err()
                );
            }
        }
        validate_time_claims(
            &json!({"exp":200}),
            100,
            &ValidationOptions::default(),
        )
        .expect("test fixture should be valid");
    }
    #[test]
    fn numeric_date_extremes_and_skew_arithmetic_do_not_wrap_or_panic() {
        let options = ValidationOptions {
            leeway_seconds: 60,
            validate_issued_at: true,
            ..Default::default()
        };
        validate_time_claims(
            &json!({"exp":i64::MAX,"nbf":i64::MIN,"iat":i64::MIN}),
            i64::MAX - 61,
            &options,
        )
        .expect("test fixture should be valid");
        assert!(matches!(
            validate_time_claims(&json!({"exp":i64::MIN}), 0, &options),
            Err(JwtError::Expired)
        ));
        assert!(matches!(
            validate_time_claims(
                &json!({"exp":i64::MAX,"iat":i64::MAX}),
                0,
                &options
            ),
            Err(JwtError::IssuedInFuture)
        ));
        assert!(matches!(
            validate_time_claims(&json!({"exp":100}), 160, &options),
            Err(JwtError::Expired)
        ));
        assert!(matches!(
            validate_time_claims(&json!({"exp":500,"nbf":161}), 100, &options),
            Err(JwtError::NotYetValid)
        ));
        assert!(
            validate_time_claims(
                &json!({"exp":500}),
                100,
                &ValidationOptions {
                    leeway_seconds: -1,
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
    #[test]
    fn expiry_can_only_be_omitted_by_an_explicit_opt_out() {
        validate_time_claims(&json!({}), 100, &ValidationOptions {
            validate_expiration: false,
            ..Default::default()
        })
        .expect("test fixture should be valid");
        assert!(
            validate_time_claims(&json!([]), 100, &ValidationOptions {
                validate_expiration: false,
                ..Default::default()
            })
            .is_err()
        );
    }
    #[test]
    fn parser_rejects_wrong_alg_extra_segments_tampering_and_empty_keys() {
        let claims = json!({"exp":i64::MAX,"sub":"owner"});
        let valid = signed(&json!({"alg":"HS256","typ":"JWT"}), &claims);
        decode::<Value>(&valid, b"test-secret", &ValidationOptions::default())
            .expect("test fixture should be valid");
        for algorithm in ["none", "HS384", "RS256"] {
            let token = signed(&json!({"alg":algorithm,"typ":"JWT"}), &claims);
            assert!(matches!(
                decode::<Value>(
                    &token,
                    b"test-secret",
                    &ValidationOptions::default()
                ),
                Err(JwtError::InvalidAlgorithm(_))
            ));
        }
        for token in [format!("{valid}.extra"), "..".into(), "one.two".into()] {
            assert!(
                decode::<Value>(
                    &token,
                    b"test-secret",
                    &ValidationOptions::default()
                )
                .is_err()
            );
        }
        assert!(
            decode::<Value>(
                &valid,
                b"wrong-secret",
                &ValidationOptions::default()
            )
            .is_err()
        );
        assert!(
            decode::<Value>(&valid, b"", &ValidationOptions::default())
                .is_err()
        );
        assert!(encode(&claims, b"").is_err());
        assert!(encode(&json!([1, 2]), b"test-secret").is_err());
    }
    #[test]
    fn audience_strings_arrays_and_issuer_are_checked_without_cross_context_fallback()
     {
        let options = ValidationOptions {
            expected_issuer: Some("issuer".into()),
            expected_audience: Some("required".into()),
            ..Default::default()
        };
        for aud in [json!("required"), json!(["other", "required"])] {
            validate_time_claims(
                &json!({"exp":500,"iss":"issuer","aud":aud}),
                100,
                &options,
            )
            .expect("test fixture should be valid");
        }
        for aud in [json!(null), json!("wrong"), json!(["required", 7])] {
            assert!(
                validate_time_claims(
                    &json!({"exp":500,"iss":"issuer","aud":aud}),
                    100,
                    &options
                )
                .is_err()
            );
        }
        assert!(
            validate_time_claims(
                &json!({"exp":500,"iss":"other","aud":"required"}),
                100,
                &options
            )
            .is_err()
        );
    }
}
