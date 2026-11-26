//! HS256 JWTs for service-issued claims with integer Unix-second timestamps.
//! Authentication, file and proof token purposes are validated by their
//! callers. Verification checks the MAC before interpreting the header or
//! claims.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use log::{debug, warn};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;

use crate::errors::{AppError, AppResult, JwtError};

type HmacSha256 = Hmac<Sha256>;

const ALG_HS256: &str = "HS256";
/// Default time leeway in seconds for exp/nbf validation
const DEFAULT_LEEWAY_SECONDS: i64 = 60;
/// Maximum token length (10KB) to prevent `DoS`
const MAX_TOKEN_BYTES: usize = 10_240;
/// Limit claims before parsing and signing an oversized token.
const MAX_CLAIMS_BYTES: usize = 8_192;

#[derive(Deserialize)]
struct DecodingHeader {
    #[serde(rename = "alg")]
    algorithm: String,
    #[serde(rename = "typ")]
    _token_type: String,
}

/// Options for JWT validation
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Time leeway in seconds for exp/nbf/iat validation
    pub leeway_seconds: i64,
    /// Whether to validate iat claim (reject if issued in future)
    pub validate_issued_at: bool,
    /// Expected audience (if Some, validates aud claim)
    pub expected_audience: Option<String>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            leeway_seconds: DEFAULT_LEEWAY_SECONDS,
            validate_issued_at: false, // iat validation is optional
            expected_audience: None,
        }
    }
}

/// Computes HMAC-SHA256 using pure Rust (synchronous, Send-safe)
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], JwtError> {
    if key.is_empty() {
        return Err(JwtError::CryptoError("JWT secret must not be empty"));
    }
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|_e| JwtError::CryptoError("HMAC initialization failed"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Decode the unpadded base64url form used by all issued tokens.
fn decode_base64url(input: &str) -> Result<Vec<u8>, JwtError> {
    // The caller bounds the whole token before decoding any segment.
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_error| JwtError::InvalidFormat("Invalid base64url encoding"))
}

/// Issue a JWT for application claims.
pub fn encode<T: Serialize>(claims: &T, secret: &[u8]) -> AppResult<String> {
    encode_signed(claims, secret)
        .map_err(|error| AppError::internal_debug("Failed to sign JWT token", error))
}

fn encode_signed<T: Serialize>(claims: &T, secret: &[u8]) -> Result<String, JwtError> {
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims_json = serde_json::to_string(claims).map_err(|error| claims_error(&error))?;
    if claims_json.len() > MAX_CLAIMS_BYTES {
        return Err(JwtError::TokenTooLarge);
    }
    let value: serde_json::Value =
        serde_json::from_str(&claims_json).map_err(|error| claims_error(&error))?;
    if !value.is_object() {
        return Err(JwtError::InvalidFormat("JWT claims must be an object"));
    }
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

    let signing_input = format!("{header_b64}.{claims_b64}");

    let signature = hmac_sha256(secret, signing_input.as_bytes())?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    let token = format!("{signing_input}.{signature_b64}");

    if token.len() > MAX_TOKEN_BYTES {
        return Err(JwtError::TokenTooLarge);
    }

    debug!("JWT encoded for claims size={} bytes", claims_json.len());

    Ok(token)
}

/// Decodes and validates a JWT token (synchronous)
pub fn decode<T: DeserializeOwned>(
    token: &str,
    secret: &[u8],
    options: &ValidationOptions,
) -> Result<T, JwtError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(JwtError::TokenTooLarge);
    }

    let (signing_input, signature_b64) = token
        .rsplit_once('.')
        .ok_or(JwtError::InvalidFormat("Missing payload"))?;
    let (header_b64, claims_b64) = signing_input
        .split_once('.')
        .ok_or(JwtError::InvalidFormat("Missing signature"))?;

    if claims_b64.contains('.') {
        return Err(JwtError::InvalidFormat("Token has more than 3 parts"));
    }

    if header_b64.is_empty() || claims_b64.is_empty() || signature_b64.is_empty() {
        return Err(JwtError::InvalidFormat("Empty token parts"));
    }

    // Verify the MAC before interpreting the encoded header or payload.
    let expected_signature = hmac_sha256(secret, signing_input.as_bytes())?;
    let provided_signature = decode_base64url(signature_b64)?;

    if !constant_time_eq(&expected_signature, &provided_signature) {
        warn!("JWT signature mismatch");
        return Err(JwtError::InvalidSignature);
    }

    let header_bytes = decode_base64url(header_b64)?;
    let header: DecodingHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_e| JwtError::InvalidFormat("Invalid header JSON"))?;

    if header.algorithm != ALG_HS256 {
        return Err(JwtError::InvalidAlgorithm {
            algorithm: header.algorithm,
        });
    }

    // Deserializing T directly preserves Serde's duplicate field checks.
    let claims_bytes = decode_base64url(claims_b64)?;
    let claims = serde_json::from_slice(&claims_bytes).map_err(|error| claims_error(&error))?;
    let claims_value =
        serde_json::from_slice(&claims_bytes).map_err(|error| claims_error(&error))?;

    let now = crate::utils::time::now_seconds();
    validate_time_claims(&claims_value, now, options)?;

    Ok(claims)
}

fn claims_error(error: &serde_json::Error) -> JwtError {
    JwtError::JsonError {
        detail: format!(
            "{:?} at line {} column {}",
            error.classify(),
            error.line(),
            error.column()
        ),
    }
}

/// Validates time-based claims (exp, nbf, iat)
fn validate_time_claims(
    claims: &serde_json::Value,
    now: i64,
    options: &ValidationOptions,
) -> Result<(), JwtError> {
    if !claims.is_object() {
        return Err(JwtError::InvalidFormat("JWT claims must be an object"));
    }
    if options.leeway_seconds < 0 {
        return Err(JwtError::InvalidFormat("JWT leeway must not be negative"));
    }
    // Older attachment capabilities only include exp.
    let exp = numeric_date(claims, "exp")?.ok_or(JwtError::MissingClaim("exp"))?;
    let nbf = numeric_date(claims, "nbf")?;
    let iat = numeric_date(claims, "iat")?;
    let now = i128::from(now);
    let leeway_seconds = i128::from(options.leeway_seconds);
    if now >= i128::from(exp) + leeway_seconds {
        return Err(JwtError::Expired);
    }
    if nbf.is_some_and(|nbf| now < i128::from(nbf) - leeway_seconds) {
        return Err(JwtError::NotYetValid);
    }
    if options.validate_issued_at && iat.is_some_and(|iat| i128::from(iat) > now + leeway_seconds) {
        return Err(JwtError::IssuedInFuture);
    }

    // Validate aud (audience) if expected
    if let Some(ref expected_audience) = options.expected_audience {
        let aud = claims.get("aud").ok_or(JwtError::MissingClaim("aud"))?;
        let matches = if let Some(aud) = aud.as_str() {
            aud == expected_audience
        } else if let Some(aud) = aud.as_array() {
            aud.iter().all(serde_json::Value::is_string)
                && aud
                    .iter()
                    .any(|value| value.as_str() == Some(expected_audience))
        } else {
            false
        };
        if !matches {
            return Err(JwtError::InvalidFormat("Audience mismatch"));
        }
    }

    Ok(())
}

fn numeric_date(claims: &serde_json::Value, name: &'static str) -> Result<Option<i64>, JwtError> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or(JwtError::InvalidFormat(
            "Numeric date claim must be an integer Unix timestamp",
        )),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn signed(header: &Value, claims: &Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header"));
        let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims"));
        let s = URL_SAFE_NO_PAD
            .encode(hmac_sha256(b"test-secret", format!("{h}.{c}").as_bytes()).expect("hmac"));
        format!("{h}.{c}.{s}")
    }

    #[test]
    fn jwt_validates_dates_skew_algorithms_signatures_and_audiences() {
        let default = ValidationOptions::default();
        assert!(matches!(
            validate_time_claims(&json!({}), 100, &default),
            Err(JwtError::MissingClaim("exp"))
        ));
        for bad in [
            json!(null),
            json!("200"),
            json!(true),
            json!(200.5),
            json!(u64::MAX),
        ] {
            assert!(validate_time_claims(&json!({"exp": bad}), 100, &default).is_err());
        }
        let skew = ValidationOptions {
            leeway_seconds: 60,
            validate_issued_at: true,
            ..Default::default()
        };
        validate_time_claims(
            &json!({"exp": i64::MAX, "nbf": i64::MIN, "iat": i64::MIN}),
            i64::MAX - 61,
            &skew,
        )
        .expect("extremes");
        assert!(matches!(
            validate_time_claims(&json!({"exp": 100}), 160, &skew),
            Err(JwtError::Expired)
        ));
        assert!(matches!(
            validate_time_claims(&json!({"exp": 500, "nbf": 161}), 100, &skew),
            Err(JwtError::NotYetValid)
        ));

        let claims = json!({"exp": i64::MAX, "sub": "owner"});
        let valid = signed(&json!({"alg": "HS256", "typ": "JWT"}), &claims);
        decode::<Value>(&valid, b"test-secret", &default).expect("valid");
        for alg in ["none", "HS384", "RS256"] {
            let token = signed(&json!({"alg": alg, "typ": "JWT"}), &claims);
            assert!(matches!(
                decode::<Value>(&token, b"test-secret", &default),
                Err(JwtError::InvalidAlgorithm { .. })
            ));
        }
        assert!(decode::<Value>(&format!("{valid}.extra"), b"test-secret", &default).is_err());
        assert!(decode::<Value>(&valid, b"wrong-secret", &default).is_err());
        assert!(encode(&claims, b"").is_err());

        let aud_opts = ValidationOptions {
            expected_audience: Some("req".into()),
            ..Default::default()
        };
        assert!(
            validate_time_claims(
                &json!({"exp": 500, "aud": ["other", "req"]}),
                100,
                &aud_opts
            )
            .is_ok()
        );
        assert!(
            validate_time_claims(&json!({"exp": 500, "aud": "wrong"}), 100, &aud_opts).is_err()
        );
    }
}
