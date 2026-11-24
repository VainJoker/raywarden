//! Two-factor providers, authenticator codes and remembered devices.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{D1Database, Env};

use crate::{
    errors::{AppError, AppResult, AuthError, CryptoError},
    infra::{
        crypto::{hmac_sha1, random_bytes},
        jwt,
    },
    models::identity::{
        authorization::VerifiedAccountAction,
        two_factor::{REMEMBER_PROVIDER, TwoFactorRow},
    },
    service::identity::{email, session::Claims, user::AccountVerificationRequest},
    utils::constant_time_eq,
};

#[derive(Serialize, Deserialize)]
struct FactorProof {
    sub: String,
    sstamp: String,
    session_token: String,
    purpose: String,
    email_state: String,
    exp: i64,
    nbf: i64,
    iat: i64,
}

fn factor_state(address: Option<&str>) -> String {
    hex::encode(Sha256::digest(address.unwrap_or("disabled").as_bytes()))
}

pub fn mint_email_factor_proof(
    access_secret: &str,
    claims: &Claims,
    address: Option<&str>,
) -> AppResult<String> {
    let now = crate::utils::time::now_seconds();
    let proof = FactorProof {
        sub: claims.sub.clone(),
        sstamp: claims.sstamp.clone(),
        session_token: claims.session_token.clone(),
        purpose: "email-factor".into(),
        email_state: factor_state(address),
        exp: now + 300,
        nbf: now,
        iat: now,
    };
    jwt::encode(&proof, access_secret.as_bytes())
}

pub async fn verify_email_factor_action(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    claims: &Claims,
    payload: &AccountVerificationRequest,
) -> AppResult<()> {
    if let Some(token) = payload.user_verification_token.as_deref() {
        return verify_email_factor_proof(db, access_secret, claims, token).await;
    }
    email::verify_password_or_otp(db, env, access_secret, claims, payload).await
}

pub(crate) async fn prepare_email_factor_action<'a>(
    verifier: &email::EmailVerifier<'_>,
    claims: &'a Claims,
    payload: &AccountVerificationRequest,
) -> AppResult<VerifiedAccountAction<'a>> {
    if let Some(token) = payload.user_verification_token.as_deref() {
        let user = email::fetch_user(verifier.db, claims).await?;
        verify_email_factor_proof(verifier.db, verifier.access_secret, claims, token).await?;
        VerifiedAccountAction::new(claims.session_snapshot()?, user, None)
    } else {
        verifier.prepare_account_action(claims, payload).await
    }
}

pub(crate) async fn verify_email_factor_proof(
    db: &D1Database,
    access_secret: &str,
    claims: &Claims,
    token: &str,
) -> AppResult<()> {
    let proof =
        jwt::decode::<FactorProof>(token, access_secret.as_bytes(), &jwt::ValidationOptions {
            leeway_seconds: 0,
            ..Default::default()
        })?;
    let current_email = email::email_provider(db, &claims.sub).await?;
    if proof.sub != claims.sub
        || proof.sstamp != claims.sstamp
        || proof.session_token != claims.session_token
        || proof.purpose != "email-factor"
        || proof.email_state != factor_state(current_email.as_deref())
    {
        return Err(AppError::invalid_credentials(
            "Invalid email verification proof",
        ));
    }
    Ok(())
}

/// Two-factor authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TwoFactorProvider {
    Authenticator = 0, // TOTP
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = REMEMBER_PROVIDER,
    OrganizationDuo = 6,
    Webauthn = 7,
    RecoveryCode = 8,
}

impl TryFrom<i32> for TwoFactorProvider {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::YubiKey),
            4 => Ok(Self::U2f),
            REMEMBER_PROVIDER => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::Webauthn),
            8 => Ok(Self::RecoveryCode),
            _ => Err(value),
        }
    }
}

impl From<TwoFactorProvider> for i32 {
    fn from(value: TwoFactorProvider) -> Self {
        value as Self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoredProvider {
    Known(TwoFactorProvider),
    LegacyUnknown(i32),
}

impl From<i32> for StoredProvider {
    fn from(value: i32) -> Self {
        TwoFactorProvider::try_from(value).map_or_else(Self::LegacyUnknown, Self::Known)
    }
}

impl From<StoredProvider> for i32 {
    fn from(provider: StoredProvider) -> Self {
        match provider {
            StoredProvider::Known(known) => known.into(),
            StoredProvider::LegacyUnknown(value) => value,
        }
    }
}

pub fn new_two_factor_provider(
    user_id: String,
    provider_type: TwoFactorProvider,
    data: String,
) -> TwoFactorRow {
    TwoFactorRow {
        id: uuid::Uuid::new_v4().to_string(),
        user_id,
        provider_type: provider_type.into(),
        is_enabled: true,
        data,
        last_used_step: 0,
    }
}

#[derive(Serialize)]
pub(crate) struct TwoFactorProviderResponse {
    enabled: bool,
    #[serde(rename = "type")]
    provider_type: i32,
    object: &'static str,
}

impl TwoFactorProviderResponse {
    pub(crate) const fn new(enabled: bool, provider_type: i32) -> Self {
        Self {
            enabled,
            provider_type,
            object: "twoFactorProvider",
        }
    }
}

impl From<&TwoFactorRow> for TwoFactorProviderResponse {
    fn from(row: &TwoFactorRow) -> Self {
        Self::new(row.is_enabled, row.provider_type)
    }
}

/// Whether the same providers used during login require a second factor.
pub fn requires_two_factor(providers: &[TwoFactorRow]) -> bool {
    providers.iter().any(TwoFactorRow::requires_login_challenge)
}

pub async fn is_two_factor_enabled(db: &worker::D1Database, user_id: &str) -> AppResult<bool> {
    let providers = TwoFactorRow::list_for_user(db, user_id).await?;
    Ok(requires_two_factor(&providers))
}

/// Unaliased verification fields accepted by the authenticator endpoints.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountVerificationFields {
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    pub user_verification_token: Option<String>,
}

impl From<AccountVerificationFields> for AccountVerificationRequest {
    fn from(fields: AccountVerificationFields) -> Self {
        Self {
            master_password_hash: fields.master_password_hash,
            otp: fields.otp,
            user_verification_token: fields.user_verification_token,
        }
    }
}

/// POST /api/two-factor/authenticator - Enable TOTP
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateAuthenticatorRequest {
    pub key: String,
    pub token: String,
    #[serde(flatten)]
    pub verification: AccountVerificationFields,
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorRequest {
    #[serde(flatten)]
    pub verification: AccountVerificationFields,
    #[serde(rename = "type")]
    pub provider_type: i32,
}

/// POST /api/two-factor/get-recover - Get recovery code
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverTwoFactorRequest {
    pub master_password_hash: String,
    pub email: String,
    pub recovery_code: String,
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorRequest {
    pub key: String,
    #[serde(flatten)]
    pub verification: AccountVerificationFields,
    #[serde(rename = "type")]
    pub provider_type: i32,
}

/// Single device remember token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RememberedDeviceToken {
    pub device_id: String,
    pub token: String,
    pub created_at: i64, // Unix timestamp
}

/// Container for multiple device remember tokens
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RememberedDevices {
    pub tokens: Vec<RememberedDeviceToken>,
}

impl RememberedDevices {
    /// Parse from JSON string stored in database
    pub fn from_json(data: &str) -> Self {
        serde_json::from_str(data).unwrap_or_default()
    }

    /// Serialize to JSON string for database storage
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Remove expired tokens using the configured policy.
    pub fn remove_expired(&mut self, days: i64) {
        let now = crate::utils::time::now_seconds();
        let expiration_seconds = days.clamp(1, 90) * 86_400;
        self.tokens.retain(|t| {
            t.created_at <= now && now.saturating_sub(t.created_at) < expiration_seconds
        });
    }

    /// Validate a token for a specific device
    /// Returns true if valid and not expired
    pub fn validate(&self, device_id: &str, token: &str, days: i64) -> bool {
        let now = crate::utils::time::now_seconds();
        let expiration_seconds = days.clamp(1, 90) * 86_400;
        let hashed = format!("sha256:{}", hex::encode(Sha256::digest(token.as_bytes())));

        self.tokens.iter().any(|t| {
            t.device_id == device_id
                && constant_time_eq(
                    t.token.as_bytes(),
                    if t.token.starts_with("sha256:") {
                        hashed.as_bytes()
                    } else {
                        token.as_bytes()
                    },
                )
                && t.created_at <= now
                && now.saturating_sub(t.created_at) < expiration_seconds
        })
    }

    /// Add or update a token for a device
    /// If the device already has a token, it will be replaced
    pub fn upsert(&mut self, device_id: String, token: &str) {
        // Remove existing token for this device
        self.tokens.retain(|t| t.device_id != device_id);

        // Add new token
        self.tokens.push(RememberedDeviceToken {
            device_id,
            token: format!("sha256:{}", hex::encode(Sha256::digest(token.as_bytes()))),
            created_at: crate::utils::time::now_seconds(),
        });
    }
}

const FACTOR_SECRET_BYTES: u32 = 20;

/// Decode an uppercase Base32 string with optional padding.
fn decode_base32(input: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::Rfc4648 { padding: true }, input)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: false }, input))
}

/// Validate and normalize the submitted secret before enabling an
/// authenticator.
pub(crate) fn normalize_authenticator_key(key: &str) -> AppResult<String> {
    let key = key.trim().to_ascii_uppercase();
    let decoded = decode_base32(&key).ok_or_else(|| AppError::bad_request("Invalid Base32 key"))?;
    if decoded.len() != FACTOR_SECRET_BYTES as usize {
        return Err(AppError::bad_request("Invalid key length"));
    }
    Ok(key)
}

/// Generate the Base32 secret used for authenticators and recovery codes.
pub(crate) fn generate_factor_secret() -> AppResult<String> {
    let secret = random_bytes(FACTOR_SECRET_BYTES, "generate authenticator secret")?;
    Ok(base32::encode(
        base32::Alphabet::Rfc4648 { padding: true },
        &secret,
    ))
}

/// Generates a TOTP code for the given secret and time.
///
/// # Arguments
/// * `secret` - Base32 encoded secret key
/// * `time_step` - Unix timestamp divided by 30 (or custom period)
///
/// # Returns
/// * 6-digit TOTP code as a string
async fn generate_totp(secret: &str, time_step: u64) -> AppResult<String> {
    let decoded_secret = decode_base32(secret).ok_or(CryptoError::InvalidBase32)?;

    // Convert time_step to big-endian bytes
    let counter = time_step.to_be_bytes();

    // Compute HMAC-SHA1
    let digest = hmac_sha1(&decoded_secret, &counter).await?;

    // Dynamic truncation (RFC 4226)
    let offset = (digest[19] & 0x0f) as usize;
    let code = u32::from(digest[offset] & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);

    // Get 6-digit code
    let code = code % 1_000_000;
    Ok(format!("{code:06}"))
}

/// Validates a TOTP code against a secret.
///
/// # Arguments
/// * `code` - The TOTP code to validate
/// * `secret` - Base32 encoded secret key
/// * `last_used_step` - The last used time step (for replay protection)
/// * `allow_drift` - Whether to allow 1 time step drift (±30 seconds)
///
/// # Returns
/// * `Ok(time_step)` if valid, with the time step that matched
/// * `Err` if invalid
pub(crate) async fn validate_totp(
    code: &str,
    secret: &str,
    last_used_step: i64,
    allow_drift: bool,
) -> AppResult<i64> {
    // Validate code format
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Auth(AuthError::InvalidTotp));
    }

    let current_time_seconds = crate::utils::time::now_seconds();
    let current_step = current_time_seconds / 30;

    // Check drift range
    let drift_steps: i64 = i64::from(allow_drift);

    for step_offset in -drift_steps..=drift_steps {
        let time_step = current_step + step_offset;

        // Skip if this time step was already used (replay protection)
        if time_step <= last_used_step {
            continue;
        }

        let expected = generate_totp(secret, time_step as u64).await?;

        if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
            return Ok(time_step);
        }
    }

    Err(AppError::Auth(AuthError::InvalidTotp))
}

#[cfg(test)]
mod tests {
    use super::{RememberedDeviceToken, RememberedDevices, TwoFactorRow, requires_two_factor};

    #[test]
    fn remember_tokens_read_legacy_values_and_store_new_hashes() {
        let now = crate::utils::time::now_seconds();
        let mut data = RememberedDevices {
            tokens: vec![RememberedDeviceToken {
                device_id: "device".into(),
                token: "old-opaque-token".into(),
                created_at: now - 2 * 86400,
            }],
        };
        assert!(data.validate("device", "old-opaque-token", 3));
        assert!(!data.validate("device", "old-opaque-token", 1));
        data.upsert("device".into(), "new-opaque-token");
        assert!(data.validate("device", "new-opaque-token", 30));
        assert!(!data.to_json().contains("new-opaque-token"));
        data.tokens[0].created_at = now + 86400;
        assert!(!data.validate("device", "new-opaque-token", 30));
        data.remove_expired(30);
        assert!(data.tokens.is_empty());
    }

    #[test]
    fn challenge_classification_matches_login_for_supported_and_legacy_factors() {
        for (provider_type, enabled, expected) in [
            (0, true, true),
            (1, true, true),
            (7, true, true),
            (0, false, false),
            (1, false, false),
            (7, false, false),
            (5, true, false),
            (1000, true, false),
            (1005, true, false),
            // Unknown and unsupported legacy factors still trigger the same
            // login challenge; this predicate must not bypass their handling.
            (2, true, true),
            (8, true, true),
            (42, true, true),
            (999, true, true),
            (-1, true, true),
        ] {
            let factor = TwoFactorRow {
                id: "factor".into(),
                user_id: "owner".into(),
                provider_type,
                is_enabled: enabled,
                data: "{}".into(),
                last_used_step: 0,
            };
            assert_eq!(
                factor.requires_login_challenge(),
                expected,
                "type {provider_type}, enabled {enabled}"
            );
            assert_eq!(requires_two_factor(std::slice::from_ref(&factor)), expected);
        }
    }
}
