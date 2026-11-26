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
    device: String,
    purpose: String,
    state: String,
    #[serde(default)]
    factor_id: Option<String>,
    exp: i64,
    nbf: i64,
    iat: i64,
}

pub(crate) fn mint_factor_proof(
    access_secret: &str,
    claims: &Claims,
    purpose: &str,
    state: String,
    factor_id: Option<&str>,
) -> AppResult<String> {
    let now = crate::utils::time::now_seconds();
    jwt::encode(
        &FactorProof {
            sub: claims.sub.clone(),
            sstamp: claims.sstamp.clone(),
            session_token: claims.session_token.clone(),
            device: claims.device().unwrap_or_default().to_owned(),
            purpose: purpose.to_owned(),
            state,
            factor_id: factor_id.map(str::to_owned),
            exp: now + 300,
            nbf: now,
            iat: now,
        },
        access_secret.as_bytes(),
    )
}

pub(crate) fn verify_factor_proof(
    access_secret: &str,
    claims: &Claims,
    token: &str,
    purpose: &str,
    expected_state: &str,
    observed_factor_id: Option<&str>,
) -> AppResult<()> {
    let proof =
        jwt::decode::<FactorProof>(token, access_secret.as_bytes(), &jwt::ValidationOptions {
            leeway_seconds: 0,
            ..Default::default()
        })?;
    if proof.sub != claims.sub
        || proof.sstamp != claims.sstamp
        || proof.session_token != claims.session_token
        || proof.device != claims.device().unwrap_or_default()
        || proof.purpose != purpose
        || proof
            .factor_id
            .as_deref()
            .is_some_and(|id| observed_factor_id != Some(id))
        || !constant_time_eq(proof.state.as_bytes(), expected_state.as_bytes())
    {
        return Err(AppError::invalid_credentials("Invalid verification proof"));
    }
    Ok(())
}

fn factor_state(address: Option<&str>) -> String {
    hex::encode(Sha256::digest(address.unwrap_or("disabled").as_bytes()))
}

pub fn mint_email_factor_proof(
    access_secret: &str,
    claims: &Claims,
    address: Option<&str>,
) -> AppResult<String> {
    mint_factor_proof(
        access_secret,
        claims,
        "email-factor",
        factor_state(address),
        None,
    )
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
    let current_email = email::email_provider(db, &claims.sub).await?;
    verify_factor_proof(
        access_secret,
        claims,
        token,
        "email-factor",
        &factor_state(current_email.as_deref()),
        None,
    )
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

/// POST /api/two-factor/authenticator - Enable TOTP
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateAuthenticatorRequest {
    pub key: String,
    pub token: String,
    #[serde(flatten)]
    pub verification: AccountVerificationRequest,
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorRequest {
    #[serde(flatten)]
    pub verification: AccountVerificationRequest,
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
    pub verification: AccountVerificationRequest,
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

    fn expiration_seconds(days: i64) -> i64 {
        days.clamp(1, 90) * 86_400
    }

    fn hash_token(token: &str) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(token.as_bytes())))
    }

    /// Remove expired tokens using the configured policy.
    pub fn remove_expired(&mut self, days: i64) {
        let now = crate::utils::time::now_seconds();
        let expiration_seconds = Self::expiration_seconds(days);
        self.tokens.retain(|t| {
            t.created_at <= now && now.saturating_sub(t.created_at) < expiration_seconds
        });
    }

    /// Validate a token for a specific device
    /// Returns true if valid and not expired
    pub fn validate(&self, device_id: &str, token: &str, days: i64) -> bool {
        let now = crate::utils::time::now_seconds();
        let expiration_seconds = Self::expiration_seconds(days);
        let hashed = Self::hash_token(token);

        self.tokens.iter().any(|t| {
            t.device_id == device_id
                && t.token.starts_with("sha256:")
                && constant_time_eq(t.token.as_bytes(), hashed.as_bytes())
                && t.created_at <= now
                && now.saturating_sub(t.created_at) < expiration_seconds
        })
    }

    /// Add or update a token for a device
    /// If the device already has a token, it will be replaced
    pub fn upsert(&mut self, device_id: String, token: &str) {
        self.tokens.retain(|t| t.device_id != device_id);
        self.tokens.push(RememberedDeviceToken {
            device_id,
            token: Self::hash_token(token),
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

/// Generates a 6-digit RFC 4226 / RFC 6238 code from an already-decoded Base32 secret.
async fn generate_totp_from_bytes(decoded_secret: &[u8], time_step: u64) -> AppResult<[u8; 6]> {
    let counter = time_step.to_be_bytes();
    let digest = hmac_sha1(decoded_secret, &counter).await?;

    let offset = (digest[19] & 0x0f) as usize;
    let code = (u32::from(digest[offset] & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]))
        % 1_000_000;

    let mut digits = [b'0'; 6];
    let mut rem = code;
    for slot in digits.iter_mut().rev() {
        *slot = b'0' + (rem % 10) as u8;
        rem /= 10;
    }
    Ok(digits)
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
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AppError::Auth(AuthError::InvalidTotp));
    }

    let decoded_secret = decode_base32(secret).ok_or(CryptoError::InvalidBase32)?;
    let current_step = crate::utils::time::now_seconds() / 30;
    let drift_steps = i64::from(allow_drift);

    for step_offset in -drift_steps..=drift_steps {
        let time_step = current_step + step_offset;
        if time_step <= last_used_step {
            continue;
        }
        let Ok(step) = u64::try_from(time_step) else {
            continue;
        };
        let expected = generate_totp_from_bytes(&decoded_secret, step).await?;
        if constant_time_eq(code.as_bytes(), &expected) {
            return Ok(time_step);
        }
    }

    Err(AppError::Auth(AuthError::InvalidTotp))
}

#[cfg(test)]
mod tests {
    use super::{RememberedDeviceToken, RememberedDevices, TwoFactorRow, requires_two_factor};

    #[test]
    fn remember_hashes_and_challenge_classification_match_policy() {
        let now = crate::utils::time::now_seconds();
        let mut data = RememberedDevices {
            tokens: vec![RememberedDeviceToken {
                device_id: "dev".into(),
                token: "plain".into(),
                created_at: now,
            }],
        };
        assert!(!data.validate("dev", "plain", 30));
        data.upsert("dev".into(), "opaque");
        assert!(data.validate("dev", "opaque", 30) && !data.to_json().contains("opaque"));

        for (kind, enabled, expected) in [
            (0, true, true),
            (7, false, false),
            (5, true, false),
            (1000, true, false),
            (2, true, true),
        ] {
            let row = TwoFactorRow {
                id: "f".into(),
                user_id: "u".into(),
                provider_type: kind,
                is_enabled: enabled,
                data: "{}".into(),
                last_used_step: 0,
            };
            assert_eq!(requires_two_factor(std::slice::from_ref(&row)), expected);
        }
    }
}
