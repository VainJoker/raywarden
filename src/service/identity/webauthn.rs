mod assertion;
mod protocol;
mod registration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use worker::{D1Database, Env};

use self::protocol as wire;
pub(crate) use self::{
    assertion::{
        AssertionOptionsResponse, VerifiedTwoFactorAssertion, assertion_options,
        passwordless_options, verify_passwordless, verify_two_factor_assertion,
    },
    registration::{RegistrationOptions, register, registration_options},
};
pub use self::{
    assertion::{UpdateWebauthnCredentialRequest, two_factor_assertion_options, update_credential},
    registration::RegisterWebauthnCredentialRequest,
};
use crate::{
    errors::{AppError, AppResult},
    models::identity::{
        account_keys::AccountSnapshot,
        webauthn::{WebauthnChallengeRow, WebauthnCredentialRow},
    },
    service::identity::{session::Claims, two_factor, user::AccountVerificationRequest},
};

pub async fn verify_two_factor_authorization(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    claims: &Claims,
    payload: &AccountVerificationRequest,
) -> AppResult<()> {
    if let Some(token) = payload.user_verification_token.as_deref() {
        if payload.master_password_hash.is_some() || payload.otp.is_some() {
            return Err(AppError::bad_request(
                "Provide exactly one verification method",
            ));
        }
        return verify_user_verification_token(db, access_secret, claims, token).await;
    }
    crate::service::identity::email::verify_password_or_otp(db, env, access_secret, claims, payload)
        .await
}

async fn credential_state(db: &D1Database, user: &str) -> AppResult<String> {
    let keys = WebauthnCredentialRow::list(db, user, "2fa").await?;
    let mut bytes = serde_json::to_vec(
        &keys
            .iter()
            .map(|k| (&k.id, &k.credential_id))
            .collect::<Vec<_>>(),
    )
    .map_err(AppError::internal_json(
        "Failed to serialize WebAuthn digest input",
    ))?;
    bytes.extend_from_slice(AccountSnapshot::load(db, user).await?.to_json()?.as_bytes());
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub async fn mint_user_verification_token(
    db: &D1Database,
    access_secret: &str,
    claims: &Claims,
) -> AppResult<String> {
    two_factor::mint_factor_proof(
        access_secret,
        claims,
        "webauthn-2fa",
        credential_state(db, &claims.sub).await?,
        None,
    )
}

pub async fn verify_user_verification_token(
    db: &D1Database,
    access_secret: &str,
    claims: &Claims,
    token: &str,
) -> AppResult<()> {
    two_factor::verify_factor_proof(
        access_secret,
        claims,
        token,
        "webauthn-2fa",
        &credential_state(db, &claims.sub).await?,
        None,
    )
}

fn random_challenge() -> String {
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}
fn verify_client(
    env: &Env,
    client: &wire::ClientData,
    kind: &str,
    challenge: &WebauthnChallengeRow,
) -> AppResult<()> {
    let allowed = crate::infra::config::webauthn_allowed_origins(env);
    client.verify(kind, &challenge.challenge, &challenge.origin, &allowed)
}

fn user_handle(user: &str) -> Vec<u8> {
    Uuid::parse_str(user).map_or_else(|_| user.as_bytes().to_vec(), |u| u.as_bytes().to_vec())
}
#[derive(Clone, Copy)]
enum ChallengePurpose {
    RegisterLogin,
    RegisterTwoFactor,
    AssertLogin,
    AssertTwoFactor,
    PasswordlessLogin,
}

impl ChallengePurpose {
    const fn register(usage: CredentialUse) -> Self {
        match usage {
            CredentialUse::Login => Self::RegisterLogin,
            CredentialUse::TwoFactor => Self::RegisterTwoFactor,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::RegisterLogin => "register.login",
            Self::RegisterTwoFactor => "register.2fa",
            Self::AssertLogin => "assert.login",
            Self::AssertTwoFactor => "assert.2fa",
            Self::PasswordlessLogin => "login.passwordless",
        }
    }
}

fn new_challenge(domain: &str, purpose: ChallengePurpose) -> AppResult<WebauthnChallengeRow> {
    let (rp, origin) = wire::relying_party(domain)?;
    Ok(WebauthnChallengeRow {
        id: Uuid::new_v4().to_string(),
        challenge: random_challenge(),
        purpose: purpose.as_str().into(),
        user_id: None,
        security_stamp: None,
        device_id: None,
        session_token: None,
        account_snapshot: None,
        rp_id: rp,
        origin,
        expires_at: crate::utils::time::format_millis(
            crate::utils::time::now()
                .checked_add(jiff::SignedDuration::from_mins(5))
                .unwrap_or(jiff::Timestamp::MAX),
        ),
    })
}

fn bind_session(challenge: &mut WebauthnChallengeRow, claims: &Claims) {
    challenge.user_id = Some(claims.sub.clone());
    challenge.security_stamp = Some(claims.sstamp.clone());
    challenge.device_id = claims.device().map(str::to_owned);
    challenge.session_token = Some(claims.session_token.clone());
}

fn validate_binding(challenge: &WebauthnChallengeRow, claims: &Claims) -> AppResult<()> {
    if challenge.user_id.as_deref() != Some(&claims.sub)
        || challenge.security_stamp.as_deref() != Some(&claims.sstamp)
        || challenge.session_token.as_deref() != Some(&claims.session_token)
        || challenge.device_id.as_deref() != claims.device()
    {
        return Err(AppError::invalid_credentials("WebAuthn session changed"));
    }
    Ok(())
}

fn validate_encrypted_keys(
    public: Option<&str>,
    user: Option<&str>,
    private: Option<&str>,
) -> AppResult<()> {
    for value in [public, user, private].into_iter().flatten() {
        if value.is_empty() || value.len() > 32768 {
            return Err(AppError::bad_request(
                "Invalid wrapped passkey key material",
            ));
        }
    }
    if user.is_some() != private.is_some() {
        return Err(AppError::bad_request(
            "Both encryptedUserKey and encryptedPrivateKey are required",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum CredentialUse {
    Login,
    TwoFactor,
}

impl CredentialUse {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::TwoFactor => "2fa",
        }
    }

    const fn credential_limit(self) -> i32 {
        match self {
            Self::Login => 20,
            Self::TwoFactor => 5,
        }
    }

    const fn requires_user_verification(self) -> bool {
        matches!(self, Self::Login)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub(crate) enum PrfStatus {
    Enabled = 0,
    NeedsEncryption = 1,
    Unsupported = 2,
}

impl From<PrfStatus> for i32 {
    fn from(status: PrfStatus) -> Self {
        status as Self
    }
}

#[derive(Serialize)]
struct CredentialDescriptor {
    #[serde(rename = "type")]
    kind: &'static str,
    id: String,
}

impl From<WebauthnCredentialRow> for CredentialDescriptor {
    fn from(row: WebauthnCredentialRow) -> Self {
        Self {
            kind: "public-key",
            id: row.credential_id,
        }
    }
}

#[derive(Default, Serialize)]
struct CredentialExtensions {
    prf: PrfExtension,
}

#[derive(Default, Serialize)]
struct PrfExtension {}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialResponse {
    id: i32,
    name: String,
    prf_status: i32,
    encrypted_public_key: Option<String>,
    encrypted_user_key: Option<String>,
    encrypted_private_key: Option<String>,
}

impl From<WebauthnCredentialRow> for CredentialResponse {
    fn from(row: WebauthnCredentialRow) -> Self {
        Self {
            id: row.slot,
            name: row.name,
            prf_status: row.prf_status,
            encrypted_public_key: row.encrypted_public_key,
            encrypted_user_key: row.encrypted_user_key,
            encrypted_private_key: row.encrypted_private_key,
        }
    }
}
