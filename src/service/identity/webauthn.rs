mod assertion;
mod protocol;
mod registration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, Serializer};
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
    infra::jwt,
    models::identity::{
        account_keys::AccountSnapshot,
        webauthn::{WebauthnChallengeRow, WebauthnCredentialRow},
    },
    service::identity::{session::Claims, user::AccountVerificationRequest},
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

#[derive(Serialize, Deserialize)]
struct VerificationClaims {
    sub: String,
    exp: i64,
    nbf: i64,
    iat: i64,
    aud: String,
    purpose: String,
    device: String,
    session: String,
    stamp: String,
    credential_state: String,
}
async fn credential_state(db: &D1Database, user: &str) -> AppResult<String> {
    let keys = WebauthnCredentialRow::list(db, user, "2fa").await?;
    let mut bytes = serde_json::to_vec(
        &keys
            .iter()
            .map(|k| (&k.id, &k.credential_id))
            .collect::<Vec<_>>(),
    )
    .map_err(AppError::internal_error)?;
    bytes.extend_from_slice(AccountSnapshot::load(db, user).await?.to_json()?.as_bytes());
    Ok(hex::encode(Sha256::digest(bytes)))
}
pub async fn mint_user_verification_token(
    db: &D1Database,
    access_secret: &str,
    claims: &Claims,
) -> AppResult<String> {
    let now = crate::utils::time::now_seconds();
    let token = VerificationClaims {
        sub: claims.sub.clone(),
        exp: now + 300,
        nbf: now,
        iat: now,
        aud: "raywarden.webauthn".into(),
        purpose: "manage-2fa".into(),
        device: claims.device().unwrap_or_default().into(),
        session: claims.session_token.clone(),
        stamp: claims.sstamp.clone(),
        credential_state: credential_state(db, &claims.sub).await?,
    };
    jwt::encode(&token, access_secret.as_bytes())
}
pub async fn verify_user_verification_token(
    db: &D1Database,
    access_secret: &str,
    claims: &Claims,
    token: &str,
) -> AppResult<()> {
    let value = jwt::decode::<VerificationClaims>(
        token,
        access_secret.as_bytes(),
        &jwt::ValidationOptions {
            leeway_seconds: 0,
            ..Default::default()
        },
    )?;
    if value.aud != "raywarden.webauthn"
        || value.purpose != "manage-2fa"
        || value.sub != claims.sub
        || value.stamp != claims.sstamp
        || value.session != claims.session_token
        || Some(value.device.as_str()) != claims.device()
        || value.credential_state != credential_state(db, &claims.sub).await?
    {
        return Err(AppError::invalid_credentials(
            "Invalid WebAuthn user verification token",
        ));
    }
    Ok(())
}

fn random_challenge() -> String {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
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
    Ok(new_challenge_record(
        random_challenge(),
        purpose.as_str(),
        rp,
        origin,
    ))
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
    const fn as_str(self) -> &'static str {
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

pub(crate) struct CredentialResponse {
    slot: i32,
    name: String,
    prf_status: i32,
    encrypted_public_key: Option<String>,
    encrypted_user_key: Option<String>,
    encrypted_private_key: Option<String>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedString<'a> {
    encrypted_string: &'a str,
}

impl<'a> EncryptedString<'a> {
    const fn new(encrypted_string: &'a str) -> Self {
        Self { encrypted_string }
    }
}

impl Serialize for CredentialResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CredentialWire<'a> {
            id: i32,
            #[serde(rename = "Id")]
            legacy_id: i32,
            name: &'a str,
            #[serde(rename = "Name")]
            legacy_name: &'a str,
            prf_status: i32,
            #[serde(rename = "PrfStatus")]
            legacy_prf_status: i32,
            encrypted_public_key: Option<&'a str>,
            #[serde(rename = "EncryptedPublicKey")]
            legacy_encrypted_public_key: Option<&'a str>,
            encrypted_public_key_object: Option<EncryptedString<'a>>,
            #[serde(rename = "EncryptedPublicKeyObj")]
            legacy_encrypted_public_key_object: Option<EncryptedString<'a>>,
            encrypted_user_key: Option<&'a str>,
            #[serde(rename = "EncryptedUserKey")]
            legacy_encrypted_user_key: Option<&'a str>,
            encrypted_user_key_object: Option<EncryptedString<'a>>,
            #[serde(rename = "EncryptedUserKeyObj")]
            legacy_encrypted_user_key_object: Option<EncryptedString<'a>>,
            encrypted_private_key: Option<&'a str>,
            #[serde(rename = "EncryptedPrivateKey")]
            legacy_encrypted_private_key: Option<&'a str>,
            encrypted_private_key_object: Option<EncryptedString<'a>>,
            #[serde(rename = "EncryptedPrivateKeyObj")]
            legacy_encrypted_private_key_object: Option<EncryptedString<'a>>,
        }

        let public = self.encrypted_public_key.as_deref();
        let user = self.encrypted_user_key.as_deref();
        let private = self.encrypted_private_key.as_deref();
        CredentialWire {
            id: self.slot,
            legacy_id: self.slot,
            name: &self.name,
            legacy_name: &self.name,
            prf_status: self.prf_status,
            legacy_prf_status: self.prf_status,
            encrypted_public_key: public,
            legacy_encrypted_public_key: public,
            encrypted_public_key_object: public.map(EncryptedString::new),
            legacy_encrypted_public_key_object: public.map(EncryptedString::new),
            encrypted_user_key: user,
            legacy_encrypted_user_key: user,
            encrypted_user_key_object: user.map(EncryptedString::new),
            legacy_encrypted_user_key_object: user.map(EncryptedString::new),
            encrypted_private_key: private,
            legacy_encrypted_private_key: private,
            encrypted_private_key_object: private.map(EncryptedString::new),
            legacy_encrypted_private_key_object: private.map(EncryptedString::new),
        }
        .serialize(serializer)
    }
}

impl From<WebauthnCredentialRow> for CredentialResponse {
    fn from(row: WebauthnCredentialRow) -> Self {
        Self {
            slot: row.slot,
            name: row.name,
            prf_status: row.prf_status,
            encrypted_public_key: row.encrypted_public_key,
            encrypted_user_key: row.encrypted_user_key,
            encrypted_private_key: row.encrypted_private_key,
        }
    }
}

fn new_challenge_record(
    challenge: String,
    purpose: &str,
    rp: String,
    origin: String,
) -> WebauthnChallengeRow {
    WebauthnChallengeRow {
        id: Uuid::new_v4().to_string(),
        challenge,
        purpose: purpose.into(),
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
    }
}
