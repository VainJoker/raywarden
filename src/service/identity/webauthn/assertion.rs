use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use worker::{D1Database, D1PreparedStatement, Env};

use super::{
    ChallengePurpose, CredentialDescriptor, CredentialExtensions, CredentialUse, bind_session,
    new_challenge, protocol as wire, user_handle, validate_binding, validate_encrypted_keys,
    verify_client,
};
use crate::{
    errors::{AppError, AppResult},
    infra::jwt,
    models::identity::{
        account_keys::AccountSnapshot,
        device::NewDeviceSession,
        user::UserRow,
        webauthn::{WebauthnChallengeRow, WebauthnCredentialRow},
    },
    service::{
        identity::session::Claims,
        notifications::{admin as admin_notify, admin::Event},
        rate_limit,
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssertionOptions {
    pub(crate) challenge: String,
    rp_id: String,
    timeout: u32,
    allow_credentials: Vec<CredentialDescriptor>,
    user_verification: &'static str,
    extensions: CredentialExtensions,
}

#[derive(Serialize)]
pub(crate) struct AssertionOptionsResponse {
    pub(crate) options: AssertionOptions,
    pub(crate) token: String,
}

async fn save_options(
    db: &D1Database,
    challenge: WebauthnChallengeRow,
    keys: Vec<WebauthnCredentialRow>,
    require_uv: bool,
) -> AppResult<AssertionOptions> {
    challenge.insert(db).await?;
    Ok(AssertionOptions {
        challenge: challenge.challenge,
        rp_id: challenge.rp_id,
        timeout: 60000,
        allow_credentials: keys.into_iter().map(Into::into).collect(),
        user_verification: if require_uv { "required" } else { "preferred" },
        extensions: CredentialExtensions::default(),
    })
}

pub(crate) async fn assertion_options(
    db: &D1Database,
    domain: &str,
    claims: &Claims,
) -> AppResult<AssertionOptions> {
    let keys = WebauthnCredentialRow::list(db, &claims.sub, "login").await?;
    if keys.is_empty() {
        return Err(AppError::not_found("Passkey"));
    }
    let mut challenge = new_challenge(domain, ChallengePurpose::AssertLogin)?;
    bind_session(&mut challenge, claims);
    challenge.account_snapshot = Some(AccountSnapshot::load(db, &claims.sub).await?.to_json()?);
    save_options(db, challenge, keys, true).await
}

pub async fn two_factor_assertion_options(
    db: &D1Database,
    domain: &str,
    user: &UserRow,
    device: &str,
) -> AppResult<Value> {
    let keys = WebauthnCredentialRow::list(db, &user.id, "2fa").await?;
    if keys.is_empty() {
        return Err(AppError::invalid_credentials(
            "No WebAuthn two-factor credential",
        ));
    }
    let mut challenge = new_challenge(domain, ChallengePurpose::AssertTwoFactor)?;
    challenge.user_id = Some(user.id.clone());
    challenge.security_stamp = Some(user.security_stamp.clone());
    challenge.account_snapshot = Some(AccountSnapshot::json_from_user(user)?);
    challenge.device_id = Some(device.into());
    let options = save_options(db, challenge, keys, false).await?;
    serde_json::to_value(options).map_err(AppError::internal_error)
}

#[derive(Serialize, Deserialize)]
struct LoginChallengeClaims {
    sub: String,
    exp: i64,
    nbf: i64,
    iat: i64,
    aud: String,
    purpose: String,
    challenge: String,
}

pub(crate) async fn passwordless_options(
    db: &D1Database,
    env: &Env,
    domain: &str,
    access_secret: &str,
    headers: &HeaderMap,
) -> AppResult<AssertionOptionsResponse> {
    rate_limit::check_auth_attempt(
        env,
        format!("passkey-options:{}", rate_limit::client_ip(headers)),
    )
    .await?;
    let mut challenge = new_challenge(domain, ChallengePurpose::PasswordlessLogin)?;
    challenge.device_id = headers
        .get("x-device-identifier")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let now = crate::utils::time::now_seconds();
    let token = LoginChallengeClaims {
        sub: challenge.id.clone(),
        exp: now + 300,
        nbf: now,
        iat: now,
        aud: "raywarden.webauthn".into(),
        purpose: "passwordless".into(),
        challenge: challenge.challenge.clone(),
    };
    let token = jwt::encode(&token, access_secret.as_bytes())?;
    let options = save_options(db, challenge, Vec::new(), true).await?;
    Ok(AssertionOptionsResponse { options, token })
}

struct AssertionCheck<'a> {
    db: &'a D1Database,
    env: &'a Env,
    challenge: &'a WebauthnChallengeRow,
    usage: CredentialUse,
    expected_credential_id: Option<&'a str>,
}

struct CredentialAssertion {
    assertion: wire::Assertion,
    client_data: wire::ClientData,
}

impl CredentialAssertion {
    fn parse(json: &str) -> AppResult<Self> {
        let assertion: wire::Assertion = serde_json::from_str(json)
            .map_err(|_error| AppError::invalid_credentials("Invalid WebAuthn assertion"))?;
        let client_data =
            wire::ClientData::parse(wire::decode_base64(&assertion.response.client_data_json)?)?;
        Ok(Self {
            assertion,
            client_data,
        })
    }

    async fn verify(self, check: AssertionCheck<'_>) -> AppResult<VerifiedAssertion> {
        let Self {
            assertion,
            client_data: client,
        } = self;
        verify_client(check.env, &client, "webauthn.get", check.challenge)?;
        let id = assertion
            .raw_id
            .as_deref()
            .or(assertion.id.as_deref())
            .ok_or_else(|| AppError::invalid_credentials("Missing WebAuthn credential id"))?;
        let id = wire::decode_base64(id)?;
        if let (Some(raw), Some(other)) = (&assertion.raw_id, &assertion.id)
            && wire::decode_base64(raw)? != wire::decode_base64(other)?
        {
            return Err(AppError::invalid_credentials(
                "WebAuthn credential id mismatch",
            ));
        }
        let key = WebauthnCredentialRow::find(check.db, &URL_SAFE_NO_PAD.encode(id))
            .await?
            .filter(|k| k.credential_use == check.usage.as_str())
            .ok_or_else(|| {
                AppError::invalid_credentials(
                    "WebAuthn credential is not registered for this purpose",
                )
            })?;
        if check
            .challenge
            .user_id
            .as_deref()
            .is_some_and(|u| u != key.user_id)
        {
            return Err(AppError::invalid_credentials(
                "WebAuthn credential owner mismatch",
            ));
        }
        if let Some(handle) = assertion.response.user_handle
            && !handle.is_empty()
            && wire::decode_base64(&handle)? != user_handle(&key.user_id)
        {
            return Err(AppError::invalid_credentials(
                "WebAuthn user handle mismatch",
            ));
        }
        let auth = wire::decode_base64(&assertion.response.authenticator_data)?;
        let parsed = wire::parse_authenticator_data(&auth, false)?;
        wire::verify_authenticator_data(
            &parsed,
            &check.challenge.rp_id,
            check.usage.requires_user_verification(),
        )?;
        let public_key = wire::parse_webauthn_public_key(&wire::decode_base64(&key.public_key)?)?.0;
        let mut signed = auth;
        signed.extend_from_slice(&Sha256::digest(client.bytes()));
        public_key.verify(
            &signed,
            &wire::decode_base64(&assertion.response.signature)?,
        )?;
        let count = i64::from(parsed.sign_count);
        wire::verify_counter(key.sign_count, count)?;
        if check.expected_credential_id.is_some_and(|id| key.id != id) {
            return Err(AppError::invalid_credentials(
                "The asserted credential does not match the updated credential",
            ));
        }
        Ok(VerifiedAssertion { key, count })
    }
}

struct VerifiedAssertion {
    key: WebauthnCredentialRow,
    count: i64,
}

pub(crate) struct VerifiedTwoFactorAssertion {
    assertion: VerifiedAssertion,
    challenge: WebauthnChallengeRow,
}

impl VerifiedTwoFactorAssertion {
    pub(crate) fn credential_row_id(&self) -> &str {
        &self.assertion.key.id
    }

    pub(crate) fn consume_statements(
        &self,
        db: &D1Database,
    ) -> AppResult<[D1PreparedStatement; 3]> {
        self.assertion
            .key
            .consume_assertion_statements(db, &self.challenge, self.assertion.count)
    }
}

pub(crate) async fn verify_two_factor_assertion(
    db: &D1Database,
    env: &Env,
    user: &UserRow,
    device: &str,
    assertion: &str,
    before_accept: impl FnOnce() -> AppResult<()>,
) -> AppResult<VerifiedTwoFactorAssertion> {
    let assertion = CredentialAssertion::parse(assertion)?;
    let challenge = WebauthnChallengeRow::find_challenge(
        db,
        assertion.client_data.challenge(),
        ChallengePurpose::AssertTwoFactor.as_str(),
    )
    .await?;
    if challenge.user_id.as_deref() != Some(user.id.as_str())
        || challenge.security_stamp.as_deref() != Some(user.security_stamp.as_str())
        || challenge.device_id.as_deref() != Some(device)
    {
        return Err(AppError::invalid_credentials(
            "WebAuthn login challenge belongs to another session",
        ));
    }
    let verified = assertion
        .verify(AssertionCheck {
            db,
            env,
            challenge: &challenge,
            usage: CredentialUse::TwoFactor,
            expected_credential_id: None,
        })
        .await?;
    before_accept()?;
    Ok(VerifiedTwoFactorAssertion {
        assertion: verified,
        challenge,
    })
}

pub(crate) struct PasswordlessLogin {
    assertion: VerifiedAssertion,
    challenge: WebauthnChallengeRow,
}

impl PasswordlessLogin {
    pub(crate) fn user_id(&self) -> &str {
        &self.assertion.key.user_id
    }

    pub(crate) async fn start_session(
        self,
        db: &D1Database,
        user: &UserRow,
        session: &NewDeviceSession<'_>,
    ) -> AppResult<Option<(String, String)>> {
        let current = AccountSnapshot::json_from_user(user)?;
        let key = &self.assertion.key;
        let prf_keys =
            if key.prf_status == 0 && key.account_snapshot.as_deref() == Some(current.as_str()) {
                key.encrypted_user_key
                    .clone()
                    .zip(key.encrypted_private_key.clone())
            } else {
                None
            };
        key.accept_login_assertion(db, &self.challenge, self.assertion.count, user, session)
            .await?;
        Ok(prf_keys)
    }
}

pub(crate) async fn verify_passwordless(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    token: &str,
    assertion: &str,
    device: &str,
) -> AppResult<PasswordlessLogin> {
    let value = jwt::decode::<LoginChallengeClaims>(
        token,
        access_secret.as_bytes(),
        &jwt::ValidationOptions {
            leeway_seconds: 0,
            ..Default::default()
        },
    )?;
    if value.aud != "raywarden.webauthn" || value.purpose != "passwordless" {
        return Err(AppError::invalid_credentials("Invalid passkey login token"));
    }
    let challenge = WebauthnChallengeRow::find_challenge(
        db,
        &value.challenge,
        ChallengePurpose::PasswordlessLogin.as_str(),
    )
    .await?;
    if challenge.id != value.sub || challenge.device_id.as_deref().is_some_and(|d| d != device) {
        return Err(AppError::invalid_credentials(
            "Passkey login device mismatch",
        ));
    }
    let assertion = CredentialAssertion::parse(assertion)?
        .verify(AssertionCheck {
            db,
            env,
            challenge: &challenge,
            usage: CredentialUse::Login,
            expected_credential_id: None,
        })
        .await?;
    Ok(PasswordlessLogin {
        assertion,
        challenge,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWebauthnCredentialRequest {
    pub token: Option<String>,
    pub name: Option<String>,
    pub device_response: Box<RawValue>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_user_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

impl UpdateWebauthnCredentialRequest {
    pub(crate) fn credential_id(&self) -> AppResult<String> {
        // Clients can send both keys. An explicitly present id takes precedence.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CredentialIdentifier<'a> {
            #[serde(default, borrow, deserialize_with = "present_identifier")]
            id: Option<&'a RawValue>,
            #[serde(borrow)]
            raw_id: Option<&'a RawValue>,
        }
        let missing = || AppError::bad_request("Missing WebAuthn credential ID");
        let identifiers =
            serde_json::from_str::<CredentialIdentifier<'_>>(self.device_response.get())
                .map_err(|_error| missing())?;
        let id = identifiers.id.or(identifiers.raw_id).ok_or_else(missing)?;
        let id: String = serde_json::from_str(id.get()).map_err(|_error| missing())?;
        if id.is_empty() {
            Err(missing())
        } else {
            Ok(id)
        }
    }
}

fn present_identifier<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(deserializer).map(Some)
}

pub async fn update_credential(
    db: &D1Database,
    env: &Env,
    claims: &Claims,
    id: &str,
    payload: UpdateWebauthnCredentialRequest,
) -> AppResult<()> {
    validate_encrypted_keys(
        payload.encrypted_public_key.as_deref(),
        payload.encrypted_user_key.as_deref(),
        payload.encrypted_private_key.as_deref(),
    )?;
    if payload.encrypted_user_key.is_none() || payload.encrypted_public_key.is_none() {
        return Err(AppError::bad_request(
            "Encrypted public, user and private PRF keys are required",
        ));
    }
    let assertion = CredentialAssertion::parse(payload.device_response.get())?;
    let challenge = WebauthnChallengeRow::find_challenge(
        db,
        assertion.client_data.challenge(),
        ChallengePurpose::AssertLogin.as_str(),
    )
    .await?;
    validate_binding(&challenge, claims)?;
    if payload
        .token
        .as_deref()
        .is_some_and(|t| !t.is_empty() && t != challenge.challenge)
    {
        return Err(AppError::invalid_credentials(
            "WebAuthn challenge token mismatch",
        ));
    }
    let expected = WebauthnCredentialRow::find_owned(db, &claims.sub, "login", id).await?;
    let verified = assertion
        .verify(AssertionCheck {
            db,
            env,
            challenge: &challenge,
            usage: CredentialUse::Login,
            expected_credential_id: Some(&expected.id),
        })
        .await?;
    let snapshot = AccountSnapshot::load(db, &claims.sub).await?.to_json()?;
    if challenge.account_snapshot.as_deref() != Some(snapshot.as_str()) {
        return Err(AppError::conflict(
            "Account encryption changed during PRF update",
        ));
    }
    let session = claims.session_snapshot()?;
    let proof = verified
        .key
        .prepare_prf_assertion(db, &session, &challenge, verified.count)?;
    let mut key = verified.key;
    key.sign_count = key.sign_count.max(verified.count);
    key.last_challenge = Some(challenge.id);
    key.account_snapshot = Some(snapshot);
    key.encrypted_public_key = payload.encrypted_public_key;
    key.encrypted_user_key = payload.encrypted_user_key;
    key.encrypted_private_key = payload.encrypted_private_key;
    key.prf_status = 0;
    if let Some(name) = payload.name {
        key.name = name;
    }
    key.update_keys(db, &session, proof).await?;
    admin_notify::emit(env, Event::WebauthnCredentialUpdate, &claims.sub).await;
    Ok(())
}
