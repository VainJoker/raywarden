use axum::http::HeaderMap;
use base64::{
    Engine as _,
    engine::general_purpose::URL_SAFE_NO_PAD,
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};
use sha2::{
    Digest,
    Sha256,
};
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            rate,
        },
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    infra::{
        admin_notify::{
            self,
            Event,
        },
        jwt,
        webauthn as wire,
    },
    models::{
        user::{
            PasswordOrOtpData,
            UserDB,
        },
        webauthn::{
            ChallengeDB,
            CredentialDB,
            now_string,
        },
    },
};

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationData {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash:    Option<String>,
    pub otp:                     Option<String>,
    pub user_verification_token: Option<String>,
}

pub async fn verify_secret(
    state: &AppState,
    claims: &Claims,
    payload: &SecretVerificationData,
) -> AppResult<()> {
    let proof = PasswordOrOtpData {
        master_password_hash:    payload.master_password_hash.clone(),
        otp:                     payload.otp.clone(),
        user_verification_token: payload.user_verification_token.clone(),
    };
    crate::api::service::email::verify_password_or_otp(state, claims, &proof)
        .await
}
pub async fn verify_2fa_secret(
    state: &AppState,
    claims: &Claims,
    payload: &SecretVerificationData,
) -> AppResult<()> {
    if let Some(token) = payload.user_verification_token.as_deref() {
        if payload.master_password_hash.is_some() || payload.otp.is_some() {
            return Err(AppError::bad_request(
                "Provide exactly one verification method",
            ));
        }
        return verify_user_verification_token(state, claims, token).await;
    }
    verify_secret(state, claims, payload).await
}

#[derive(Serialize, Deserialize)]
struct VerificationClaims {
    sub:              String,
    exp:              i64,
    nbf:              i64,
    iat:              i64,
    aud:              String,
    purpose:          String,
    device:           String,
    session:          String,
    stamp:            String,
    credential_state: String,
}
async fn credential_state(state: &AppState, user: &str) -> AppResult<String> {
    let keys = CredentialDB::list(&state.get_db(), user, "2fa").await?;
    let mut bytes = serde_json::to_vec(
        &keys
            .iter()
            .map(|k| (&k.id, &k.credential_id))
            .collect::<Vec<_>>(),
    )
    .map_err(|_| AppError::Internal)?;
    bytes.extend_from_slice(
        crate::models::account_keys::AccountSnapshot::load(
            &state.get_db(),
            user,
        )
        .await?
        .to_json()?
        .as_bytes(),
    );
    Ok(hex::encode(Sha256::digest(bytes)))
}
pub async fn mint_user_verification_token(
    state: &AppState,
    claims: &Claims,
) -> AppResult<String> {
    let now = crate::infra::time::now_seconds();
    let token = VerificationClaims {
        sub:              claims.sub.clone(),
        exp:              now + 300,
        nbf:              now,
        iat:              now,
        aud:              "raywarden.webauthn".into(),
        purpose:          "manage-2fa".into(),
        device:           claims.device().unwrap_or_default().into(),
        session:          claims.session_token.clone(),
        stamp:            claims.sstamp.clone(),
        credential_state: credential_state(state, &claims.sub).await?,
    };
    Ok(jwt::encode(&token, state.config.jwt_secret.as_bytes())?)
}
pub async fn verify_user_verification_token(
    state: &AppState,
    claims: &Claims,
    token: &str,
) -> AppResult<()> {
    let value = jwt::decode::<VerificationClaims>(
        token,
        state.config.jwt_secret.as_bytes(),
        &jwt::ValidationOptions {
            leeway: 0,
            ..Default::default()
        },
    )?
    .claims;
    if value.aud != "raywarden.webauthn" ||
        value.purpose != "manage-2fa" ||
        value.sub != claims.sub ||
        value.stamp != claims.sstamp ||
        value.session != claims.session_token ||
        Some(value.device.as_str()) != claims.device() ||
        value.credential_state !=
            credential_state(state, &claims.sub).await?
    {
        return Err(wire::invalid("Invalid WebAuthn user verification token"));
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
    state: &AppState,
    bytes: &[u8],
    kind: &str,
    challenge: &ChallengeDB,
) -> AppResult<()> {
    let allowed = state
        .env
        .var("WEBAUTHN_ALLOWED_ORIGINS")
        .ok()
        .map(|value| value.to_string())
        .unwrap_or_default();
    wire::verify_client_data_with_origins(
        bytes,
        kind,
        &challenge.challenge,
        &challenge.origin,
        &allowed,
    )
}

fn user_handle(user: &str) -> Vec<u8> {
    Uuid::parse_str(user)
        .map_or_else(|_| user.as_bytes().to_vec(), |u| u.as_bytes().to_vec())
}
fn new_challenge(state: &AppState, purpose: &str) -> AppResult<ChallengeDB> {
    let (rp, origin) = wire::relying_party(state.get_domain())?;
    Ok(ChallengeDB::new(random_challenge(), purpose, rp, origin))
}
fn bind_session(challenge: &mut ChallengeDB, claims: &Claims) {
    challenge.user_id = Some(claims.sub.clone());
    challenge.security_stamp = Some(claims.sstamp.clone());
    challenge.device_id = claims.device().map(str::to_owned);
    challenge.session_token = Some(claims.session_token.clone());
}

pub async fn registration_options(
    state: &AppState,
    claims: &Claims,
    usage: &str,
) -> AppResult<Value> {
    let db = state.get_db();
    let user = UserDB::fetch_by_id_with(
        &db,
        &claims.sub,
        "Failed to fetch WebAuthn user",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    let keys = CredentialDB::list(&db, &claims.sub, usage).await?;
    if keys.len() >= if usage == "2fa" { 5 } else { 20 } {
        return Err(AppError::bad_request("WebAuthn credential limit reached"));
    }
    let mut challenge = new_challenge(state, &format!("register.{usage}"))?;
    bind_session(&mut challenge, claims);
    challenge.account_snapshot = Some(
        crate::models::account_keys::AccountSnapshot::from_user(&user)
            .to_json()?,
    );
    challenge.insert(&db).await?;
    Ok(
        json!({"challenge":challenge.challenge,"rp":{"id":challenge.rp_id,"name":"raywarden"},"user":{"id":URL_SAFE_NO_PAD.encode(user_handle(&user.id)),"name":user.email,"displayName":user.name.unwrap_or(user.email)},"timeout":60000,"attestation":"none","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"authenticatorSelection":{"residentKey":if usage=="login" {"required"}else{"discouraged"},"userVerification":if usage=="login" {"required"}else{"preferred"}},"excludeCredentials":keys.iter().map(|k|json!({"type":"public-key","id":k.credential_id})).collect::<Vec<_>>(),"extensions":{"prf":{}}}),
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAttestation {
    pub response: AttestationResponse,
}
#[derive(Debug, Deserialize)]
pub struct AttestationResponse {
    #[serde(rename = "attestationObject", alias = "AttestationObject")]
    pub attestation_object: String,
    #[serde(rename = "clientDataJSON", alias = "clientDataJson")]
    pub client_data_json:   String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationData {
    pub id:                    Option<i32>,
    pub token:                 Option<String>,
    #[serde(alias = "Name", alias = "keyName", alias = "deviceName")]
    pub name:                  Option<String>,
    pub device_response:       DeviceAttestation,
    pub supports_prf:          Option<bool>,
    pub encrypted_public_key:  Option<String>,
    pub encrypted_user_key:    Option<String>,
    pub encrypted_private_key: Option<String>,
    #[serde(flatten)]
    pub proof:                 SecretVerificationData,
}
fn validate_binding(challenge: &ChallengeDB, claims: &Claims) -> AppResult<()> {
    if challenge.user_id.as_deref() != Some(&claims.sub) ||
        challenge.security_stamp.as_deref() != Some(&claims.sstamp) ||
        challenge.session_token.as_deref() != Some(&claims.session_token) ||
        challenge.device_id.as_deref() != claims.device()
    {
        return Err(wire::invalid("WebAuthn session changed"));
    }
    Ok(())
}
fn validate_encrypted_keys(
    public: &Option<String>,
    user: &Option<String>,
    private: &Option<String>,
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
pub async fn register(
    state: &AppState,
    claims: &Claims,
    payload: RegistrationData,
    usage: &str,
) -> AppResult<()> {
    let db = state.get_db();
    let bytes = wire::decode_b64_any(
        &payload.device_response.response.client_data_json,
    )?;
    let client: wire::ClientDataJson = serde_json::from_slice(&bytes)
        .map_err(|_| wire::invalid("Invalid WebAuthn client data"))?;
    let challenge = ChallengeDB::find_challenge(
        &db,
        &client.challenge,
        &format!("register.{usage}"),
    )
    .await?;
    validate_binding(&challenge, claims)?;
    verify_client(state, &bytes, "webauthn.create", &challenge)?;
    if payload
        .token
        .as_deref()
        .is_some_and(|t| !t.is_empty() && t != challenge.challenge)
    {
        return Err(wire::invalid("WebAuthn challenge token mismatch"));
    }
    let attestation = wire::decode_b64_any(
        &payload.device_response.response.attestation_object,
    )?;
    let (rp_hash, count, id, key) =
        wire::parse_attestation_object(&attestation)?;
    let _ = rp_hash;
    // parse_attestation_object already enforces user presence. Verify UV
    // directly from the original authenticator data rather than synthesizing
    // flags.
    let value: ciborium::value::Value =
        ciborium::de::from_reader(attestation.as_slice())
            .map_err(|_| wire::invalid("Invalid attestation"))?;
    let auth = value
        .as_map()
        .and_then(|m| {
            m.iter().find_map(|(k, v)| {
                if k.as_text() == Some("authData") {
                    v.as_bytes()
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| wire::invalid("Missing authenticator data"))?;
    wire::verify_authenticator_data(
        &wire::parse_auth_data(auth, true)?,
        &challenge.rp_id,
        usage == "login",
    )?;
    wire::parse_webauthn_public_key(&key)?;
    validate_encrypted_keys(
        &payload.encrypted_public_key,
        &payload.encrypted_user_key,
        &payload.encrypted_private_key,
    )?;
    if challenge.account_snapshot.as_deref() !=
        Some(
            crate::models::account_keys::AccountSnapshot::load(
                &db,
                &claims.sub,
            )
            .await?
            .to_json()?
            .as_str(),
        )
    {
        return Err(AppError::conflict(
            "Account encryption changed during passkey registration",
        ));
    }
    let current = CredentialDB::list(&db, &claims.sub, usage).await?;
    let max = if usage == "2fa" { 5 } else { 20 };
    let slot = payload.id.unwrap_or_else(|| {
        (1..=max)
            .find(|slot| !current.iter().any(|k| k.slot == *slot))
            .unwrap_or(0)
    });
    if !(1..=max).contains(&slot) || current.iter().any(|k| k.slot == slot) {
        return Err(AppError::bad_request(
            "WebAuthn key slot is already used or invalid",
        ));
    }
    let prf_status = if payload.supports_prf.unwrap_or(false) {
        if payload.encrypted_user_key.is_some() {
            0
        } else {
            1
        }
    } else {
        2
    };
    if prf_status == 2 &&
        (payload.encrypted_user_key.is_some() ||
            payload.encrypted_private_key.is_some())
    {
        return Err(AppError::bad_request(
            "Encrypted PRF keys require PRF support",
        ));
    }
    let now = now_string();
    let key = CredentialDB {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        slot,
        name: payload.name.unwrap_or_else(|| "Passkey".into()),
        credential_id: URL_SAFE_NO_PAD.encode(id),
        public_key: URL_SAFE_NO_PAD.encode(key),
        sign_count: i64::from(count),
        credential_use: usage.into(),
        prf_status,
        encrypted_public_key: payload.encrypted_public_key,
        encrypted_user_key: payload.encrypted_user_key,
        encrypted_private_key: payload.encrypted_private_key,
        last_challenge: None,
        account_snapshot: challenge.account_snapshot.clone(),
        created_at: now.clone(),
        updated_at: now,
    };
    key.register(&db, &challenge).await?;
    admin_notify::emit(
        &state.env,
        if usage == "login" {
            Event::WebAuthnCredentialCreate
        } else {
            Event::TwoFactorEnable
        },
        &claims.sub,
    )
    .await;
    Ok(())
}

async fn options(
    state: &AppState,
    challenge: ChallengeDB,
    keys: Vec<CredentialDB>,
    require_uv: bool,
) -> AppResult<Value> {
    challenge.insert(&state.get_db()).await?;
    Ok(
        json!({"challenge":challenge.challenge,"rpId":challenge.rp_id,"timeout":60000,"allowCredentials":keys.iter().map(|k|json!({"type":"public-key","id":k.credential_id})).collect::<Vec<_>>(),"userVerification":if require_uv {"required"}else{"preferred"},"extensions":{"prf":{}}}),
    )
}
pub async fn assertion_options(
    state: &AppState,
    claims: &Claims,
) -> AppResult<Value> {
    let keys =
        CredentialDB::list(&state.get_db(), &claims.sub, "login").await?;
    if keys.is_empty() {
        return Err(AppError::not_found("Passkey"));
    }
    let mut challenge = new_challenge(state, "assert.login")?;
    bind_session(&mut challenge, claims);
    challenge.account_snapshot = Some(
        crate::models::account_keys::AccountSnapshot::load(
            &state.get_db(),
            &claims.sub,
        )
        .await?
        .to_json()?,
    );
    options(state, challenge, keys, true).await
}
pub async fn issue_2fa_options(
    state: &AppState,
    user: &UserDB,
    device: &str,
) -> AppResult<Value> {
    let keys = CredentialDB::list(&state.get_db(), &user.id, "2fa").await?;
    if keys.is_empty() {
        return Err(wire::invalid("No WebAuthn two-factor credential"));
    }
    let mut challenge = new_challenge(state, "assert.2fa")?;
    challenge.user_id = Some(user.id.clone());
    challenge.security_stamp = Some(user.security_stamp.clone());
    challenge.account_snapshot = Some(
        crate::models::account_keys::AccountSnapshot::from_user(user)
            .to_json()?,
    );
    challenge.device_id = Some(device.into());
    options(state, challenge, keys, false).await
}

#[derive(Serialize, Deserialize)]
struct LoginChallengeClaims {
    sub:       String,
    exp:       i64,
    nbf:       i64,
    iat:       i64,
    aud:       String,
    purpose:   String,
    challenge: String,
}
pub async fn passwordless_options(
    state: &AppState,
    headers: &HeaderMap,
) -> AppResult<Value> {
    rate::check_rate_limit(
        state,
        format!("passkey-options:{}", rate::client_ip(headers)),
    )
    .await?;
    let mut challenge = new_challenge(state, "login.passwordless")?;
    challenge.device_id = headers
        .get("x-device-identifier")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let now = crate::infra::time::now_seconds();
    let token = LoginChallengeClaims {
        sub:       challenge.id.clone(),
        exp:       now + 300,
        nbf:       now,
        iat:       now,
        aud:       "raywarden.webauthn".into(),
        purpose:   "passwordless".into(),
        challenge: challenge.challenge.clone(),
    };
    let token = jwt::encode(&token, state.config.jwt_secret.as_bytes())?;
    let options = options(state, challenge, Vec::new(), true).await?;
    Ok(json!({"options":options,"token":token}))
}
async fn verify_assertion(
    state: &AppState,
    challenge: &ChallengeDB,
    assertion_json: &str,
    usage: &str,
    require_uv: bool,
) -> AppResult<CredentialDB> {
    let assertion: wire::Assertion = serde_json::from_str(assertion_json)
        .map_err(|_| wire::invalid("Invalid WebAuthn assertion"))?;
    let client = wire::decode_b64_any(&assertion.response.client_data_json)?;
    verify_client(state, &client, "webauthn.get", challenge)?;
    let id = assertion
        .raw_id
        .as_deref()
        .or(assertion.id.as_deref())
        .ok_or_else(|| wire::invalid("Missing WebAuthn credential id"))?;
    let id = wire::decode_b64_any(id)?;
    if let (Some(raw), Some(other)) = (&assertion.raw_id, &assertion.id) {
        if wire::decode_b64_any(raw)? != wire::decode_b64_any(other)? {
            return Err(wire::invalid("WebAuthn credential id mismatch"));
        }
    }
    let key = CredentialDB::find(&state.get_db(), &URL_SAFE_NO_PAD.encode(id))
        .await?
        .filter(|k| k.credential_use == usage)
        .ok_or_else(|| {
            wire::invalid(
                "WebAuthn credential is not registered for this purpose",
            )
        })?;
    if challenge
        .user_id
        .as_deref()
        .is_some_and(|u| u != key.user_id)
    {
        return Err(wire::invalid("WebAuthn credential owner mismatch"));
    }
    if let Some(handle) = assertion.response.user_handle {
        if !handle.is_empty() &&
            wire::decode_b64_any(&handle)? != user_handle(&key.user_id)
        {
            return Err(wire::invalid("WebAuthn user handle mismatch"));
        }
    }
    let auth = wire::decode_b64_any(&assertion.response.authenticator_data)?;
    let parsed = wire::parse_auth_data(&auth, false)?;
    wire::verify_authenticator_data(&parsed, &challenge.rp_id, require_uv)?;
    let public_key = wire::parse_webauthn_public_key(&wire::decode_b64_any(
        &key.public_key,
    )?)?
    .0;
    let mut signed = auth;
    signed.extend_from_slice(&Sha256::digest(&client));
    public_key.verify(
        &signed,
        &wire::decode_b64_any(&assertion.response.signature)?,
    )?;
    let count = i64::from(parsed.sign_count);
    wire::verify_counter(key.sign_count, count)?;
    key.accept_assertion(&state.get_db(), challenge, count)
        .await?;
    Ok(key)
}
fn challenge_from_assertion(value: &str) -> AppResult<String> {
    let assertion: wire::Assertion = serde_json::from_str(value)
        .map_err(|_| wire::invalid("Invalid WebAuthn assertion"))?;
    let client: wire::ClientDataJson = serde_json::from_slice(
        &wire::decode_b64_any(&assertion.response.client_data_json)?,
    )
    .map_err(|_| wire::invalid("Invalid WebAuthn client data"))?;
    Ok(client.challenge)
}
pub async fn verify_2fa(
    state: &AppState,
    user: &UserDB,
    device: &str,
    assertion: &str,
) -> AppResult<()> {
    let challenge = ChallengeDB::find_challenge(
        &state.get_db(),
        &challenge_from_assertion(assertion)?,
        "assert.2fa",
    )
    .await?;
    if challenge.user_id.as_deref() != Some(user.id.as_str()) ||
        challenge.security_stamp.as_deref() !=
            Some(user.security_stamp.as_str()) ||
        challenge.device_id.as_deref() != Some(device)
    {
        return Err(wire::invalid(
            "WebAuthn login challenge belongs to another session",
        ));
    }
    verify_assertion(state, &challenge, assertion, "2fa", false).await?;
    Ok(())
}
#[derive(Debug)]
pub struct PasswordlessLoginResult {
    pub account_snapshot:      String,
    pub user_id:               String,
    pub encrypted_user_key:    Option<String>,
    pub encrypted_private_key: Option<String>,
}
pub async fn verify_passwordless(
    state: &AppState,
    token: &str,
    assertion: &str,
    device: &str,
) -> AppResult<PasswordlessLoginResult> {
    let value = jwt::decode::<LoginChallengeClaims>(
        token,
        state.config.jwt_secret.as_bytes(),
        &jwt::ValidationOptions {
            leeway: 0,
            ..Default::default()
        },
    )?
    .claims;
    if value.aud != "raywarden.webauthn" || value.purpose != "passwordless" {
        return Err(wire::invalid("Invalid passkey login token"));
    }
    let challenge = ChallengeDB::find_challenge(
        &state.get_db(),
        &value.challenge,
        "login.passwordless",
    )
    .await?;
    if challenge.id != value.sub ||
        challenge.device_id.as_deref().is_some_and(|d| d != device)
    {
        return Err(wire::invalid("Passkey login device mismatch"));
    }
    let key =
        verify_assertion(state, &challenge, assertion, "login", true).await?;
    let current = crate::models::account_keys::AccountSnapshot::load(
        &state.get_db(),
        &key.user_id,
    )
    .await?
    .to_json()?;
    let has_current_prf =
        key.account_snapshot.as_deref() == Some(current.as_str());
    Ok(PasswordlessLoginResult {
        account_snapshot:      current,
        user_id:               key.user_id,
        encrypted_user_key:    if key.prf_status == 0 && has_current_prf {
            key.encrypted_user_key
        } else {
            None
        },
        encrypted_private_key: if key.prf_status == 0 && has_current_prf {
            key.encrypted_private_key
        } else {
            None
        },
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCredentialData {
    pub token:                 Option<String>,
    pub name:                  Option<String>,
    pub device_response:       Value,
    pub encrypted_public_key:  Option<String>,
    pub encrypted_user_key:    Option<String>,
    pub encrypted_private_key: Option<String>,
}
pub async fn update_credential(
    state: &AppState,
    claims: &Claims,
    id: &str,
    payload: UpdateCredentialData,
) -> AppResult<()> {
    validate_encrypted_keys(
        &payload.encrypted_public_key,
        &payload.encrypted_user_key,
        &payload.encrypted_private_key,
    )?;
    if payload.encrypted_user_key.is_none() {
        return Err(AppError::bad_request(
            "Both encrypted PRF keys are required",
        ));
    }
    let assertion = serde_json::to_string(&payload.device_response)
        .map_err(|_| AppError::Internal)?;
    let challenge = ChallengeDB::find_challenge(
        &state.get_db(),
        &challenge_from_assertion(&assertion)?,
        "assert.login",
    )
    .await?;
    validate_binding(&challenge, claims)?;
    if payload
        .token
        .as_deref()
        .is_some_and(|t| !t.is_empty() && t != challenge.challenge)
    {
        return Err(wire::invalid("WebAuthn challenge token mismatch"));
    }
    let expected =
        CredentialDB::find_owned(&state.get_db(), &claims.sub, "login", id)
            .await?;
    let mut key =
        verify_assertion(state, &challenge, &assertion, "login", true).await?;
    if key.id != expected.id {
        return Err(wire::invalid(
            "The asserted credential does not match the updated credential",
        ));
    }
    let snapshot = crate::models::account_keys::AccountSnapshot::load(
        &state.get_db(),
        &claims.sub,
    )
    .await?
    .to_json()?;
    if challenge.account_snapshot.as_deref() != Some(snapshot.as_str()) {
        return Err(AppError::conflict(
            "Account encryption changed during PRF update",
        ));
    }
    key.account_snapshot = Some(snapshot);
    key.encrypted_public_key = payload.encrypted_public_key;
    key.encrypted_user_key = payload.encrypted_user_key;
    key.encrypted_private_key = payload.encrypted_private_key;
    key.prf_status = 0;
    if let Some(name) = payload.name {
        key.name = name;
    }
    key.update_keys(&state.get_db()).await?;
    admin_notify::emit(
        &state.env,
        Event::WebAuthnCredentialUpdate,
        &claims.sub,
    )
    .await;
    Ok(())
}
