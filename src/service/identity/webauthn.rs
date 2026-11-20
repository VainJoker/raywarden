mod protocol;

use axum::http::HeaderMap;
use base64::{
    Engine as _,
    engine::general_purpose::URL_SAFE_NO_PAD,
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use sha2::{
    Digest,
    Sha256,
};
use uuid::Uuid;

use self::protocol as wire;
use crate::{
    app::AppContext,
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    infra::jwt,
    models::identity::{
        user::UserRow,
        webauthn::{
            WebauthnChallengeRow,
            WebauthnCredentialRow,
        },
    },
    service::{
        identity::{
            session::Claims,
            user::AccountVerificationRequest,
        },
        notifications::{
            admin as admin_notify,
            admin::Event,
        },
        rate_limit,
    },
};

pub async fn verify_two_factor_authorization(
    state: &AppContext,
    claims: &Claims,
    payload: &AccountVerificationRequest,
) -> AppResult<()> {
    if let Some(token) = payload.user_verification_token.as_deref() {
        if payload.master_password_hash.is_some() || payload.otp.is_some() {
            return Err(AppError::bad_request(
                "Provide exactly one verification method",
            ));
        }
        return verify_user_verification_token(state, claims, token).await;
    }
    crate::service::identity::email::verify_password_or_otp(
        state, claims, payload,
    )
    .await
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
async fn credential_state(state: &AppContext, user: &str) -> AppResult<String> {
    let keys =
        WebauthnCredentialRow::list(state.database(), user, "2fa").await?;
    let mut bytes = serde_json::to_vec(
        &keys
            .iter()
            .map(|k| (&k.id, &k.credential_id))
            .collect::<Vec<_>>(),
    )
    .map_err(AppError::internal_error)?;
    bytes.extend_from_slice(
        crate::models::identity::account_keys::AccountSnapshot::load(
            state.database(),
            user,
        )
        .await?
        .to_json()?
        .as_bytes(),
    );
    Ok(hex::encode(Sha256::digest(bytes)))
}
pub async fn mint_user_verification_token(
    state: &AppContext,
    claims: &Claims,
) -> AppResult<String> {
    let now = crate::utils::time::now_seconds();
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
    Ok(jwt::encode(
        &token,
        state.jwt_keys.access_secret.as_bytes(),
    )?)
}
pub async fn verify_user_verification_token(
    state: &AppContext,
    claims: &Claims,
    token: &str,
) -> AppResult<()> {
    let value = jwt::decode::<VerificationClaims>(
        token,
        state.jwt_keys.access_secret.as_bytes(),
        &jwt::ValidationOptions {
            leeway_seconds: 0,
            ..Default::default()
        },
    )?;
    if value.aud != "raywarden.webauthn" ||
        value.purpose != "manage-2fa" ||
        value.sub != claims.sub ||
        value.stamp != claims.sstamp ||
        value.session != claims.session_token ||
        Some(value.device.as_str()) != claims.device() ||
        value.credential_state !=
            credential_state(state, &claims.sub).await?
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
    state: &AppContext,
    client: &wire::ClientData,
    kind: &str,
    challenge: &WebauthnChallengeRow,
) -> AppResult<()> {
    let allowed = state
        .env
        .var("WEBAUTHN_ALLOWED_ORIGINS")
        .map_or_else(|_| String::new(), |value| value.to_string());
    client.verify(kind, &challenge.challenge, &challenge.origin, &allowed)
}

fn user_handle(user: &str) -> Vec<u8> {
    Uuid::parse_str(user)
        .map_or_else(|_| user.as_bytes().to_vec(), |u| u.as_bytes().to_vec())
}
fn new_challenge(
    state: &AppContext,
    purpose: &str,
) -> AppResult<WebauthnChallengeRow> {
    let (rp, origin) = wire::relying_party(state.domain())?;
    Ok(new_challenge_record(
        random_challenge(),
        purpose,
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
#[serde(rename_all = "camelCase")]
pub(crate) struct RegistrationOptions {
    pub(crate) challenge: String,
    rp: RelyingParty,
    user: RegistrationUser,
    timeout: u32,
    attestation: &'static str,
    pub_key_cred_params: [CredentialAlgorithm; 2],
    authenticator_selection: AuthenticatorSelection,
    exclude_credentials: Vec<CredentialDescriptor>,
    extensions: CredentialExtensions,
}

#[derive(Serialize)]
struct RelyingParty {
    id:   String,
    name: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationUser {
    id:           String,
    name:         String,
    display_name: String,
}

#[derive(Serialize)]
struct CredentialAlgorithm {
    #[serde(rename = "type")]
    kind: &'static str,
    alg:  i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSelection {
    resident_key:      &'static str,
    user_verification: &'static str,
}

#[derive(Serialize)]
struct CredentialDescriptor {
    #[serde(rename = "type")]
    kind: &'static str,
    id:   String,
}

impl From<WebauthnCredentialRow> for CredentialDescriptor {
    fn from(row: WebauthnCredentialRow) -> Self {
        Self {
            kind: "public-key",
            id:   row.credential_id,
        }
    }
}

#[derive(Default, Serialize)]
struct CredentialExtensions {
    prf: PrfExtension,
}

#[derive(Default, Serialize)]
struct PrfExtension {}

pub(crate) async fn registration_options(
    state: &AppContext,
    claims: &Claims,
    usage: CredentialUse,
) -> AppResult<RegistrationOptions> {
    let db = state.database();
    let user = UserRow::fetch_by_id_with(
        db,
        &claims.sub,
        "Failed to fetch WebAuthn user",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    let keys =
        WebauthnCredentialRow::list(db, &claims.sub, usage.as_str()).await?;
    if keys.len() >= usage.credential_limit() as usize {
        return Err(AppError::bad_request("WebAuthn credential limit reached"));
    }
    let mut challenge =
        new_challenge(state, &format!("register.{}", usage.as_str()))?;
    bind_session(&mut challenge, claims);
    challenge.account_snapshot = Some(
        crate::models::identity::account_keys::AccountSnapshot::from_user(
            &user,
        )
        .to_json()?,
    );
    challenge.insert(db).await?;
    let require_uv = usage.requires_user_verification();
    Ok(RegistrationOptions {
        challenge: challenge.challenge,
        rp: RelyingParty {
            id:   challenge.rp_id,
            name: "raywarden",
        },
        user: RegistrationUser {
            id:           URL_SAFE_NO_PAD.encode(user_handle(&user.id)),
            name:         user.email.clone(),
            display_name: user.name.unwrap_or(user.email),
        },
        timeout: 60000,
        attestation: "none",
        pub_key_cred_params: [
            CredentialAlgorithm {
                kind: "public-key",
                alg:  -7,
            },
            CredentialAlgorithm {
                kind: "public-key",
                alg:  -257,
            },
        ],
        authenticator_selection: AuthenticatorSelection {
            resident_key:      if require_uv {
                "required"
            } else {
                "discouraged"
            },
            user_verification: if require_uv {
                "required"
            } else {
                "preferred"
            },
        },
        exclude_credentials: keys.into_iter().map(Into::into).collect(),
        extensions: CredentialExtensions::default(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnAttestation {
    pub response: WebauthnAttestationResponse,
}
#[derive(Debug, Deserialize)]
pub struct WebauthnAttestationResponse {
    #[serde(rename = "attestationObject", alias = "AttestationObject")]
    pub attestation_object: String,
    #[serde(rename = "clientDataJSON", alias = "clientDataJson")]
    pub client_data_json:   String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWebauthnCredentialRequest {
    pub id:                    Option<i32>,
    pub token:                 Option<String>,
    #[serde(
        alias = "Name",
        alias = "keyName",
        alias = "KeyName",
        alias = "deviceName",
        alias = "DeviceName"
    )]
    pub name:                  Option<String>,
    pub device_response:       WebauthnAttestation,
    pub supports_prf:          Option<bool>,
    pub encrypted_public_key:  Option<String>,
    pub encrypted_user_key:    Option<String>,
    pub encrypted_private_key: Option<String>,
    #[serde(flatten)]
    // Parsed for request compatibility; authorization is bound to the
    // challenge.
    pub _proof: AccountVerificationRequest,
}
fn validate_binding(
    challenge: &WebauthnChallengeRow,
    claims: &Claims,
) -> AppResult<()> {
    if challenge.user_id.as_deref() != Some(&claims.sub) ||
        challenge.security_stamp.as_deref() != Some(&claims.sstamp) ||
        challenge.session_token.as_deref() != Some(&claims.session_token) ||
        challenge.device_id.as_deref() != claims.device()
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
#[allow(
    clippy::too_many_lines,
    reason = "Keep WebAuthn attestation validation and its guarded credential \
              registration together"
)]
pub(crate) async fn register(
    state: &AppContext,
    claims: &Claims,
    payload: RegisterWebauthnCredentialRequest,
    usage: CredentialUse,
) -> AppResult<WebauthnCredentialRow> {
    let db = state.database();
    let client = wire::ClientData::parse(wire::decode_base64(
        &payload.device_response.response.client_data_json,
    )?)?;
    let challenge = WebauthnChallengeRow::find_challenge(
        db,
        client.challenge(),
        &format!("register.{}", usage.as_str()),
    )
    .await?;
    validate_binding(&challenge, claims)?;
    verify_client(state, &client, "webauthn.create", &challenge)?;
    if payload
        .token
        .as_deref()
        .is_some_and(|t| !t.is_empty() && t != challenge.challenge)
    {
        return Err(AppError::invalid_credentials(
            "WebAuthn challenge token mismatch",
        ));
    }
    let attestation = wire::decode_base64(
        &payload.device_response.response.attestation_object,
    )?;
    let parsed = wire::parse_attestation_object(&attestation)?;
    wire::verify_authenticator_data(
        &parsed,
        &challenge.rp_id,
        usage.requires_user_verification(),
    )?;
    let count = parsed.sign_count;
    let id = parsed.credential_id.ok_or(AppError::Internal)?;
    let key = parsed
        .credential_public_key_cose
        .ok_or(AppError::Internal)?;
    wire::parse_webauthn_public_key(&key)?;
    validate_encrypted_keys(
        payload.encrypted_public_key.as_deref(),
        payload.encrypted_user_key.as_deref(),
        payload.encrypted_private_key.as_deref(),
    )?;
    if challenge.account_snapshot.as_deref() !=
        Some(
            crate::models::identity::account_keys::AccountSnapshot::load(
                db,
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
    let current =
        WebauthnCredentialRow::list(db, &claims.sub, usage.as_str()).await?;
    let max = usage.credential_limit();
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
        i32::from(
            !(payload.encrypted_user_key.is_some() &&
                payload.encrypted_private_key.is_some() &&
                payload.encrypted_public_key.is_some()),
        )
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
    let now = crate::utils::time::now_rfc3339();
    let key = WebauthnCredentialRow {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        slot,
        name: payload.name.unwrap_or_else(|| "Passkey".into()),
        credential_id: URL_SAFE_NO_PAD.encode(id),
        public_key: URL_SAFE_NO_PAD.encode(key),
        sign_count: i64::from(count),
        credential_use: usage.as_str().into(),
        prf_status,
        encrypted_public_key: payload.encrypted_public_key,
        encrypted_user_key: payload.encrypted_user_key,
        encrypted_private_key: payload.encrypted_private_key,
        last_challenge: None,
        account_snapshot: challenge.account_snapshot.clone(),
        created_at: now.clone(),
        updated_at: now,
    };
    key.register(db, &challenge).await?;
    admin_notify::emit(
        &state.env,
        if usage.requires_user_verification() {
            Event::WebauthnCredentialCreate
        } else {
            Event::TwoFactorEnable
        },
        &claims.sub,
    )
    .await;
    Ok(key)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssertionOptions {
    pub(crate) challenge: String,
    rp_id:                String,
    timeout:              u32,
    allow_credentials:    Vec<CredentialDescriptor>,
    user_verification:    &'static str,
    extensions:           CredentialExtensions,
}

#[derive(Serialize)]
pub(crate) struct AssertionOptionsResponse {
    pub(crate) options: AssertionOptions,
    pub(crate) token:   String,
}

async fn options(
    state: &AppContext,
    challenge: WebauthnChallengeRow,
    keys: Vec<WebauthnCredentialRow>,
    require_uv: bool,
) -> AppResult<AssertionOptions> {
    challenge.insert(state.database()).await?;
    Ok(AssertionOptions {
        challenge:         challenge.challenge,
        rp_id:             challenge.rp_id,
        timeout:           60000,
        allow_credentials: keys.into_iter().map(Into::into).collect(),
        user_verification: if require_uv { "required" } else { "preferred" },
        extensions:        CredentialExtensions::default(),
    })
}
pub(crate) async fn assertion_options(
    state: &AppContext,
    claims: &Claims,
) -> AppResult<AssertionOptions> {
    let keys =
        WebauthnCredentialRow::list(state.database(), &claims.sub, "login")
            .await?;
    if keys.is_empty() {
        return Err(AppError::not_found("Passkey"));
    }
    let mut challenge = new_challenge(state, "assert.login")?;
    bind_session(&mut challenge, claims);
    challenge.account_snapshot = Some(
        crate::models::identity::account_keys::AccountSnapshot::load(
            state.database(),
            &claims.sub,
        )
        .await?
        .to_json()?,
    );
    options(state, challenge, keys, true).await
}
pub async fn two_factor_assertion_options(
    state: &AppContext,
    user: &UserRow,
    device: &str,
) -> AppResult<Value> {
    let keys =
        WebauthnCredentialRow::list(state.database(), &user.id, "2fa").await?;
    if keys.is_empty() {
        return Err(AppError::invalid_credentials(
            "No WebAuthn two-factor credential",
        ));
    }
    let mut challenge = new_challenge(state, "assert.2fa")?;
    challenge.user_id = Some(user.id.clone());
    challenge.security_stamp = Some(user.security_stamp.clone());
    challenge.account_snapshot = Some(
        crate::models::identity::account_keys::AccountSnapshot::from_user(user)
            .to_json()?,
    );
    challenge.device_id = Some(device.into());
    let options = options(state, challenge, keys, false).await?;
    serde_json::to_value(options).map_err(AppError::internal_error)
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
pub(crate) async fn passwordless_options(
    state: &AppContext,
    headers: &HeaderMap,
) -> AppResult<AssertionOptionsResponse> {
    rate_limit::check_auth_attempt(
        state,
        format!("passkey-options:{}", rate_limit::client_ip(headers)),
    )
    .await?;
    let mut challenge = new_challenge(state, "login.passwordless")?;
    challenge.device_id = headers
        .get("x-device-identifier")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let now = crate::utils::time::now_seconds();
    let token = LoginChallengeClaims {
        sub:       challenge.id.clone(),
        exp:       now + 300,
        nbf:       now,
        iat:       now,
        aud:       "raywarden.webauthn".into(),
        purpose:   "passwordless".into(),
        challenge: challenge.challenge.clone(),
    };
    let token = jwt::encode(&token, state.jwt_keys.access_secret.as_bytes())?;
    let options = options(state, challenge, Vec::new(), true).await?;
    Ok(AssertionOptionsResponse { options, token })
}
struct CredentialAssertion {
    assertion:   wire::Assertion,
    client_data: wire::ClientData,
}

impl CredentialAssertion {
    fn parse(json: &str) -> AppResult<Self> {
        let assertion: wire::Assertion =
            serde_json::from_str(json).map_err(|_error| {
                AppError::invalid_credentials("Invalid WebAuthn assertion")
            })?;
        let client_data = wire::ClientData::parse(wire::decode_base64(
            &assertion.response.client_data_json,
        )?)?;
        Ok(Self {
            assertion,
            client_data,
        })
    }

    async fn verify(
        self,
        state: &AppContext,
        challenge: &WebauthnChallengeRow,
        usage: CredentialUse,
        expected_credential_id: Option<&str>,
    ) -> AppResult<WebauthnCredentialRow> {
        let Self {
            assertion,
            client_data: client,
        } = self;
        verify_client(state, &client, "webauthn.get", challenge)?;
        let id = assertion
            .raw_id
            .as_deref()
            .or(assertion.id.as_deref())
            .ok_or_else(|| {
                AppError::invalid_credentials("Missing WebAuthn credential id")
            })?;
        let id = wire::decode_base64(id)?;
        if let (Some(raw), Some(other)) = (&assertion.raw_id, &assertion.id) &&
            wire::decode_base64(raw)? != wire::decode_base64(other)?
        {
            return Err(AppError::invalid_credentials(
                "WebAuthn credential id mismatch",
            ));
        }
        let mut key = WebauthnCredentialRow::find(
            state.database(),
            &URL_SAFE_NO_PAD.encode(id),
        )
        .await?
        .filter(|k| k.credential_use == usage.as_str())
        .ok_or_else(|| {
            AppError::invalid_credentials(
                "WebAuthn credential is not registered for this purpose",
            )
        })?;
        if challenge
            .user_id
            .as_deref()
            .is_some_and(|u| u != key.user_id)
        {
            return Err(AppError::invalid_credentials(
                "WebAuthn credential owner mismatch",
            ));
        }
        if let Some(handle) = assertion.response.user_handle &&
            !handle.is_empty() &&
            wire::decode_base64(&handle)? != user_handle(&key.user_id)
        {
            return Err(AppError::invalid_credentials(
                "WebAuthn user handle mismatch",
            ));
        }
        let auth = wire::decode_base64(&assertion.response.authenticator_data)?;
        let parsed = wire::parse_authenticator_data(&auth, false)?;
        wire::verify_authenticator_data(
            &parsed,
            &challenge.rp_id,
            usage.requires_user_verification(),
        )?;
        let public_key = wire::parse_webauthn_public_key(
            &wire::decode_base64(&key.public_key)?,
        )?
        .0;
        let mut signed = auth;
        signed.extend_from_slice(&Sha256::digest(client.bytes()));
        public_key.verify(
            &signed,
            &wire::decode_base64(&assertion.response.signature)?,
        )?;
        let count = i64::from(parsed.sign_count);
        wire::verify_counter(key.sign_count, count)?;
        if expected_credential_id.is_some_and(|id| key.id != id) {
            return Err(AppError::invalid_credentials(
                "The asserted credential does not match the updated credential",
            ));
        }
        key.accept_assertion(state.database(), challenge, count)
            .await?;
        key.sign_count = key.sign_count.max(count);
        key.last_challenge = Some(challenge.id.clone());
        Ok(key)
    }
}

pub async fn verify_two_factor_assertion(
    state: &AppContext,
    user: &UserRow,
    device: &str,
    assertion: &str,
) -> AppResult<()> {
    let assertion = CredentialAssertion::parse(assertion)?;
    let challenge = WebauthnChallengeRow::find_challenge(
        state.database(),
        assertion.client_data.challenge(),
        "assert.2fa",
    )
    .await?;
    if challenge.user_id.as_deref() != Some(user.id.as_str()) ||
        challenge.security_stamp.as_deref() !=
            Some(user.security_stamp.as_str()) ||
        challenge.device_id.as_deref() != Some(device)
    {
        return Err(AppError::invalid_credentials(
            "WebAuthn login challenge belongs to another session",
        ));
    }
    assertion
        .verify(state, &challenge, CredentialUse::TwoFactor, None)
        .await?;
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
    state: &AppContext,
    token: &str,
    assertion: &str,
    device: &str,
) -> AppResult<PasswordlessLoginResult> {
    let value = jwt::decode::<LoginChallengeClaims>(
        token,
        state.jwt_keys.access_secret.as_bytes(),
        &jwt::ValidationOptions {
            leeway_seconds: 0,
            ..Default::default()
        },
    )?;
    if value.aud != "raywarden.webauthn" || value.purpose != "passwordless" {
        return Err(AppError::invalid_credentials(
            "Invalid passkey login token",
        ));
    }
    let challenge = WebauthnChallengeRow::find_challenge(
        state.database(),
        &value.challenge,
        "login.passwordless",
    )
    .await?;
    if challenge.id != value.sub ||
        challenge.device_id.as_deref().is_some_and(|d| d != device)
    {
        return Err(AppError::invalid_credentials(
            "Passkey login device mismatch",
        ));
    }
    let key = CredentialAssertion::parse(assertion)?
        .verify(state, &challenge, CredentialUse::Login, None)
        .await?;
    let current = crate::models::identity::account_keys::AccountSnapshot::load(
        state.database(),
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
pub struct UpdateWebauthnCredentialRequest {
    pub token:                 Option<String>,
    pub name:                  Option<String>,
    pub device_response:       Value,
    pub encrypted_public_key:  Option<String>,
    pub encrypted_user_key:    Option<String>,
    pub encrypted_private_key: Option<String>,
}
pub async fn update_credential(
    state: &AppContext,
    claims: &Claims,
    id: &str,
    payload: UpdateWebauthnCredentialRequest,
) -> AppResult<()> {
    validate_encrypted_keys(
        payload.encrypted_public_key.as_deref(),
        payload.encrypted_user_key.as_deref(),
        payload.encrypted_private_key.as_deref(),
    )?;
    if payload.encrypted_user_key.is_none() ||
        payload.encrypted_public_key.is_none()
    {
        return Err(AppError::bad_request(
            "Encrypted public, user and private PRF keys are required",
        ));
    }
    let assertion = serde_json::to_string(&payload.device_response)
        .map_err(AppError::internal_error)?;
    let assertion = CredentialAssertion::parse(&assertion)?;
    let challenge = WebauthnChallengeRow::find_challenge(
        state.database(),
        assertion.client_data.challenge(),
        "assert.login",
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
    let expected = WebauthnCredentialRow::find_owned(
        state.database(),
        &claims.sub,
        "login",
        id,
    )
    .await?;
    let mut key = assertion
        .verify(state, &challenge, CredentialUse::Login, Some(&expected.id))
        .await?;
    let snapshot =
        crate::models::identity::account_keys::AccountSnapshot::load(
            state.database(),
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
    key.update_keys(state.database(), &claims.session_snapshot()?)
        .await?;
    admin_notify::emit(
        &state.env,
        Event::WebauthnCredentialUpdate,
        &claims.sub,
    )
    .await;
    Ok(())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialResponse {
    id: i32,
    #[serde(rename = "Id")]
    legacy_id: i32,
    name: String,
    #[serde(rename = "Name")]
    legacy_name: String,
    prf_status: i32,
    #[serde(rename = "PrfStatus")]
    legacy_prf_status: i32,
    encrypted_public_key: Option<String>,
    #[serde(rename = "EncryptedPublicKey")]
    legacy_encrypted_public_key: Option<String>,
    encrypted_public_key_object: Option<EncryptedString>,
    #[serde(rename = "EncryptedPublicKeyObj")]
    legacy_encrypted_public_key_object: Option<EncryptedString>,
    encrypted_user_key: Option<String>,
    #[serde(rename = "EncryptedUserKey")]
    legacy_encrypted_user_key: Option<String>,
    encrypted_user_key_object: Option<EncryptedString>,
    #[serde(rename = "EncryptedUserKeyObj")]
    legacy_encrypted_user_key_object: Option<EncryptedString>,
    encrypted_private_key: Option<String>,
    #[serde(rename = "EncryptedPrivateKey")]
    legacy_encrypted_private_key: Option<String>,
    encrypted_private_key_object: Option<EncryptedString>,
    #[serde(rename = "EncryptedPrivateKeyObj")]
    legacy_encrypted_private_key_object: Option<EncryptedString>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedString {
    encrypted_string: String,
}

impl From<WebauthnCredentialRow> for CredentialResponse {
    fn from(row: WebauthnCredentialRow) -> Self {
        let encrypted_object = |value: &Option<String>| {
            value
                .clone()
                .map(|encrypted_string| EncryptedString { encrypted_string })
        };
        Self {
            id: row.slot,
            legacy_id: row.slot,
            legacy_name: row.name.clone(),
            name: row.name,
            prf_status: row.prf_status,
            legacy_prf_status: row.prf_status,
            encrypted_public_key_object: encrypted_object(
                &row.encrypted_public_key,
            ),
            legacy_encrypted_public_key_object: encrypted_object(
                &row.encrypted_public_key,
            ),
            legacy_encrypted_public_key: row.encrypted_public_key.clone(),
            encrypted_public_key: row.encrypted_public_key,
            encrypted_user_key_object: encrypted_object(
                &row.encrypted_user_key,
            ),
            legacy_encrypted_user_key_object: encrypted_object(
                &row.encrypted_user_key,
            ),
            legacy_encrypted_user_key: row.encrypted_user_key.clone(),
            encrypted_user_key: row.encrypted_user_key,
            encrypted_private_key_object: encrypted_object(
                &row.encrypted_private_key,
            ),
            legacy_encrypted_private_key_object: encrypted_object(
                &row.encrypted_private_key,
            ),
            legacy_encrypted_private_key: row.encrypted_private_key.clone(),
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
