use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, Env};

use super::{
    ChallengePurpose, CredentialDescriptor, CredentialExtensions, CredentialUse, new_challenge,
    protocol as wire, user_handle, validate_binding, validate_encrypted_keys, verify_client,
};
use crate::{
    errors::{AppError, AppResult, AuthError},
    models::identity::{
        account_keys::AccountSnapshot,
        user::UserRow,
        webauthn::{WebauthnChallengeRow, WebauthnCredentialRow},
    },
    service::{
        identity::{session::Claims, user::AccountVerificationRequest},
        notifications::{admin as admin_notify, admin::Event},
    },
};

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
    id: String,
    name: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationUser {
    id: String,
    name: String,
    display_name: String,
}

#[derive(Serialize)]
struct CredentialAlgorithm {
    #[serde(rename = "type")]
    kind: &'static str,
    alg: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSelection {
    resident_key: &'static str,
    user_verification: &'static str,
}

pub(crate) async fn registration_options(
    db: &D1Database,
    domain: &str,
    claims: &Claims,
    usage: CredentialUse,
) -> AppResult<RegistrationOptions> {
    let user = UserRow::fetch_by_id_with(db, &claims.sub, "Failed to fetch WebAuthn user", || {
        AuthError::UserNotFound.into()
    })
    .await?;
    let keys = WebauthnCredentialRow::list(db, &claims.sub, usage.as_str()).await?;
    if keys.len() >= usage.credential_limit() as usize {
        return Err(AppError::bad_request("WebAuthn credential limit reached"));
    }
    let mut challenge = new_challenge(domain, ChallengePurpose::register(usage))?;
    super::bind_session(&mut challenge, claims);
    challenge.account_snapshot = Some(AccountSnapshot::json_from_user(&user)?);
    challenge.insert(db).await?;
    let require_uv = usage.requires_user_verification();
    Ok(RegistrationOptions {
        challenge: challenge.challenge,
        rp: RelyingParty {
            id: challenge.rp_id,
            name: "raywarden",
        },
        user: RegistrationUser {
            id: URL_SAFE_NO_PAD.encode(user_handle(&user.id)),
            name: user.email.clone(),
            display_name: user.name.unwrap_or(user.email),
        },
        timeout: 60000,
        attestation: "none",
        pub_key_cred_params: [
            CredentialAlgorithm {
                kind: "public-key",
                alg: -7,
            },
            CredentialAlgorithm {
                kind: "public-key",
                alg: -257,
            },
        ],
        authenticator_selection: AuthenticatorSelection {
            resident_key: if require_uv {
                "required"
            } else {
                "discouraged"
            },
            user_verification: if require_uv { "required" } else { "preferred" },
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
    pub client_data_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWebauthnCredentialRequest {
    pub id: Option<i32>,
    pub token: Option<String>,
    #[serde(
        alias = "Name",
        alias = "keyName",
        alias = "KeyName",
        alias = "deviceName",
        alias = "DeviceName"
    )]
    pub name: Option<String>,
    pub device_response: WebauthnAttestation,
    pub supports_prf: Option<bool>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_user_key: Option<String>,
    pub encrypted_private_key: Option<String>,
    #[serde(flatten)]
    // Parsed for request compatibility; authorization is bound to the
    // challenge.
    pub _proof: AccountVerificationRequest,
}

struct RegistrationCeremony<'a> {
    db: &'a D1Database,
    env: &'a Env,
    claims: &'a Claims,
    usage: CredentialUse,
}

struct VerifiedAttestation {
    challenge: WebauthnChallengeRow,
    credential_id: String,
    public_key: String,
    sign_count: u32,
}

impl RegistrationCeremony<'_> {
    async fn verify(
        &self,
        payload: &RegisterWebauthnCredentialRequest,
    ) -> AppResult<VerifiedAttestation> {
        let client = wire::ClientData::parse(wire::decode_base64(
            &payload.device_response.response.client_data_json,
        )?)?;
        let challenge = WebauthnChallengeRow::find_challenge(
            self.db,
            client.challenge(),
            ChallengePurpose::register(self.usage).as_str(),
        )
        .await?;
        validate_binding(&challenge, self.claims)?;
        verify_client(self.env, &client, "webauthn.create", &challenge)?;
        if payload
            .token
            .as_deref()
            .is_some_and(|t| !t.is_empty() && t != challenge.challenge)
        {
            return Err(AppError::invalid_credentials(
                "WebAuthn challenge token mismatch",
            ));
        }
        let attestation =
            wire::decode_base64(&payload.device_response.response.attestation_object)?;
        let parsed = wire::parse_attestation_object(&attestation)?;
        wire::verify_authenticator_data(
            &parsed,
            &challenge.rp_id,
            self.usage.requires_user_verification(),
        )?;
        let sign_count = parsed.sign_count;
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
        let current_snapshot = AccountSnapshot::load(self.db, &self.claims.sub)
            .await?
            .to_json()?;
        if challenge.account_snapshot.as_deref() != Some(current_snapshot.as_str()) {
            return Err(AppError::conflict(
                "Account encryption changed during passkey registration",
            ));
        }
        Ok(VerifiedAttestation {
            challenge,
            credential_id: URL_SAFE_NO_PAD.encode(id),
            public_key: URL_SAFE_NO_PAD.encode(key),
            sign_count,
        })
    }

    async fn persist(
        &self,
        payload: RegisterWebauthnCredentialRequest,
        verified: VerifiedAttestation,
    ) -> AppResult<WebauthnCredentialRow> {
        let VerifiedAttestation {
            challenge,
            credential_id,
            public_key,
            sign_count,
        } = verified;
        let current =
            WebauthnCredentialRow::list(self.db, &self.claims.sub, self.usage.as_str()).await?;
        let max = self.usage.credential_limit();
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
        let prf_status = registration_prf_status(&payload)?;
        let now = crate::utils::time::now_rfc3339();
        let key = WebauthnCredentialRow {
            id: Uuid::new_v4().to_string(),
            user_id: self.claims.sub.clone(),
            slot,
            name: payload.name.unwrap_or_else(|| "Passkey".into()),
            credential_id,
            public_key,
            sign_count: i64::from(sign_count),
            credential_use: self.usage.as_str().into(),
            prf_status,
            encrypted_public_key: payload.encrypted_public_key,
            encrypted_user_key: payload.encrypted_user_key,
            encrypted_private_key: payload.encrypted_private_key,
            last_challenge: None,
            account_snapshot: challenge.account_snapshot.clone(),
            created_at: now.clone(),
            updated_at: now,
        };
        key.register(self.db, &challenge).await?;
        admin_notify::emit(
            self.env,
            if self.usage.requires_user_verification() {
                Event::WebauthnCredentialCreate
            } else {
                Event::TwoFactorEnable
            },
            &self.claims.sub,
        )
        .await;
        Ok(key)
    }
}

pub(crate) async fn register(
    db: &D1Database,
    env: &Env,
    claims: &Claims,
    payload: RegisterWebauthnCredentialRequest,
    usage: CredentialUse,
) -> AppResult<WebauthnCredentialRow> {
    let ceremony = RegistrationCeremony {
        db,
        env,
        claims,
        usage,
    };
    let verified = ceremony.verify(&payload).await?;
    ceremony.persist(payload, verified).await
}

fn registration_prf_status(payload: &RegisterWebauthnCredentialRequest) -> AppResult<i32> {
    let prf_status = if payload.supports_prf.unwrap_or(false) {
        i32::from(
            !(payload.encrypted_user_key.is_some()
                && payload.encrypted_private_key.is_some()
                && payload.encrypted_public_key.is_some()),
        )
    } else {
        2
    };
    if prf_status == 2
        && (payload.encrypted_user_key.is_some() || payload.encrypted_private_key.is_some())
    {
        return Err(AppError::bad_request(
            "Encrypted PRF keys require PRF support",
        ));
    }
    Ok(prf_status)
}
