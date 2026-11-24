use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    api::{
        AppState,
        common::{
            json::Json,
            response::{ApiResponse, EmptyObject},
        },
    },
    errors::{AppError, AppResult},
    models::identity::{
        authorization::VerifiedAccountAction, user::UserRow, webauthn::WebauthnCredentialRow,
    },
    service::{
        identity::{
            session::Claims,
            user::AccountVerificationRequest,
            webauthn,
            webauthn::{
                AssertionOptionsResponse, CredentialResponse, RegisterWebauthnCredentialRequest,
                RegistrationOptions, UpdateWebauthnCredentialRequest,
            },
        },
        notifications::{admin as admin_notify, admin::Event},
    },
};

pub(in crate::api) struct CredentialListResponse {
    data: Vec<CredentialResponse>,
}

impl Serialize for CredentialListResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CredentialListWire<'a> {
            data: &'a [CredentialResponse],
            #[serde(rename = "Data")]
            legacy_data: &'a [CredentialResponse],
            object: &'static str,
            #[serde(rename = "Object")]
            legacy_object: &'static str,
            continuation_token: Option<&'a str>,
        }

        CredentialListWire {
            data: &self.data,
            legacy_data: &self.data,
            object: "list",
            legacy_object: "list",
            continuation_token: None,
        }
        .serialize(serializer)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct SavedCredentialResponse {
    #[serde(flatten)]
    credentials: CredentialListResponse,
    id: String,
    name: String,
    success: bool,
    prf_status: i32,
    can_use_passkey_unlock: bool,
    requires_password_login: bool,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    message: &'static str,
}

#[derive(Serialize)]
pub(in crate::api) struct UpdatedCredentialResponse {
    #[serde(flatten)]
    credentials: CredentialListResponse,
    success: bool,
}

#[derive(Clone, Serialize)]
struct WebauthnTwoFactorKey {
    id: i32,
    name: String,
    migrated: bool,
}

#[derive(Serialize)]
struct WebauthnTwoFactorDetails {
    enabled: bool,
    keys: Vec<WebauthnTwoFactorKey>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct WebauthnTwoFactorResponse {
    enabled: bool,
    keys: Vec<WebauthnTwoFactorKey>,
    object: &'static str,
    web_authn: WebauthnTwoFactorDetails,
    user_verification_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrfProbeDetails {
    required_for_unlock: bool,
    fallback: &'static str,
    endpoint: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct AttestationOptionsResponse {
    token: String,
    options: RegistrationOptions,
    prf_probe: PrfProbeDetails,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Independent protocol fields.
pub(in crate::api) struct PrfProbeResponse {
    supports_prf: bool,
    can_use_passkey_unlock: bool,
    requires_password_login: bool,
    required_for_unlock: bool,
    fallback: &'static str,
    message: &'static str,
}

async fn list_response(state: &AppState, user: &str) -> AppResult<CredentialListResponse> {
    let data = WebauthnCredentialRow::list(state.database(), user, "login")
        .await?
        .into_iter()
        .map(CredentialResponse::from)
        .collect();
    Ok(CredentialListResponse { data })
}

async fn two_factor_response(
    state: &AppState,
    claims: &Claims,
) -> AppResult<WebauthnTwoFactorResponse> {
    let keys = WebauthnCredentialRow::list(state.database(), &claims.sub, "2fa")
        .await?
        .into_iter()
        .map(|key| WebauthnTwoFactorKey {
            id: key.slot,
            name: key.name,
            migrated: false,
        })
        .collect::<Vec<_>>();
    let enabled = !keys.is_empty();
    let token = webauthn::mint_user_verification_token(
        state.database(),
        &state.jwt_keys.access_secret,
        claims,
    )
    .await?;
    Ok(WebauthnTwoFactorResponse {
        enabled,
        web_authn: WebauthnTwoFactorDetails {
            enabled,
            keys: keys.clone(),
        },
        keys,
        object: "twoFactorWebAuthn",
        user_verification_token: token,
    })
}

#[worker::send]
pub(in crate::api) async fn list_credentials(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<ApiResponse<CredentialListResponse>> {
    Ok(ApiResponse(list_response(&state, &claims.sub).await?))
}

#[worker::send]
pub(in crate::api) async fn attestation_options(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<AttestationOptionsResponse>> {
    state
        .email_verifier()
        .verify_password_or_otp(&claims, &proof)
        .await?;
    let options = webauthn::registration_options(
        state.database(),
        state.domain(),
        &claims,
        webauthn::CredentialUse::Login,
    )
    .await?;
    Ok(ApiResponse(AttestationOptionsResponse {
        token: options.challenge.clone(),
        options,
        prf_probe: PrfProbeDetails {
            required_for_unlock: true,
            fallback: "master_password",
            endpoint: "/api/webauthn/prf-probe",
        },
    }))
}

#[worker::send]
pub(in crate::api) async fn create_credential(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<RegisterWebauthnCredentialRequest>,
) -> AppResult<ApiResponse<SavedCredentialResponse>> {
    let saved = webauthn::register(
        state.database(),
        &state.env,
        &claims,
        data,
        webauthn::CredentialUse::Login,
    )
    .await?;
    let credentials = list_response(&state, &claims.sub).await?;
    let can_use_passkey_unlock = saved.prf_status == 0;
    Ok(ApiResponse(SavedCredentialResponse {
        credentials,
        id: saved.slot.to_string(),
        name: saved.name,
        success: true,
        prf_status: saved.prf_status,
        can_use_passkey_unlock,
        requires_password_login: !can_use_passkey_unlock,
        encrypted_user_key: saved.encrypted_user_key,
        encrypted_public_key: saved.encrypted_public_key,
        message: if can_use_passkey_unlock {
            "Passkey saved with PRF unlock enabled."
        } else {
            "Passkey saved. Vault unlock will fall back to the master password."
        },
    }))
}

#[worker::send]
pub(in crate::api) async fn assertion_options(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<AssertionOptionsResponse>> {
    state
        .email_verifier()
        .verify_password_or_otp(&claims, &proof)
        .await?;
    let options = webauthn::assertion_options(state.database(), state.domain(), &claims).await?;
    Ok(ApiResponse(AssertionOptionsResponse {
        token: options.challenge.clone(),
        options,
    }))
}

#[worker::send]
pub(in crate::api) async fn update_credential(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<UpdateWebauthnCredentialRequest>,
) -> AppResult<ApiResponse<UpdatedCredentialResponse>> {
    let id = data.credential_id()?;
    update_credential_with_id(&state, claims, &id, data).await
}

#[worker::send]
pub(in crate::api) async fn update_credential_by_id(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<UpdateWebauthnCredentialRequest>,
) -> AppResult<ApiResponse<UpdatedCredentialResponse>> {
    update_credential_with_id(&state, claims, &id, data).await
}

async fn update_credential_with_id(
    state: &AppState,
    claims: Claims,
    id: &str,
    data: UpdateWebauthnCredentialRequest,
) -> AppResult<ApiResponse<UpdatedCredentialResponse>> {
    webauthn::update_credential(state.database(), &state.env, &claims, id, data).await?;
    Ok(ApiResponse(UpdatedCredentialResponse {
        credentials: list_response(state, &claims.sub).await?,
        success: true,
    }))
}

#[worker::send]
pub(in crate::api) async fn delete_credential(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let db = state.database();
    let target = WebauthnCredentialRow::find_owned(db, &claims.sub, "login", &id).await;
    let authorization = state
        .email_verifier()
        .prepare_account_action(&claims, &proof)
        .await?;
    target?.delete(db, &authorization, None).await?;
    admin_notify::emit(&state.env, Event::WebauthnCredentialDelete, &claims.sub).await;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct PrfProbe {
    supports_prf: Option<bool>,
}

#[worker::send]
pub(in crate::api) async fn prf_probe(
    _claims: Claims,
    Json(probe): Json<PrfProbe>,
) -> ApiResponse<PrfProbeResponse> {
    let supported = probe.supports_prf.unwrap_or(false);
    ApiResponse(PrfProbeResponse {
        supports_prf: supported,
        can_use_passkey_unlock: supported,
        requires_password_login: !supported,
        required_for_unlock: true,
        fallback: "master_password",
        message: if supported {
            "PRF is available. You can continue passkey unlock setup."
        } else {
            "PRF is unavailable. Vault unlock will fall back to the master \
             password."
        },
    })
}

#[worker::send]
pub(in crate::api) async fn identity_assertion_options(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<ApiResponse<AssertionOptionsResponse>> {
    Ok(ApiResponse(
        webauthn::passwordless_options(
            state.database(),
            &state.env,
            state.domain(),
            &state.jwt_keys.access_secret,
            &headers,
        )
        .await?,
    ))
}

#[worker::send]
pub(in crate::api) async fn list_two_factor_providers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<WebauthnTwoFactorResponse>> {
    state
        .email_verifier()
        .verify_password_or_otp(&claims, &proof)
        .await?;
    Ok(ApiResponse(two_factor_response(&state, &claims).await?))
}
#[worker::send]
pub(in crate::api) async fn two_factor_challenge(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<RegistrationOptions>> {
    webauthn::verify_two_factor_authorization(
        state.database(),
        &state.env,
        &state.jwt_keys.access_secret,
        &claims,
        &proof,
    )
    .await?;
    Ok(ApiResponse(
        webauthn::registration_options(
            state.database(),
            state.domain(),
            &claims,
            webauthn::CredentialUse::TwoFactor,
        )
        .await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn register_two_factor(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<RegisterWebauthnCredentialRequest>,
) -> AppResult<ApiResponse<WebauthnTwoFactorResponse>> {
    // The registration challenge was authorized with a password/OTP and is
    // bound to this authenticated session. A one-time OTP need not be reused.
    webauthn::register(
        state.database(),
        &state.env,
        &claims,
        data,
        webauthn::CredentialUse::TwoFactor,
    )
    .await?;
    Ok(ApiResponse(two_factor_response(&state, &claims).await?))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct DeleteWebauthnTwoFactorRequest {
    id: i32,
    #[serde(flatten)]
    proof: AccountVerificationRequest,
}
#[worker::send]
pub(in crate::api) async fn delete_two_factor(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<DeleteWebauthnTwoFactorRequest>,
) -> AppResult<ApiResponse<WebauthnTwoFactorResponse>> {
    if !(1..=5).contains(&data.id) {
        return Err(AppError::bad_request("Invalid WebAuthn key slot"));
    }
    let db = state.database();
    let target =
        WebauthnCredentialRow::find_owned(db, &claims.sub, "2fa", &data.id.to_string()).await;
    let (authorization, expected_keys) = if data.proof.user_verification_token.is_some() {
        let user =
            UserRow::fetch_by_id_with(db, &claims.sub, "Failed to fetch WebAuthn owner", || {
                AppError::not_found("User")
            })
            .await?;
        let keys = WebauthnCredentialRow::list(db, &claims.sub, "2fa").await?;
        webauthn::verify_two_factor_authorization(
            db,
            &state.env,
            &state.jwt_keys.access_secret,
            &claims,
            &data.proof,
        )
        .await?;
        (
            VerifiedAccountAction::new(claims.session_snapshot()?, user, None)?,
            Some(keys),
        )
    } else {
        (
            state
                .email_verifier()
                .prepare_account_action(&claims, &data.proof)
                .await?,
            None,
        )
    };
    target?
        .delete(db, &authorization, expected_keys.as_deref())
        .await?;
    admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub).await;
    Ok(ApiResponse(two_factor_response(&state, &claims).await?))
}

#[worker::send]
pub(in crate::api) async fn delete_all_two_factors(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<WebauthnTwoFactorResponse>> {
    if proof.user_verification_token.is_none()
        || proof.master_password_hash.is_some()
        || proof.otp.is_some()
    {
        return Err(AppError::bad_request(
            "A WebAuthn verification token is required",
        ));
    }
    let db = state.database();
    let user = UserRow::fetch_by_id_with(db, &claims.sub, "Failed to fetch WebAuthn owner", || {
        AppError::not_found("User")
    })
    .await?;
    let keys = WebauthnCredentialRow::list(db, &claims.sub, "2fa").await?;
    if keys.is_empty() {
        return Err(AppError::bad_request("WebAuthn data not found"));
    }
    webauthn::verify_two_factor_authorization(
        state.database(),
        &state.env,
        &state.jwt_keys.access_secret,
        &claims,
        &proof,
    )
    .await?;
    WebauthnCredentialRow::clear_2fa_if_current(
        db,
        &claims.session_snapshot()?,
        &crate::models::identity::account_keys::AccountSnapshot::from_user(&user),
        &keys,
    )
    .await?;
    admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub).await;
    Ok(ApiResponse(two_factor_response(&state, &claims).await?))
}
