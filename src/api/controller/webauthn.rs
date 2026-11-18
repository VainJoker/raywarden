use axum::{
    Json,
    extract::{
        Path,
        State,
    },
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            webauthn::{
                self,
                RegistrationData,
                SecretVerificationData,
                UpdateCredentialData,
            },
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    infra::admin_notify::{
        self,
        Event,
    },
    models::webauthn::CredentialDB,
};

async fn list_response(state: &AppState, user: &str) -> AppResult<Value> {
    let data = CredentialDB::list(&state.get_db(), user, "login")
        .await?
        .iter()
        .map(CredentialDB::to_json)
        .collect::<Vec<_>>();
    Ok(
        json!({"data":data,"Data":data,"object":"list","Object":"list","continuationToken":null}),
    )
}
async fn two_factor_response(
    state: &AppState,
    claims: &Claims,
) -> AppResult<Value> {
    let keys = CredentialDB::list(&state.get_db(), &claims.sub, "2fa")
        .await?
        .iter()
        .map(|k| json!({"id":k.slot,"name":k.name,"migrated":false}))
        .collect::<Vec<_>>();
    let enabled = !keys.is_empty();
    let token = webauthn::mint_user_verification_token(state, claims).await?;
    Ok(
        json!({"enabled":enabled,"keys":keys,"object":"twoFactorWebAuthn","webAuthn":{"enabled":enabled,"keys":keys},"userVerificationToken":token}),
    )
}
#[worker::send]
pub async fn list_credentials(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    Ok(Json(list_response(&state, &claims.sub).await?))
}
#[worker::send]
pub async fn attestation_options(
    claims: Claims,
    State(state): State<AppState>,
    Json(proof): Json<SecretVerificationData>,
) -> AppResult<Json<Value>> {
    webauthn::verify_secret(&state, &claims, &proof).await?;
    let options =
        webauthn::registration_options(&state, &claims, "login").await?;
    Ok(Json(
        json!({"token":options["challenge"],"options":options,"prfProbe":{"requiredForUnlock":true,"fallback":"master_password","endpoint":"/api/webauthn/prf-probe"}}),
    ))
}
#[worker::send]
pub async fn create_credential(
    claims: Claims,
    State(state): State<AppState>,
    Json(data): Json<RegistrationData>,
) -> AppResult<Json<Value>> {
    webauthn::register(&state, &claims, data, "login").await?;
    Ok(Json(list_response(&state, &claims.sub).await?))
}
#[worker::send]
pub async fn assertion_options(
    claims: Claims,
    State(state): State<AppState>,
    Json(proof): Json<SecretVerificationData>,
) -> AppResult<Json<Value>> {
    webauthn::verify_secret(&state, &claims, &proof).await?;
    let options = webauthn::assertion_options(&state, &claims).await?;
    Ok(Json(
        json!({"token":options["challenge"],"options":options}),
    ))
}
#[worker::send]
pub async fn update_credential(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(data): Json<UpdateCredentialData>,
) -> AppResult<Json<Value>> {
    webauthn::update_credential(&state, &claims, &id, data).await?;
    Ok(Json(list_response(&state, &claims.sub).await?))
}
#[worker::send]
pub async fn delete_credential(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(proof): Json<SecretVerificationData>,
) -> AppResult<Json<Value>> {
    webauthn::verify_secret(&state, &claims, &proof).await?;
    let db = state.get_db();
    CredentialDB::find_owned(&db, &claims.sub, "login", &id)
        .await?
        .delete(&db)
        .await?;
    admin_notify::emit(
        &state.env,
        Event::WebAuthnCredentialDelete,
        &claims.sub,
    )
    .await;
    Ok(Json(json!({})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrfProbe {
    supports_prf: bool,
}
#[worker::send]
pub async fn prf_probe(
    _claims: Claims,
    Json(probe): Json<PrfProbe>,
) -> Json<Value> {
    Json(
        json!({"supportsPrf":probe.supports_prf,"requiredForUnlock":true,"fallback":"master_password"}),
    )
}
#[worker::send]
pub async fn identity_assertion_options(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    Ok(Json(
        webauthn::passwordless_options(&state, &headers).await?,
    ))
}
#[worker::send]
pub async fn get_twofactor(
    claims: Claims,
    State(state): State<AppState>,
    Json(proof): Json<SecretVerificationData>,
) -> AppResult<Json<Value>> {
    webauthn::verify_2fa_secret(&state, &claims, &proof).await?;
    Ok(Json(two_factor_response(&state, &claims).await?))
}
#[worker::send]
pub async fn twofactor_challenge(
    claims: Claims,
    State(state): State<AppState>,
    Json(proof): Json<SecretVerificationData>,
) -> AppResult<Json<Value>> {
    webauthn::verify_2fa_secret(&state, &claims, &proof).await?;
    Ok(Json(
        webauthn::registration_options(&state, &claims, "2fa").await?,
    ))
}
#[worker::send]
pub async fn register_twofactor(
    claims: Claims,
    State(state): State<AppState>,
    Json(data): Json<RegistrationData>,
) -> AppResult<Json<Value>> {
    // The registration challenge was authorized with a password/OTP and is
    // bound to this authenticated session. A one-time OTP need not be reused.
    webauthn::register(&state, &claims, data, "2fa").await?;
    Ok(Json(two_factor_response(&state, &claims).await?))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteTwofactor {
    pub id:    i32,
    #[serde(flatten)]
    pub proof: SecretVerificationData,
}
#[worker::send]
pub async fn delete_twofactor(
    claims: Claims,
    State(state): State<AppState>,
    Json(data): Json<DeleteTwofactor>,
) -> AppResult<Json<Value>> {
    if !(1..=5).contains(&data.id) {
        return Err(AppError::bad_request("Invalid WebAuthn key slot"));
    }
    webauthn::verify_2fa_secret(&state, &claims, &data.proof).await?;
    let db = state.get_db();
    CredentialDB::find_owned(&db, &claims.sub, "2fa", &data.id.to_string())
        .await?
        .delete(&db)
        .await?;
    admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub).await;
    Ok(Json(two_factor_response(&state, &claims).await?))
}
