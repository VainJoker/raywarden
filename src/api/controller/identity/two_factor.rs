use std::sync::Arc;

use axum::extract::State;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    api::{
        AppState,
        common::{
            extract::ClientIp,
            json::Json,
            response::{ApiResponse, EmptyObject},
        },
    },
    errors::{AppError, AppResult, AuthError},
    models::identity::{
        authorization::VerifiedAccountAction, two_factor::TwoFactorRow, user::UserRow,
        webauthn::WebauthnCredentialRow,
    },
    service::{
        identity::{
            session::Claims,
            two_factor,
            two_factor::{
                ActivateAuthenticatorRequest, DisableAuthenticatorRequest, DisableTwoFactorRequest,
                RecoverTwoFactorRequest, StoredProvider, TwoFactorProvider,
                TwoFactorProviderResponse, generate_factor_secret, normalize_authenticator_key,
                validate_totp,
            },
            user::AccountVerificationRequest,
        },
        notifications::{admin as admin_notify, admin::Event},
        rate_limit,
    },
    utils::constant_time_eq,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct TwoFactorProvidersResponse {
    data: Vec<TwoFactorProviderResponse>,
    object: &'static str,
    continuation_token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct AuthenticatorResponse {
    enabled: bool,
    key: String,
    object: &'static str,
    authenticator: AuthenticatorDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_verification_token: Option<String>,
}

#[derive(Serialize)]
struct AuthenticatorDetails {
    enabled: bool,
    key: String,
}

impl AuthenticatorResponse {
    fn new(enabled: bool, key: String, user_verification_token: Option<String>) -> Self {
        Self {
            enabled,
            authenticator: AuthenticatorDetails {
                enabled,
                key: key.clone(),
            },
            key,
            object: "twoFactorAuthenticator",
            user_verification_token,
        }
    }
}

#[derive(Serialize)]
pub(in crate::api) struct TwoFactorRecoveryResponse {
    code: Option<String>,
    object: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct DeviceVerificationSettingsResponse {
    is_device_verification_section_enabled: bool,
    unknown_device_verification_enabled: bool,
    object: &'static str,
}

/// GET /api/two-factor - Get all enabled 2FA providers for current user
#[worker::send]
pub(in crate::api) async fn list_two_factor_providers(
    State(state): State<Arc<AppState>>,
    claims: Claims,
) -> AppResult<ApiResponse<TwoFactorProvidersResponse>> {
    let user_id = claims.sub.clone();
    let db = state.database();
    let providers = TwoFactorRow::list_for_user(db, &user_id).await?;
    let providers = providers
        .iter()
        .filter(|factor| {
            factor.is_enabled && factor.provider_type != i32::from(TwoFactorProvider::Remember)
        })
        .map(TwoFactorProviderResponse::from)
        .collect();

    Ok(ApiResponse(TwoFactorProvidersResponse {
        data: providers,
        object: "list",
        continuation_token: None,
    }))
}

/// POST /api/two-factor/get-authenticator - Get or generate TOTP secret
#[worker::send]
pub(in crate::api) async fn prepare_authenticator(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    Json(data): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<AuthenticatorResponse>> {
    let user_id = claims.sub.clone();
    let db = state.database();

    state
        .email_verifier()
        .verify_password_or_otp(&claims, &data)
        .await?;

    let existing =
        TwoFactorRow::find_provider(db, &user_id, i32::from(TwoFactorProvider::Authenticator))
            .await?;

    let (enabled, key, factor_id) = match existing {
        Some(tf) => (tf.is_enabled, tf.data, Some(tf.id)),
        None => (false, generate_factor_secret()?, None),
    };

    let token = mint_authenticator_proof(&state, &claims, &key, enabled, factor_id.as_deref())?;
    Ok(ApiResponse(AuthenticatorResponse::new(
        enabled,
        key,
        Some(token),
    )))
}

/// POST /api/two-factor/authenticator - Activate TOTP
#[worker::send]
pub(in crate::api) async fn activate_authenticator(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    Json(data): Json<ActivateAuthenticatorRequest>,
) -> AppResult<ApiResponse<AuthenticatorResponse>> {
    let db = state.database();
    let key = normalize_authenticator_key(&data.key)?;
    let existing = TwoFactorRow::find_provider(db, &claims.sub, 0).await?;
    let proof = AccountVerificationRequest::from(data.verification);
    if proof.user_verification_token.is_some()
        && existing.as_ref().is_some_and(|factor| {
            !factor.is_enabled && !constant_time_eq(factor.data.as_bytes(), key.as_bytes())
        })
    {
        return Err(AppError::conflict(
            "Authenticator setup changed; request a new verification proof",
        ));
    }
    let authorization = if let Some(token) = proof.user_verification_token.as_deref() {
        verify_authenticator_proof(
            &state,
            &claims,
            &proof,
            token,
            &key,
            false,
            existing.as_ref(),
        )?;
        None
    } else {
        state
            .email_verifier()
            .prepare_password_or_otp(&claims, &proof)
            .await?
    };
    if proof.user_verification_token.is_some() && existing.as_ref().is_some_and(|v| v.is_enabled) {
        return Err(AppError::bad_request("Authenticator is already enabled"));
    }
    let previous_step = existing
        .as_ref()
        .filter(|v| constant_time_eq(v.data.as_bytes(), key.as_bytes()))
        .map_or(0, |v| v.last_used_step);
    let step = validate_totp(
        &data.token,
        &key,
        previous_step,
        !state.config.authenticator_time_drift_disabled,
    )
    .await?;
    let mut value = crate::service::identity::two_factor::new_two_factor_provider(
        claims.sub.clone(),
        TwoFactorProvider::Authenticator,
        key.clone(),
    );
    value.last_used_step = step;
    let session = claims.session_snapshot()?;
    TwoFactorRow::replace_authenticator(
        db,
        &session,
        existing.as_ref(),
        &value,
        &generate_factor_secret()?,
        authorization.as_ref(),
    )
    .await?;
    admin_notify::emit(&state.env, Event::TwoFactorEnable, &claims.sub).await;
    Ok(ApiResponse(AuthenticatorResponse::new(true, key, None)))
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[worker::send]
pub(in crate::api) async fn disable_two_factor(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    Json(data): Json<DisableTwoFactorRequest>,
) -> AppResult<ApiResponse<TwoFactorProviderResponse>> {
    let user_id = &claims.sub;
    let db = state.database();

    let provider_kind = StoredProvider::from(data.provider_type);
    let provider_type = i32::from(provider_kind);
    let proof = AccountVerificationRequest::from(data.verification);
    let provider = TwoFactorRow::find_provider(db, user_id, provider_type).await?;
    let was_enabled = provider.as_ref().is_some_and(|factor| factor.is_enabled);
    if let Some(factor) = provider
        .as_ref()
        .filter(|_| provider_kind == StoredProvider::Known(TwoFactorProvider::Authenticator))
    {
        let authorization =
            prepare_authenticator_delete(&state, &claims, &proof, &factor.data, factor).await?;
        TwoFactorRow::delete_authenticator_snapshot(db, &authorization, factor, true).await?;
    } else {
        let keys = if provider_kind == StoredProvider::Known(TwoFactorProvider::Webauthn) {
            Some(WebauthnCredentialRow::list(db, user_id, "2fa").await?)
        } else {
            None
        };
        let verifier = state.email_verifier();
        let authorization = if provider_kind == StoredProvider::Known(TwoFactorProvider::Email) {
            two_factor::prepare_email_factor_action(&verifier, &claims, &proof).await?
        } else {
            verifier.prepare_account_action(&claims, &proof).await?
        };
        TwoFactorRow::disable_provider(
            db,
            &authorization,
            provider_type,
            provider.as_ref(),
            keys.as_deref(),
        )
        .await?;
    }
    log::info!("User {user_id} disabled 2FA type {provider_type}");

    if was_enabled {
        admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub).await;
    }
    Ok(ApiResponse(TwoFactorProviderResponse::new(
        false,
        provider_type,
    )))
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[worker::send]
pub(in crate::api) async fn disable_authenticator(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    Json(data): Json<DisableAuthenticatorRequest>,
) -> AppResult<ApiResponse<TwoFactorProviderResponse>> {
    let db = state.database();
    if TwoFactorProvider::try_from(data.provider_type) != Ok(TwoFactorProvider::Authenticator) {
        return Err(AppError::bad_request("Invalid two factor type"));
    }
    let existing = TwoFactorRow::find_provider(db, &claims.sub, 0)
        .await?
        .ok_or_else(|| AppError::bad_request("TOTP not configured"))?;
    let key = data.key.trim().to_uppercase();
    let proof = AccountVerificationRequest::from(data.verification);
    let authorization =
        prepare_authenticator_delete(&state, &claims, &proof, &key, &existing).await?;
    if !constant_time_eq(existing.data.as_bytes(), key.as_bytes()) {
        return Err(AuthError::InvalidTotp.into());
    }
    TwoFactorRow::delete_authenticator_snapshot(db, &authorization, &existing, false).await?;
    admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub).await;
    Ok(ApiResponse(TwoFactorProviderResponse::new(false, 0)))
}

/// POST /api/two-factor/get-recover - Get recovery code
#[worker::send]
pub(in crate::api) async fn get_two_factor_recovery_code(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    Json(data): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<TwoFactorRecoveryResponse>> {
    let user_id = claims.sub.clone();
    let db = state.database();

    let user =
        UserRow::fetch_by_id_with(db, &user_id, "Failed to fetch user in get_recover", || {
            AppError::Auth(AuthError::UserNotFound)
        })
        .await?;

    state
        .email_verifier()
        .verify_password_or_otp(&claims, &data)
        .await?;

    admin_notify::emit(&state.env, Event::TwoFactorRecoveryCodeView, &claims.sub).await;
    Ok(ApiResponse(TwoFactorRecoveryResponse {
        code: user.two_factor_recovery_code,
        object: "twoFactorRecover",
    }))
}

/// POST /api/two-factor/recover - Use recovery code to disable all 2FA
#[worker::send]
pub(in crate::api) async fn recover(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Json(data): Json<RecoverTwoFactorRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let email = data.email.trim().to_lowercase();
    rate_limit::check_auth_attempt(&state.env, format!("twofactor-recover-ip:{ip}")).await?;
    rate_limit::check_auth_attempt(&state.env, format!("twofactor-recover:{email}")).await?;
    let db = state.database();

    // Get user by email
    let user = crate::service::identity::user::fetch_by_email_with(
        db,
        &email,
        "Failed to fetch user by email for 2FA recover",
        || AppError::invalid_credentials("Username or password is incorrect"),
    )
    .await?;

    // Verify master password
    let verification =
        crate::service::identity::user::verify_master_password(&user, &data.master_password_hash)
            .await?;
    if !verification.is_valid() {
        return Err(AppError::invalid_credentials(
            "Username or password is incorrect",
        ));
    }

    // Check recovery code (case-insensitive)
    let is_valid = user
        .two_factor_recovery_code
        .as_ref()
        .is_some_and(|stored_code| {
            !stored_code.trim().is_empty()
                && constant_time_eq(
                    stored_code.to_uppercase().as_bytes(),
                    data.recovery_code.to_uppercase().as_bytes(),
                )
        });

    if !is_valid {
        return Err(AppError::invalid_credentials("Invalid recovery code"));
    }

    TwoFactorRow::recover_if_current(db, &user).await?;

    log::info!("User {} recovered 2FA using recovery code", user.id);

    admin_notify::emit(&state.env, Event::TwoFactorRecover, &user.id).await;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Serialize, Deserialize)]
struct AuthenticatorProofClaims {
    sub: String,
    sstamp: String,
    session_token: String,
    purpose: String,
    state_hash: String,
    #[serde(default)]
    factor_id: Option<String>,
    exp: i64,
    nbf: i64,
    iat: i64,
}

fn mint_authenticator_proof(
    state: &AppState,
    claims: &Claims,
    key: &str,
    enabled: bool,
    factor_id: Option<&str>,
) -> AppResult<String> {
    let now = crate::utils::time::now_seconds();
    crate::infra::jwt::encode(
        &AuthenticatorProofClaims {
            sub: claims.sub.clone(),
            sstamp: claims.sstamp.clone(),
            session_token: claims.session_token.clone(),
            purpose: "authenticator-factor".into(),
            state_hash: authenticator_state_hash(key, enabled),
            factor_id: factor_id.map(str::to_string),
            exp: now + 300,
            nbf: now,
            iat: now,
        },
        state.jwt_keys.access_secret.as_bytes(),
    )
}

fn authenticator_state_hash(key: &str, enabled: bool) -> String {
    hex::encode(Sha256::digest(format!(
        "{}:{}",
        u8::from(enabled),
        key.trim().to_uppercase()
    )))
}

async fn prepare_authenticator_delete<'a>(
    state: &AppState,
    claims: &'a Claims,
    data: &AccountVerificationRequest,
    key: &str,
    observed: &TwoFactorRow,
) -> AppResult<VerifiedAccountAction<'a>> {
    if let Some(token) = data.user_verification_token.as_deref() {
        verify_authenticator_proof(
            state,
            claims,
            data,
            token,
            key,
            observed.is_enabled,
            Some(observed),
        )?;
        let user = crate::service::identity::email::fetch_user(state.database(), claims).await?;
        VerifiedAccountAction::new(claims.session_snapshot()?, user, None)
    } else {
        state
            .email_verifier()
            .prepare_account_action(claims, data)
            .await
    }
}

fn verify_authenticator_proof(
    state: &AppState,
    claims: &Claims,
    data: &AccountVerificationRequest,
    token: &str,
    key: &str,
    enabled: bool,
    observed: Option<&TwoFactorRow>,
) -> AppResult<()> {
    if data.master_password_hash.is_some() || data.otp.is_some() {
        return Err(AppError::bad_request(
            "Provide exactly one verification method",
        ));
    }
    let proof = crate::infra::jwt::decode::<AuthenticatorProofClaims>(
        token,
        state.jwt_keys.access_secret.as_bytes(),
        &crate::infra::jwt::ValidationOptions {
            leeway_seconds: 0,
            ..Default::default()
        },
    )?;
    if proof.sub != claims.sub
        || proof.sstamp != claims.sstamp
        || proof.session_token != claims.session_token
        || proof.purpose != "authenticator-factor"
        || proof
            .factor_id
            .as_deref()
            .is_some_and(|id| observed.is_none_or(|factor| factor.id != id))
        || !constant_time_eq(
            proof.state_hash.as_bytes(),
            authenticator_state_hash(key, enabled).as_bytes(),
        )
    {
        return Err(AppError::invalid_credentials("Invalid authenticator proof"));
    }
    Ok(())
}

#[worker::send]
pub(in crate::api) async fn device_verification_settings(
    _claims: Claims,
) -> ApiResponse<DeviceVerificationSettingsResponse> {
    ApiResponse(DeviceVerificationSettingsResponse {
        is_device_verification_section_enabled: false,
        unknown_device_verification_enabled: false,
        object: "deviceVerificationSettings",
    })
}

#[cfg(test)]
mod proof_tests {
    use super::authenticator_state_hash;

    #[test]
    fn authenticator_proof_binds_the_key_and_enabled_state() {
        assert_eq!(
            authenticator_state_hash(" abc ", false),
            authenticator_state_hash("ABC", false)
        );
        assert_ne!(
            authenticator_state_hash("ABC", true),
            authenticator_state_hash("ABC", false)
        );
        assert_ne!(
            authenticator_state_hash("ABC", false),
            authenticator_state_hash("ABD", false)
        );
    }
}
