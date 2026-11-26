use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse as _, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        common::{
            extract::{ClientIp, Query},
            json::Json,
            response::{ApiResponse, EmptyListResponse, EmptyObject, NoStore, WithCookies},
        },
    },
    errors::{AppError, AppResult, AuthError},
    models::identity::user::UserRow,
    service::{
        identity::{
            kdf::{ValidatedKdfParams, unknown_email_kdf, validate_stored_kdf},
            session::Claims,
            setup,
            two_factor::is_two_factor_enabled,
            user::{
                AccountCredentials, AccountVerificationRequest, ChangeKdfRequest,
                ChangePasswordRequest, KdfParams, PreloginResponse, ProfileResponse,
                RegisterRequest, UpdateAvatarColorRequest, UpdateProfileRequest,
            },
        },
        notifications::{self, UpdateType, admin as admin_notify, admin::Event},
        rate_limit,
    },
};

#[derive(Deserialize)]
#[serde(untagged)]
pub(in crate::api) enum PreloginRequest {
    Email { email: String },
    MissingEmail(serde::de::IgnoredAny),
}

#[worker::send]
pub(in crate::api) async fn prelogin(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<PreloginRequest>,
) -> AppResult<ApiResponse<PreloginResponse>> {
    let PreloginRequest::Email { email } = payload else {
        return Err(AppError::invalid_credentials("Missing email"));
    };
    let rate_limit_key = format!("prelogin:{ip}");
    rate_limit::check_auth_attempt(&state.env, rate_limit_key).await?;

    let email = email.trim().to_lowercase();
    let params = match UserRow::kdf_params_by_email(state.database(), &email).await? {
        Some(stored) => {
            let params = KdfParams {
                kdf_type: stored.kdf_type,
                iterations: stored.kdf_iterations,
                memory: stored.kdf_memory,
                parallelism: stored.kdf_parallelism,
            };
            validate_stored_kdf(&params)?;
            params
        }
        None => unknown_email_kdf(&state.jwt_keys.access_secret, &email)?,
    };

    Ok(ApiResponse(PreloginResponse {
        kdf: params.kdf_type,
        kdf_iterations: params.iterations,
        kdf_memory: params.memory,
        kdf_parallelism: params.parallelism,
        kdf_settings: params,
        salt: email,
    }))
}

#[worker::send]
pub(in crate::api) async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ClientIp(ip): ClientIp,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<Response> {
    log::info!("Registration request received");

    let rate_limit_key = format!("register:{ip}");
    rate_limit::check_auth_attempt(&state.env, rate_limit_key).await?;

    let account_email = state
        .setup_guard()
        .authorize_registration(&headers, &payload.email)
        .await?;
    let verification = crate::service::identity::email::registration_proof(
        state.database(),
        &state.env,
        &state.jwt_keys.access_secret,
        &account_email,
        payload.email_verification_token.as_deref(),
    )
    .await?;

    let kdf = KdfParams::from(ValidatedKdfParams::try_from(payload.kdf)?);
    let password =
        crate::service::identity::user::new_stored_password(&payload.master_password_hash).await?;
    let now = crate::utils::time::now_rfc3339();

    let account_keys = payload.account_keys.into_persistence_material()?;
    let user = UserRow {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        avatar_color: None,
        email: account_email,
        is_email_verified: verification.is_some(),
        master_password_hash: password.hash,
        master_password_hint: payload.master_password_hint,
        password_salt: Some(password.salt),
        password_iterations: password.iterations,
        key: payload.user_symmetric_key,
        private_key: account_keys.private_key,
        public_key: account_keys.public_key,
        kdf_type: kdf.kdf_type,
        kdf_iterations: kdf.iterations,
        kdf_memory: kdf.memory,
        kdf_parallelism: kdf.parallelism,
        security_stamp: Uuid::new_v4().to_string(),
        user_key_id: payload.user_key_id,
        signed_public_key: account_keys.signed_public_key,
        security_state: account_keys.security_state,
        security_version: account_keys.security_version,
        signature_key_pair: account_keys.signature_key_pair,
        v2_upgrade_token: None,
        security_stamp_exceptions: None,
        equivalent_domains: "[]".to_string(),
        excluded_globals: "[]".to_string(),
        two_factor_recovery_code: None,
        created_at: now.clone(),
        updated_at: now,
    };

    let clear_cookie = HeaderValue::from_str(&setup::clear_cookie(state.domain()))
        .map_err(|error| AppError::internal_debug("Failed to build setup clear cookie", error))?;
    UserRow::insert(state.database(), &user, verification.as_ref()).await?;
    Ok(WithCookies {
        response: NoStore(ApiResponse(EmptyObject {})),
        cookies: vec![clear_cookie],
    }
    .into_response())
}

#[worker::send]
pub(in crate::api) async fn revision_date(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<ApiResponse<i64>> {
    let db = state.database();
    let revision_date = crate::service::identity::user::revision_date_ms(db, &claims.sub).await?;
    Ok(ApiResponse(revision_date))
}

#[worker::send]
pub(in crate::api) async fn get_tasks(_claims: Claims) -> ApiResponse<EmptyListResponse> {
    ApiResponse(EmptyListResponse::new())
}

#[derive(Serialize)]
pub(in crate::api) struct MasterPasswordPolicyResponse {
    #[serde(rename = "Object")]
    object: &'static str,
}

#[worker::send]
pub(in crate::api) async fn verify_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<MasterPasswordPolicyResponse>> {
    rate_limit::check_auth_attempt(&state.env, format!("verify-password:{}", claims.sub)).await?;
    let hash = payload
        .master_password_hash
        .ok_or_else(|| AppError::bad_request("Missing master password hash"))?;
    let db = state.database();
    let user = UserRow::fetch_by_id_with(
        db,
        &claims.sub,
        "Failed to fetch user for password verification",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    crate::service::identity::user::require_master_password(&user, &hash).await?;
    Ok(ApiResponse(MasterPasswordPolicyResponse {
        object: "masterPasswordPolicy",
    }))
}

#[worker::send]
pub(in crate::api) async fn get_profile(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<ApiResponse<ProfileResponse>> {
    let db = state.database();
    let user_id = claims.sub;

    let user = UserRow::fetch_by_id_with(db, &user_id, "Failed to fetch user for profile", || {
        AppError::Auth(AuthError::AccountLocked)
    })
    .await?;

    let two_factor_enabled = is_two_factor_enabled(db, &user_id).await?;
    let profile = ProfileResponse::from_user(user, two_factor_enabled);

    Ok(ApiResponse(profile))
}

#[worker::send]
pub(in crate::api) async fn update_profile(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateProfileRequest>,
) -> AppResult<ApiResponse<ProfileResponse>> {
    if payload.name.len() > 50 {
        return Err(AppError::Params(
            "The field Name must be a string with a maximum length of 50.".into(),
        ));
    }

    let db = state.database();
    let user_id = &claims.sub;

    let mut user = UserRow::fetch_by_id_with(
        db,
        user_id,
        "Failed to fetch user for profile update",
        || AppError::Auth(AuthError::AccountLocked),
    )
    .await?;
    let two_factor_enabled = is_two_factor_enabled(db, user_id).await?;
    let now = crate::utils::time::now_rfc3339();

    user.name = Some(payload.name);

    let session = claims.session_snapshot()?;
    let revision = UserRow::update_profile_name(db, &session, user.name.as_deref(), &now).await?;
    user.updated_at = revision.clone();

    Ok(updated_profile(&state, &claims, user, two_factor_enabled, &revision).await)
}

#[worker::send]
pub(in crate::api) async fn update_avatar_color(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateAvatarColorRequest>,
) -> AppResult<ApiResponse<ProfileResponse>> {
    if let Some(color) = &payload.avatar_color
        && color.len() != 7
    {
        return Err(AppError::Params(
            "The field AvatarColor must be a HTML/Hex color code with a \
             length of 7 characters"
                .into(),
        ));
    }

    let db = state.database();
    let user_id = &claims.sub;

    let mut user = UserRow::fetch_by_id_with(
        db,
        user_id,
        "Failed to fetch user for avatar update",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    let two_factor_enabled = is_two_factor_enabled(db, user_id).await?;
    let now = crate::utils::time::now_rfc3339();

    user.avatar_color = payload.avatar_color;

    let session = claims.session_snapshot()?;
    let revision =
        UserRow::update_avatar_color(db, &session, user.avatar_color.as_deref(), &now).await?;
    user.updated_at = revision.clone();

    Ok(updated_profile(&state, &claims, user, two_factor_enabled, &revision).await)
}

async fn updated_profile(
    state: &AppState,
    claims: &Claims,
    user: UserRow,
    two_factor_enabled: bool,
    revision: &str,
) -> ApiResponse<ProfileResponse> {
    let user_id = &claims.sub;
    let profile = ProfileResponse::from_user(user, two_factor_enabled);

    admin_notify::emit(&state.env, Event::AccountSettingsChanged, user_id).await;
    notifications::publish_user_update(
        &state.env,
        user_id,
        UpdateType::SyncVault,
        revision,
        claims.device(),
    )
    .await;
    ApiResponse(profile)
}

#[worker::send]
pub(in crate::api) async fn delete_account(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let authorization = state
        .email_verifier()
        .prepare_account_action(&claims, &payload)
        .await?;
    crate::service::identity::user::delete_account(state.database(), &state.env, &authorization)
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}

/// POST /accounts/password - Change master password
#[worker::send]
pub(in crate::api) async fn change_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ChangePasswordRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    AccountCredentials::load(
        state.database(),
        &state.env,
        &claims,
        "Failed to fetch user for password change",
    )
    .await?
    .change_password(payload)
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

/// POST /accounts/kdf - Change KDF settings (PBKDF2 <-> Argon2id)
///
/// Both the legacy flat request and the authentication/unlock pair resolve to
/// one verified set of credential material before any password derivation.
#[worker::send]
pub(in crate::api) async fn change_kdf(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ChangeKdfRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    AccountCredentials::load(
        state.database(),
        &state.env,
        &claims,
        "Failed to fetch user for KDF change",
    )
    .await?
    .change_kdf(payload)
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Debug, Deserialize)]
pub(in crate::api) struct HibpBreachQuery {
    username: String,
}

/// Proxy HIBP only when configured; no fabricated breach records.
#[worker::send]
pub(in crate::api) async fn hibp_breach(
    claims: crate::service::identity::session::Claims,
    State(state): State<Arc<AppState>>,
    Query(query): Query<HibpBreachQuery>,
) -> AppResult<ApiResponse<Value>> {
    crate::service::rate_limit::check_auth_attempt(&state.env, format!("hibp:{}", claims.sub))
        .await?;
    let secret = crate::infra::config::env_text(&state.env, "HIBP_API_KEY")
        .ok_or_else(|| AppError::bad_request("HIBP_API_KEY is not configured"))?;
    Ok(ApiResponse(hibp_breaches(&secret, &query.username).await?))
}

async fn hibp_breaches(secret: &str, username: &str) -> AppResult<Value> {
    let mut url = url::Url::parse("https://haveibeenpwned.com/api/v3/breachedaccount/")
        .map_err(|error| AppError::internal_debug("Invalid HIBP base URL", error))?;
    url.path_segments_mut()
        .map_err(|()| AppError::internal("Invalid HIBP URL path segments"))?
        .push(username);
    url.set_query(Some("truncateResponse=false&includeUnverified=false"));
    let mut request = worker::Request::new(url.as_str(), worker::Method::Get)?;
    request.headers_mut()?.set("hibp-api-key", secret)?;
    request.headers_mut()?.set("user-agent", "raywarden")?;
    let mut response = worker::Fetch::Request(request).send().await?;
    if response.status_code() == 404 {
        return Ok(Value::Array(Vec::new()));
    }
    if response.status_code() != 200 {
        return Err(AppError::bad_request("HIBP service is unavailable"));
    }
    Ok(response.json().await?)
}
