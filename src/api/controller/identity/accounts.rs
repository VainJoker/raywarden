use axum::{
    Json,
    extract::{
        Query,
        State,
    },
    http::{
        HeaderMap,
        HeaderValue,
        header,
    },
    response::{
        IntoResponse as _,
        Response,
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        common::response::{
            ApiResponse,
            EmptyListResponse,
            EmptyObject,
        },
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    models::{
        identity::user::UserRow,
        usage,
    },
    service::{
        identity::{
            kdf::{
                DEFAULT_PBKDF2_ITERATIONS,
                KDF_TYPE_ARGON2ID,
                KDF_TYPE_PBKDF2,
                ensure_supported_kdf,
                unknown_email_kdf,
            },
            session::Claims,
            setup,
            user::{
                AccountCredentials,
                AccountVerificationRequest,
                ChangeKdfRequest,
                ChangePasswordRequest,
                KdfParams,
                PreloginResponse,
                ProfileResponse,
                RegisterRequest,
                SetPasswordRequest,
                UpdateAvatarColorRequest,
                UpdateProfileRequest,
            },
        },
        notifications::{
            self,
            UpdateType,
            admin as admin_notify,
            admin::Event,
        },
        rate_limit,
    },
};

#[worker::send]
pub(in crate::api) async fn prelogin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> AppResult<ApiResponse<PreloginResponse>> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::invalid_credentials("Missing email"))?;

    let ip = rate_limit::client_ip(&headers);
    let rate_limit_key = format!("prelogin:{ip}");
    rate_limit::check_auth_attempt(&state, rate_limit_key).await?;

    let email = email.trim().to_lowercase();
    let params =
        match UserRow::kdf_params_by_email(state.database(), &email).await? {
            Some(params) => KdfParams {
                kdf_type:    params.kdf_type.unwrap_or(KDF_TYPE_PBKDF2),
                iterations:  params
                    .kdf_iterations
                    .unwrap_or(DEFAULT_PBKDF2_ITERATIONS),
                memory:      params.kdf_memory,
                parallelism: params.kdf_parallelism,
            },
            None => unknown_email_kdf(&state.jwt_keys.access_secret, &email)?,
        };

    Ok(ApiResponse(PreloginResponse {
        kdf:             params.kdf_type,
        kdf_iterations:  params.iterations,
        kdf_memory:      params.memory,
        kdf_parallelism: params.parallelism,
        kdf_settings:    params,
        salt:            email,
    }))
}

#[worker::send]
pub(in crate::api) async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<Response> {
    log::info!("Registration request received");

    let ip = rate_limit::client_ip(&headers);
    let rate_limit_key = format!("register:{ip}");
    rate_limit::check_auth_attempt(&state, rate_limit_key).await?;

    let account_email =
        setup::authorize_registration(&state, &headers, &payload.email).await?;
    crate::service::identity::email::enforce_registration_verification(
        &state,
        &account_email,
        payload.email_verification_token.as_deref(),
    )
    .await?;

    ensure_supported_kdf(
        payload.kdf,
        payload.kdf_iterations,
        payload.kdf_memory,
        payload.kdf_parallelism,
    )?;

    let password = crate::service::identity::user::new_stored_password(
        &payload.master_password_hash,
    )
    .await?;

    let now = crate::utils::time::now_rfc3339();

    // Only store kdf_memory and kdf_parallelism for Argon2id, clear for PBKDF2
    let (kdf_memory, kdf_parallelism) = if payload.kdf == KDF_TYPE_ARGON2ID {
        (payload.kdf_memory, payload.kdf_parallelism)
    } else {
        (None, None)
    };

    let account_keys = payload.account_keys.into_persistence_material()?;
    let user = UserRow {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        avatar_color: None,
        email: account_email,
        is_email_verified:
            crate::service::identity::email::registration_verification_required(
                &state,
            ),
        master_password_hash: password.hash,
        master_password_hint: payload.master_password_hint,
        password_salt: Some(password.salt),
        password_iterations: password.iterations,
        key: payload.user_symmetric_key,
        private_key: account_keys.private_key,
        public_key: account_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        kdf_memory,
        kdf_parallelism,
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

    let clear_cookie = HeaderValue::from_str(&setup::clear_cookie(&state))
        .map_err(AppError::internal_error)?;
    UserRow::insert(state.database(), &user).await?;
    let mut response = ApiResponse(EmptyObject {}).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_cookie);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[worker::send]
pub(in crate::api) async fn revision_date(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<i64>> {
    let db = state.database();
    let revision_date =
        crate::service::identity::user::revision_date_ms(db, &claims.sub)
            .await?;
    Ok(ApiResponse(revision_date))
}

#[worker::send]
pub(in crate::api) async fn get_tasks(
    _claims: Claims,
) -> ApiResponse<EmptyListResponse> {
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
    State(state): State<AppState>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<MasterPasswordPolicyResponse>> {
    rate_limit::check_auth_attempt(
        &state,
        format!("verify-password:{}", claims.sub),
    )
    .await?;
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
    if !crate::service::identity::user::verify_master_password(&user, &hash)
        .await?
        .is_valid()
    {
        return Err(AuthError::InvalidPassword.into());
    }
    Ok(ApiResponse(MasterPasswordPolicyResponse {
        object: "masterPasswordPolicy",
    }))
}

#[worker::send]
pub(in crate::api) async fn get_profile(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<ProfileResponse>> {
    let db = state.database();
    let user_id = claims.sub;

    let user = UserRow::fetch_by_id_with(
        db,
        &user_id,
        "Failed to fetch user for profile",
        || AppError::Auth(AuthError::AccountLocked),
    )
    .await?;

    let is_two_factor_enabled =
        crate::service::identity::two_factor::is_two_factor_enabled(
            db, &user_id,
        )
        .await?;
    let profile = ProfileResponse::from_user(user, is_two_factor_enabled);

    Ok(ApiResponse(profile))
}

#[worker::send]
pub(in crate::api) async fn update_profile(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<UpdateProfileRequest>,
) -> AppResult<ApiResponse<ProfileResponse>> {
    if payload.name.len() > 50 {
        return Err(AppError::Params(
            "The field Name must be a string with a maximum length of 50."
                .to_string(),
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
    let now = crate::utils::time::now_rfc3339();

    user.name = Some(payload.name);

    UserRow::update_profile_name(db, user_id, user.name.as_deref(), &now)
        .await?;

    updated_profile(&state, &claims, user).await
}

#[worker::send]
pub(in crate::api) async fn update_avatar_color(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<UpdateAvatarColorRequest>,
) -> AppResult<ApiResponse<ProfileResponse>> {
    if let Some(color) = &payload.avatar_color &&
        color.len() != 7
    {
        return Err(AppError::Params(
            "The field AvatarColor must be a HTML/Hex color code with a \
             length of 7 characters"
                .to_string(),
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
    let now = crate::utils::time::now_rfc3339();

    user.avatar_color = payload.avatar_color;

    UserRow::update_avatar_color(
        db,
        user_id,
        user.avatar_color.as_deref(),
        &now,
    )
    .await?;

    updated_profile(&state, &claims, user).await
}

async fn updated_profile(
    state: &AppState,
    claims: &Claims,
    user: UserRow,
) -> AppResult<ApiResponse<ProfileResponse>> {
    let user_id = &claims.sub;
    let is_two_factor_enabled =
        crate::service::identity::two_factor::is_two_factor_enabled(
            state.database(),
            user_id,
        )
        .await?;
    let profile = ProfileResponse::from_user(user, is_two_factor_enabled);

    admin_notify::emit(&state.env, Event::AccountSettingsChanged, user_id)
        .await;
    notifications::publish_user_update(
        &state.env,
        user_id,
        UpdateType::SyncVault,
        &crate::utils::time::now_rfc3339(),
        claims.device(),
    )
    .await;
    Ok(ApiResponse(profile))
}

#[worker::send]
pub(in crate::api) async fn delete_account(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    crate::service::identity::email::verify_password_or_otp(
        &state, &claims, &payload,
    )
    .await?;

    crate::service::identity::user::delete_account(
        &state,
        &claims.sub,
        claims.device(),
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Serialize)]
pub(in crate::api) struct SetPasswordResponse {
    object: &'static str,
}

/// Set the first password on an already authenticated, empty V1 account.
#[worker::send]
pub(in crate::api) async fn set_password(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<SetPasswordRequest>,
) -> AppResult<ApiResponse<SetPasswordResponse>> {
    AccountCredentials::load(
        &state,
        &claims,
        "Failed to fetch password initialization owner",
        || AuthError::UserNotFound.into(),
    )
    .await?
    .initialize(payload)
    .await?;
    Ok(ApiResponse(SetPasswordResponse {
        object: "set-password",
    }))
}

/// POST /accounts/password - Change master password
#[worker::send]
pub(in crate::api) async fn change_password(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    AccountCredentials::load(
        &state,
        &claims,
        "Failed to fetch user for password change",
        || AppError::not_found("User not found"),
    )
    .await?
    .change_password(payload)
    .await?;
    notifications::publish_user_update(
        &state.env,
        &claims.sub,
        UpdateType::LogOut,
        &crate::utils::time::now_rfc3339(),
        claims.device(),
    )
    .await;
    Ok(ApiResponse(EmptyObject {}))
}

/// POST /accounts/kdf - Change KDF settings (PBKDF2 <-> Argon2id)
///
/// Both the legacy flat request and the authentication/unlock pair resolve to
/// one verified set of credential material before any password derivation.
#[worker::send]
pub(in crate::api) async fn change_kdf(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ChangeKdfRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    AccountCredentials::load(
        &state,
        &claims,
        "Failed to fetch user for KDF change",
        || AppError::not_found("User not found"),
    )
    .await?
    .change_kdf(payload)
    .await?;
    notifications::publish_user_update(
        &state.env,
        &claims.sub,
        UpdateType::LogOut,
        &crate::utils::time::now_rfc3339(),
        claims.device(),
    )
    .await;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Debug, Deserialize)]
pub(in crate::api) struct HibpBreachQuery {
    #[allow(dead_code)] // stub endpoint doesn't use it yet
    username: String,
}

/// Proxy HIBP only when configured; no fabricated breach records.
#[worker::send]
pub(in crate::api) async fn hibp_breach(
    claims: crate::service::identity::session::Claims,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<HibpBreachQuery>,
) -> AppResult<ApiResponse<Value>> {
    crate::service::rate_limit::check_auth_attempt(
        &state,
        format!("hibp:{}", claims.sub),
    )
    .await?;
    let secret = crate::infra::env::env_text(&state.env, "HIBP_API_KEY")
        .ok_or_else(|| {
            AppError::bad_request("HIBP_API_KEY is not configured")
        })?;
    let mut url =
        url::Url::parse("https://haveibeenpwned.com/api/v3/breachedaccount/")
            .map_err(AppError::internal_error)?;
    url.path_segments_mut()
        .map_err(AppError::internal_error)?
        .push(&query.username);
    url.set_query(Some("truncateResponse=false&includeUnverified=false"));
    let mut request = worker::Request::new(url.as_str(), worker::Method::Get)?;
    request.headers_mut()?.set("hibp-api-key", &secret)?;
    request.headers_mut()?.set("user-agent", "raywarden")?;
    let mut response = worker::Fetch::Request(request).send().await?;
    if response.status_code() == 404 {
        return Ok(ApiResponse(Value::Array(Vec::new())));
    }
    if response.status_code() != 200 {
        return Err(AppError::bad_request("HIBP service is unavailable"));
    }
    Ok(ApiResponse(response.json().await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct UsageQuery {
    user_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct UsageResponse {
    object:            &'static str,
    user_id:           String,
    total_bytes:       i64,
    d1_bytes:          i64,
    r2_bytes:          i64,
    max_bytes:         i64,
    total_percent:     f64,
    remaining_bytes:   i64,
    remaining_percent: f64,
    send_files_bytes:  i64,
    quota_is_estimate: bool,
    quota_source:      &'static str,
    file_bytes:        i64,
    is_estimate:       bool,
    items:             Vec<UsageItem>,
}

#[derive(Serialize)]
struct UsageItem {
    key:     String,
    name:    String,
    bytes:   i64,
    storage: &'static str,
}

#[worker::send]
pub(in crate::api) async fn usage(
    claims: Claims,
    State(state): State<AppState>,
    Query(query): Query<UsageQuery>,
) -> AppResult<ApiResponse<UsageResponse>> {
    if query.user_id.as_deref().is_some_and(|id| id != claims.sub) {
        return Err(AppError::Unauthorized {
            message: "Cannot inspect another account".into(),
        });
    }
    let mut rows = usage::for_user(state.database(), &claims.sub).await?;
    let mut total = 0i64;
    let mut files = 0i64;
    let mut send_files = 0i64;
    for row in &rows {
        if row.name.ends_with("Files") {
            files += row.bytes;
            if row.name == "sendFiles" {
                send_files = row.bytes;
            }
        } else {
            total += row.bytes;
        }
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.bytes));
    let items = rows
        .into_iter()
        .map(|row| UsageItem {
            key:     row.name.clone(),
            bytes:   row.bytes,
            storage: if row.name.ends_with("Files") {
                "r2"
            } else {
                "d1"
            },
            name:    row.name,
        })
        .collect();
    // Reference UI budget, never an assertion about this account's plan or an
    // enforcement limit. Row sizes and referenced files are logical estimates.
    let budget = 500 * 1024 * 1024_i64;
    let remaining = (budget - total).max(0);
    Ok(ApiResponse(UsageResponse {
        object: "d1-usage",
        user_id: claims.sub,
        total_bytes: total + files,
        d1_bytes: total,
        r2_bytes: files,
        max_bytes: budget,
        total_percent: total as f64 * 100.0 / budget as f64,
        remaining_bytes: remaining,
        remaining_percent: remaining as f64 * 100.0 / budget as f64,
        send_files_bytes: send_files,
        quota_is_estimate: true,
        quota_source: "reference-budget",
        file_bytes: files,
        is_estimate: true,
        items,
    }))
}
