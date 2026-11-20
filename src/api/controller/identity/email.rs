use axum::{
    Json,
    extract::State,
    http::HeaderMap,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    api::{
        AppState,
        common::response::{
            ApiResponse,
            EmptyObject,
        },
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    models::identity::{
        email::{
            EmailChange,
            EmailStore,
        },
        two_factor::TwoFactorRow,
        user::UserRow,
    },
    service::{
        identity::{
            email,
            kdf::ensure_supported_kdf,
            session::Claims,
            two_factor,
            two_factor::TwoFactorProvider,
            user::AccountVerificationRequest,
        },
        notifications::{
            self,
            UpdateType,
            admin as admin_notify,
            admin::Event,
        },
    },
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct EmailRequest {
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyProtectedActionOtpRequest {
    #[serde(alias = "OTP", alias = "token")]
    otp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct SendEmailFactorCodeRequest {
    email:        String,
    #[serde(flatten)]
    verification: AccountVerificationRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyEmailFactorRequest {
    token:        String,
    #[serde(flatten)]
    verification: AccountVerificationRequest,
}

#[worker::send]
pub(in crate::api) async fn request_protected_action_otp(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = email::fetch_user(&state, &claims).await?;
    email::issue_code(
        &state,
        Some(&user),
        email::PROTECTED_ACTION,
        &user.email,
        "",
        &claims.session_token,
        true,
        false,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn verify_protected_action_otp(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<VerifyProtectedActionOtpRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = email::fetch_user(&state, &claims).await?;
    // This is the final authorization step for client-side vault export.
    // Consume its proof here rather than leaving it for a later server action.
    email::verify_code(
        &state,
        Some(&user),
        email::PROTECTED_ACTION,
        &user.email,
        "",
        &claims.session_token,
        &payload.otp,
        true,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct EmailFactorSetupResponse {
    enabled:                 bool,
    email:                   EmailFactorDetails,
    user_verification_token: String,
    object:                  &'static str,
}

#[derive(Serialize)]
struct EmailFactorDetails {
    email: Option<String>,
    token: String,
}

#[derive(Serialize)]
pub(in crate::api) struct EmailFactorStateResponse {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    email:   Option<String>,
    object:  &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_email_factor(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<EmailFactorSetupResponse>> {
    email::verify_password_or_otp(&state, &claims, &payload).await?;
    let address = email::email_provider(state.database(), &claims.sub).await?;
    let token = two_factor::mint_email_factor_proof(
        &state,
        &claims,
        address.as_deref(),
    )?;
    Ok(ApiResponse(EmailFactorSetupResponse {
        enabled:                 address.is_some(),
        email:                   EmailFactorDetails {
            email: address,
            token: token.clone(),
        },
        user_verification_token: token,
        object:                  "twoFactorEmail",
    }))
}

#[worker::send]
pub(in crate::api) async fn send_email_factor_code(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<SendEmailFactorCodeRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    two_factor::verify_email_factor_action(
        &state,
        &claims,
        &payload.verification,
    )
    .await?;
    let user = email::fetch_user(&state, &claims).await?;
    let recipient = email::normalize_email(&payload.email)?;
    email::issue_code(
        &state,
        Some(&user),
        email::EMAIL_SETUP,
        &recipient,
        "",
        &claims.session_token,
        true,
        false,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn verify_email_factor(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailFactorRequest>,
) -> AppResult<ApiResponse<EmailFactorStateResponse>> {
    two_factor::verify_email_factor_action(
        &state,
        &claims,
        &payload.verification,
    )
    .await?;
    let user = email::fetch_user(&state, &claims).await?;
    let db = state.database();
    let recipient = EmailStore::pending_recipient(
        db,
        &user.id,
        email::EMAIL_SETUP,
        crate::utils::time::now_seconds(),
        &claims.session_token,
    )
    .await?
    .ok_or_else(|| AppError::bad_request("No email setup is pending"))?;
    email::verify_code(
        &state,
        Some(&user),
        email::EMAIL_SETUP,
        &recipient,
        "",
        &claims.session_token,
        &payload.token,
        true,
    )
    .await?;
    email::set_email_provider(&state, &user, &recipient).await?;
    Ok(ApiResponse(EmailFactorStateResponse {
        enabled: true,
        email:   Some(recipient),
        object:  "twoFactorEmail",
    }))
}

#[worker::send]
pub(in crate::api) async fn disable_email_factor(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<EmailFactorStateResponse>> {
    two_factor::verify_email_factor_action(&state, &claims, &payload).await?;
    let db = state.database();
    let was_enabled = TwoFactorRow::find_provider(
        db,
        &claims.sub,
        TwoFactorProvider::Email as i32,
    )
    .await?
    .is_some_and(|factor| factor.is_enabled);
    EmailStore::disable_provider(db, &claims.sub).await?;
    if was_enabled {
        admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub)
            .await;
    }
    Ok(ApiResponse(EmailFactorStateResponse {
        enabled: false,
        email:   None,
        object:  "twoFactorEmail",
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct SendLoginCodeRequest {
    #[serde(alias = "Email")]
    email:                    Option<String>,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash:     Option<String>,
    #[serde(rename = "deviceIdentifier", alias = "DeviceIdentifier")]
    device_id:                Option<String>,
    #[serde(alias = "AuthRequestId")]
    auth_request_id:          Option<String>,
    #[serde(alias = "AuthRequestAccessCode")]
    auth_request_access_code: Option<String>,
}

#[worker::send]
pub(in crate::api) async fn send_login_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SendLoginCodeRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state, &headers, "email-login").await?;
    let db = state.database();
    let user = if let (Some(address), Some(hash)) = (
        payload.email.as_deref(),
        payload.master_password_hash.as_deref(),
    ) {
        let user = crate::service::identity::user::fetch_by_email_with(
            db,
            address,
            "Failed to find email login owner",
            || AuthError::InvalidPassword.into(),
        )
        .await?;
        if !crate::service::identity::user::verify_master_password(&user, hash)
            .await?
            .is_valid()
        {
            return Err(AuthError::InvalidPassword.into());
        }
        user
    } else if let (Some(id), Some(code), Some(device)) = (
        payload.auth_request_id.as_deref(),
        payload.auth_request_access_code.as_deref(),
        payload.device_id.as_deref(),
    ) {
        let request =
            crate::models::identity::auth_request::AuthRequestRow::find_by_id(
                db, id,
            )
            .await?
            .ok_or_else(|| {
                AppError::bad_request("Invalid authentication request")
            })?;
        let user = UserRow::fetch_by_id_with(
            db,
            &request.user_id,
            "Failed to fetch authentication request owner",
            || AuthError::InvalidPassword.into(),
        )
        .await?;
        let device_type =
            crate::api::middleware::auth::request_device_type(&headers)?;
        if !crate::service::identity::auth_request::auth_request_matches_login(
            &request,
            &user.id,
            device,
            device_type,
            crate::service::rate_limit::client_ip(&headers),
            code,
            &user.security_stamp,
        ) || payload.email.as_deref().is_some_and(|address| {
            !address.trim().eq_ignore_ascii_case(&user.email)
        }) {
            return Err(AppError::invalid_credentials(
                "Invalid authentication request",
            ));
        }
        user
    } else {
        return Err(AppError::bad_request(
            "Password or approved authentication request is required",
        ));
    };
    email::issue_login_code(&state, &user).await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn password_hint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state, &headers, "password-hint").await?;
    if !email::mail_configured(&state.env) {
        return Err(AppError::bad_request("Email delivery is not configured"));
    }
    let address = email::normalize_email(&payload.email)?;
    let db = state.database();
    let user = crate::service::identity::user::fetch_by_email_with(
        db,
        &address,
        "Failed to fetch password hint",
        || AppError::not_found("User"),
    )
    .await;
    match user {
        Ok(user) => {
            if email::send_password_hint(&state, &user).await.is_err() {
                log::warn!("Password hint delivery failed");
            }
        }
        Err(AppError::NotFound { .. }) => {}
        Err(error) => return Err(error),
    }
    // Identical response for known and unknown addresses.
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn send_email_verification_code(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = email::fetch_user(&state, &claims).await?;
    email::issue_code(
        &state,
        Some(&user),
        email::VERIFY_EMAIL,
        &user.email,
        "",
        "",
        false,
        false,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyEmailRequest {
    user_id: String,
    token:   String,
}

#[worker::send]
pub(in crate::api) async fn verify_email_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyEmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state, &headers, "verify-email").await?;
    let db = state.database();
    let user = UserRow::fetch_by_id_with(
        db,
        &payload.user_id,
        "Failed to fetch verification owner",
        || AppError::not_found("User"),
    )
    .await?;
    email::verify_code(
        &state,
        Some(&user),
        email::VERIFY_EMAIL,
        &user.email,
        "",
        "",
        &payload.token,
        true,
    )
    .await?;
    EmailStore::update_verified(
        db,
        &user.id,
        &user.email,
        &user.security_stamp,
        &crate::utils::time::now_rfc3339(),
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct ChangeEmailTokenRequest {
    new_email:    String,
    #[serde(flatten)]
    verification: AccountVerificationRequest,
}

#[worker::send]
pub(in crate::api) async fn request_email_change(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ChangeEmailTokenRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::verify_password_or_otp(&state, &claims, &payload.verification)
        .await?;
    let user = email::fetch_user(&state, &claims).await?;
    let address = email::normalize_email(&payload.new_email)?;
    if !state
        .config
        .allowed_emails
        .as_ref()
        .is_some_and(|emails| emails.contains(&address))
    {
        return Err(AppError::bad_request("Email address is not allowed"));
    }
    if EmailStore::email_in_use(state.database(), &address, &user.id).await? {
        return Err(AppError::bad_request("Email address is unavailable"));
    }
    email::issue_code(
        &state,
        Some(&user),
        email::CHANGE_EMAIL,
        &address,
        "",
        &claims.session_token,
        true,
        false,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TokenValue {
    Text(String),
    Number(u64),
}
impl TokenValue {
    fn text(&self) -> String {
        match self {
            Self::Text(value) => value.clone(),
            Self::Number(value) => format!("{value:06}"),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct ChangeEmailRequest {
    master_password_hash: String,
    new_master_password_hash: String,
    new_email: String,
    #[serde(alias = "key")]
    user_symmetric_key: String,
    token: TokenValue,
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
}

#[worker::send]
pub(in crate::api) async fn change_email(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ChangeEmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = email::fetch_user(&state, &claims).await?;
    if !crate::service::identity::user::verify_master_password(
        &user,
        &payload.master_password_hash,
    )
    .await?
    .is_valid()
    {
        return Err(AuthError::InvalidPassword.into());
    }
    let address = email::normalize_email(&payload.new_email)?;
    if payload.user_symmetric_key.is_empty() ||
        payload.new_master_password_hash.is_empty()
    {
        return Err(AppError::bad_request(
            "New password hash and encrypted key are required",
        ));
    }
    if !state
        .config
        .allowed_emails
        .as_ref()
        .is_some_and(|emails| emails.contains(&address))
    {
        return Err(AppError::bad_request("Email address is not allowed"));
    }
    let kdf = payload.kdf.unwrap_or(user.kdf_type);
    let iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let memory = if kdf == 1 {
        payload.kdf_memory.or(user.kdf_memory)
    } else {
        None
    };
    let parallelism = if kdf == 1 {
        payload.kdf_parallelism.or(user.kdf_parallelism)
    } else {
        None
    };
    ensure_supported_kdf(kdf, iterations, memory, parallelism)?;
    email::verify_code(
        &state,
        Some(&user),
        email::CHANGE_EMAIL,
        &address,
        "",
        &claims.session_token,
        &payload.token.text(),
        true,
    )
    .await?;
    let password = crate::service::identity::user::stored_password_for_user(
        &payload.new_master_password_hash,
        &user,
    )
    .await?;
    EmailStore::change_email(
        state.database(),
        &user,
        &claims.session_snapshot()?,
        EmailChange {
            address:         &address,
            password:        &password,
            key:             &payload.user_symmetric_key,
            kdf_type:        kdf,
            kdf_iterations:  iterations,
            kdf_memory:      memory,
            kdf_parallelism: parallelism,
        },
        &crate::utils::time::now_rfc3339(),
    )
    .await?;
    admin_notify::emit(&state.env, Event::EmailChange, &user.id).await;
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

#[worker::send]
pub(in crate::api) async fn request_registration_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EmailRequest>,
) -> AppResult<ApiResponse<String>> {
    email::rate_unauthenticated(&state, &headers, "registration-email").await?;
    let address = crate::service::identity::setup::authorize_registration(
        &state,
        &headers,
        &payload.email,
    )
    .await?;
    if !email::registration_verification_required(&state) {
        // Registration remains possible for private deployments that do not
        // enable email verification. This marker is never accepted as proof
        // when REQUIRE_EMAIL_VERIFICATION is enabled.
        return Ok(ApiResponse("email-verification-not-required".into()));
    }
    email::issue_code(
        &state,
        None,
        email::REGISTRATION,
        &address,
        "",
        "",
        false,
        false,
    )
    .await?;
    // This is an acknowledgement, never the emailed proof itself.
    Ok(ApiResponse("verification-email-sent".into()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyRegistrationEmailRequest {
    email:                    String,
    email_verification_token: String,
}

#[worker::send]
pub(in crate::api) async fn verify_registration_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyRegistrationEmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state, &headers, "registration-check").await?;
    email::verify_code(
        &state,
        None,
        email::REGISTRATION,
        &payload.email,
        "",
        "",
        &payload.email_verification_token,
        false,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn request_account_deletion_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state, &headers, "delete-recover").await?;
    if !email::mail_configured(&state.env) {
        return Err(AppError::bad_request("Email delivery is not configured"));
    }
    let db = state.database();
    match crate::service::identity::user::fetch_by_email_with(
        db,
        &payload.email,
        "Failed to fetch deletion recovery owner",
        || AppError::not_found("User"),
    )
    .await
    {
        Ok(user) => {
            if email::issue_code(
                &state,
                Some(&user),
                email::DELETE_RECOVER,
                &user.email,
                "",
                "",
                false,
                true,
            )
            .await
            .is_err()
            {
                log::warn!("Account deletion recovery delivery failed");
            }
        }
        Err(AppError::NotFound { .. }) => {}
        Err(error) => return Err(error),
    }
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn delete_account_with_recovery_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyEmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state, &headers, "delete-recover-token")
        .await?;
    let db = state.database();
    let user = UserRow::fetch_by_id_with(
        db,
        &payload.user_id,
        "Failed to fetch deletion recovery owner",
        || AppError::not_found("User"),
    )
    .await?;
    email::verify_code(
        &state,
        Some(&user),
        email::DELETE_RECOVER,
        &user.email,
        "",
        "",
        &payload.token,
        true,
    )
    .await?;
    crate::service::identity::user::delete_account(&state, &user.id, None)
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}
