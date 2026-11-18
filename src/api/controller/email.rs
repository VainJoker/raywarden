use axum::{
    Json,
    extract::State,
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
            email,
            kdf::ensure_supported_kdf,
            twofactor,
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
        crypto,
        delivery,
    },
    models::{
        email::EmailDB,
        twofactor::{
            TwoFactorDB,
            TwoFactorType,
        },
        user::{
            PasswordOrOtpData,
            UserDB,
        },
    },
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailRequest {
    pub email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeRequest {
    #[serde(alias = "OTP", alias = "token")]
    pub otp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorSend {
    pub email:        String,
    #[serde(flatten)]
    pub verification: PasswordOrOtpData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorVerify {
    pub token:        String,
    #[serde(flatten)]
    pub verification: PasswordOrOtpData,
}

#[worker::send]
pub async fn request_otp(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
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
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn verify_otp(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CodeRequest>,
) -> AppResult<Json<Value>> {
    let user = email::fetch_user(&state, &claims).await?;
    email::verify_code(
        &state,
        Some(&user),
        email::PROTECTED_ACTION,
        &user.email,
        "",
        &claims.session_token,
        &payload.otp,
        false,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn get_email(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<PasswordOrOtpData>,
) -> AppResult<Json<Value>> {
    email::verify_password_or_otp(&state, &claims, &payload).await?;
    let address = email::email_provider(&state.get_db(), &claims.sub).await?;
    let token = twofactor::mint_email_factor_proof(
        &state,
        &claims,
        address.as_deref(),
    )?;
    Ok(Json(
        json!({"enabled":address.is_some(),"email":{"email":address,"token":token},"userVerificationToken":token,"object":"twoFactorEmail"}),
    ))
}

#[worker::send]
pub async fn send_email(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<FactorSend>,
) -> AppResult<Json<Value>> {
    twofactor::verify_email_factor_action(
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
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn verify_email_factor(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<FactorVerify>,
) -> AppResult<Json<Value>> {
    twofactor::verify_email_factor_action(
        &state,
        &claims,
        &payload.verification,
    )
    .await?;
    let user = email::fetch_user(&state, &claims).await?;
    let db = state.get_db();
    let recipient = EmailDB::pending_recipient(
        &db,
        &user.id,
        email::EMAIL_SETUP,
        crate::infra::time::now_seconds(),
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
    Ok(Json(
        json!({"enabled":true,"email":recipient,"object":"twoFactorEmail"}),
    ))
}

#[worker::send]
pub async fn disable_email(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<PasswordOrOtpData>,
) -> AppResult<Json<Value>> {
    twofactor::verify_email_factor_action(&state, &claims, &payload).await?;
    let db = state.get_db();
    let was_enabled = TwoFactorDB::get_for_user_by_type(
        &db,
        &claims.sub,
        TwoFactorType::Email as i32,
    )
    .await?
    .is_some_and(|factor| factor.enabled);
    EmailDB::disable_provider(&db, &claims.sub).await?;
    if was_enabled {
        admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub)
            .await;
    }
    Ok(Json(json!({"enabled":false,"object":"twoFactorEmail"})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailLoginRequest {
    #[serde(alias = "Email")]
    pub email:                    Option<String>,
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash:     Option<String>,
    #[serde(alias = "DeviceIdentifier")]
    pub device_identifier:        Option<String>,
    #[serde(alias = "AuthRequestId")]
    pub auth_request_id:          Option<String>,
    #[serde(alias = "AuthRequestAccessCode")]
    pub auth_request_access_code: Option<String>,
}

#[worker::send]
pub async fn send_email_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EmailLoginRequest>,
) -> AppResult<Json<Value>> {
    email::rate_unauthenticated(&state, &headers, "email-login").await?;
    let db = state.get_db();
    let user = if let (Some(address), Some(hash)) = (
        payload.email.as_deref(),
        payload.master_password_hash.as_deref(),
    ) {
        let user = UserDB::fetch_by_email_with(
            &db,
            address,
            "Failed to find email login owner",
            || AuthError::InvalidPassword.into(),
        )
        .await?;
        if !user.verify_master_password(hash).await?.is_valid() {
            return Err(AuthError::InvalidPassword.into());
        }
        user
    } else if let (Some(id), Some(code), Some(device)) = (
        payload.auth_request_id.as_deref(),
        payload.auth_request_access_code.as_deref(),
        payload.device_identifier.as_deref(),
    ) {
        let request =
            crate::models::auth_request::AuthRequestDB::find_by_id(&db, id)
                .await?
                .ok_or_else(|| {
                    AppError::bad_request("Invalid authentication request")
                })?;
        let user = UserDB::fetch_by_id_with(
            &db,
            &request.user_id,
            "Failed to fetch authentication request owner",
            || AuthError::InvalidPassword.into(),
        )
        .await?;
        let kind = crate::api::service::auth::request_device_type(&headers)?;
        if !request.matches_login(
            &user.id,
            device,
            kind,
            crate::api::service::rate::client_ip(&headers),
            code,
            &user.security_stamp,
        ) || payload.email.as_deref().is_some_and(|address| {
            !address.trim().eq_ignore_ascii_case(&user.email)
        }) {
            return Err(AuthError::InvalidCredentials(
                "Invalid authentication request".into(),
            )
            .into());
        }
        user
    } else {
        return Err(AppError::bad_request(
            "Password or approved authentication request is required",
        ));
    };
    email::issue_login_code(&state, &user).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn password_hint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EmailRequest>,
) -> AppResult<Json<Value>> {
    email::rate_unauthenticated(&state, &headers, "password-hint").await?;
    if !delivery::mail_configured(&state.env) {
        return Err(AppError::bad_request("Email delivery is not configured"));
    }
    let address = email::normalize_email(&payload.email)?;
    let db = state.get_db();
    let user = UserDB::fetch_by_email_with(
        &db,
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
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn request_verify_email(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
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
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyEmailToken {
    pub user_id: String,
    pub token:   String,
}

#[worker::send]
pub async fn verify_email_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyEmailToken>,
) -> AppResult<Json<Value>> {
    email::rate_unauthenticated(&state, &headers, "verify-email").await?;
    let db = state.get_db();
    let user = UserDB::fetch_by_id_with(
        &db,
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
    EmailDB::update_verified(
        &db,
        &user.id,
        &user.email,
        &user.security_stamp,
        &crate::infra::time::now_rfc3339(),
    )
    .await?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailTokenRequest {
    pub new_email:    String,
    #[serde(flatten)]
    pub verification: PasswordOrOtpData,
}

#[worker::send]
pub async fn request_email_change(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ChangeEmailTokenRequest>,
) -> AppResult<Json<Value>> {
    email::verify_password_or_otp(&state, &claims, &payload.verification)
        .await?;
    let user = email::fetch_user(&state, &claims).await?;
    let address = email::normalize_email(&payload.new_email)?;
    if let Some(patterns) = &state.config.allowed_emails {
        if !patterns
            .iter()
            .any(|pattern| glob_match::glob_match(pattern, &address))
        {
            return Err(AppError::bad_request("Email address is not allowed"));
        }
    }
    if EmailDB::email_in_use(&state.get_db(), &address, &user.id).await? {
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
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum TokenValue {
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
pub struct ChangeEmailRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub new_email: String,
    #[serde(alias = "key")]
    pub user_symmetric_key: String,
    pub token: TokenValue,
    pub kdf: Option<i32>,
    pub kdf_iterations: Option<i32>,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
}

#[worker::send]
pub async fn change_email(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ChangeEmailRequest>,
) -> AppResult<Json<Value>> {
    let user = email::fetch_user(&state, &claims).await?;
    if !user
        .verify_master_password(&payload.master_password_hash)
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
    if let Some(patterns) = &state.config.allowed_emails {
        if !patterns
            .iter()
            .any(|pattern| glob_match::glob_match(pattern, &address))
        {
            return Err(AppError::bad_request("Email address is not allowed"));
        }
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
    let salt = crypto::generate_salt()?;
    let hash = crypto::hash_password_for_storage(
        &payload.new_master_password_hash,
        &salt,
    )
    .await?;
    EmailDB::change_email(
        &state.get_db(),
        &user.id,
        &claims.sstamp,
        &address,
        &hash,
        &salt,
        &payload.user_symmetric_key,
        kdf,
        iterations,
        memory,
        parallelism,
        &crate::infra::time::now_rfc3339(),
        &user.master_password_hash,
        &crate::models::account_keys::AccountSnapshot::from_user(&user)
            .to_json()?,
        claims.device().unwrap_or_default(),
        &claims.session_token,
    )
    .await?;
    admin_notify::emit(&state.env, Event::EmailChange, &user.id).await;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn request_registration_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EmailRequest>,
) -> AppResult<Json<String>> {
    email::rate_unauthenticated(&state, &headers, "registration-email").await?;
    let address = crate::api::service::setup::authorize_registration(
        &state,
        &headers,
        &payload.email,
    )
    .await?;
    if !email::registration_verification_required(&state) {
        // Registration remains possible for private deployments that do not
        // enable email verification. This marker is never accepted as proof
        // when REQUIRE_EMAIL_VERIFICATION is enabled.
        return Ok(Json("email-verification-not-required".into()));
    }
    if let Some(patterns) = &state.config.allowed_emails {
        if !patterns
            .iter()
            .any(|pattern| glob_match::glob_match(pattern, &address))
        {
            return Err(AppError::bad_request("Email address is not allowed"));
        }
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
    Ok(Json("verification-email-sent".into()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationVerification {
    pub email:                    String,
    pub email_verification_token: String,
}

#[worker::send]
pub async fn registration_clicked(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegistrationVerification>,
) -> AppResult<Json<Value>> {
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
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn request_delete_recover(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EmailRequest>,
) -> AppResult<Json<Value>> {
    email::rate_unauthenticated(&state, &headers, "delete-recover").await?;
    if !delivery::mail_configured(&state.env) {
        return Err(AppError::bad_request("Email delivery is not configured"));
    }
    let db = state.get_db();
    match UserDB::fetch_by_email_with(
        &db,
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
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn delete_recover_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyEmailToken>,
) -> AppResult<Json<Value>> {
    email::rate_unauthenticated(&state, &headers, "delete-recover-token")
        .await?;
    let db = state.get_db();
    let user = UserDB::fetch_by_id_with(
        &db,
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
    crate::api::service::notifications::publish_user_update(
        &state.env,
        &user.id,
        crate::api::service::notifications::UpdateType::LogOut,
        &crate::infra::time::now_rfc3339(),
        None,
    )
    .await;
    crate::api::service::push::unregister_user(&state.env, &user.id).await;
    UserDB::delete_user(&db, &user.id).await?;
    if let Err(error) =
        crate::infra::storage::cleanup::drain(&state.env, &db).await
    {
        log::warn!("Deleted account object cleanup deferred: {error}");
    }
    admin_notify::emit(&state.env, Event::AccountDeleted, &user.id).await;
    Ok(Json(json!({})))
}
