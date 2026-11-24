use std::sync::Arc;

use axum::{extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        AppState,
        common::{
            extract::{ClientIp, DeviceTypeHeader},
            json::Json,
            response::{ApiResponse, EmptyObject},
        },
    },
    errors::{AppError, AppResult, AuthError},
    models::identity::{
        email::{self as email_model, EmailChange},
        two_factor::TwoFactorRow,
        user::UserRow,
    },
    service::{
        identity::{
            email::{self, EmailPurpose, EmailVerifier, IssuePolicy, OtpFormat, ReservationMode},
            kdf::{KdfKind, ValidatedKdfParams},
            session::Claims,
            two_factor,
            two_factor::TwoFactorProvider,
            user::{AccountVerificationRequest, KdfParams},
        },
        notifications::{self, admin as admin_notify, admin::Event},
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
    email: String,
    #[serde(flatten)]
    verification: AccountVerificationRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyEmailFactorRequest {
    token: String,
    #[serde(flatten)]
    verification: AccountVerificationRequest,
}

#[worker::send]
pub(in crate::api) async fn request_protected_action_otp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = email::fetch_user(state.database(), &claims).await?;
    state
        .email_verifier()
        .issue_code(
            email::VerificationTarget {
                user: Some(&user),
                purpose: EmailPurpose::ProtectedAction,
                recipient: &user.email,
                context: "",
                session: &claims.session_token,
            },
            IssuePolicy {
                format: OtpFormat::SixDigit,
                reservation: ReservationMode::Fresh,
            },
        )
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn verify_protected_action_otp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyProtectedActionOtpRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = email::fetch_user(state.database(), &claims).await?;
    // This is the final authorization step for client-side vault export.
    // Consume its proof here rather than leaving it for a later server action.
    email::verify_code(
        state.database(),
        &state.jwt_keys.access_secret,
        email::VerificationTarget {
            user: Some(&user),
            purpose: EmailPurpose::ProtectedAction,
            recipient: &user.email,
            context: "",
            session: &claims.session_token,
        },
        &payload.otp,
        true,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct EmailFactorSetupResponse {
    enabled: bool,
    email: EmailFactorDetails,
    user_verification_token: String,
    object: &'static str,
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
    email: Option<String>,
    object: &'static str,
}

#[worker::send]
pub(in crate::api) async fn get_email_factor(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<EmailFactorSetupResponse>> {
    state
        .email_verifier()
        .verify_password_or_otp(&claims, &payload)
        .await?;
    let address = email::email_provider(state.database(), &claims.sub).await?;
    let token = two_factor::mint_email_factor_proof(
        &state.jwt_keys.access_secret,
        &claims,
        address.as_deref(),
    )?;
    Ok(ApiResponse(EmailFactorSetupResponse {
        enabled: address.is_some(),
        email: EmailFactorDetails {
            email: address,
            token: token.clone(),
        },
        user_verification_token: token,
        object: "twoFactorEmail",
    }))
}

#[worker::send]
pub(in crate::api) async fn send_email_factor_code(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendEmailFactorCodeRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    two_factor::verify_email_factor_action(
        state.database(),
        &state.env,
        &state.jwt_keys.access_secret,
        &claims,
        &payload.verification,
    )
    .await?;
    let user = email::fetch_user(state.database(), &claims).await?;
    let recipient = email::normalize_new_recipient(&payload.email)?;
    state
        .email_verifier()
        .issue_code(
            email::VerificationTarget {
                user: Some(&user),
                purpose: EmailPurpose::Setup,
                recipient: &recipient,
                context: "",
                session: &claims.session_token,
            },
            IssuePolicy {
                format: OtpFormat::SixDigit,
                reservation: ReservationMode::Fresh,
            },
        )
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn verify_email_factor(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyEmailFactorRequest>,
) -> AppResult<ApiResponse<EmailFactorStateResponse>> {
    let db = state.database();
    let access_secret = &state.jwt_keys.access_secret;
    let authorization = if let Some(token) = payload.verification.user_verification_token.as_deref()
    {
        two_factor::verify_email_factor_proof(db, access_secret, &claims, token).await?;
        None
    } else {
        state
            .email_verifier()
            .prepare_password_or_otp(&claims, &payload.verification)
            .await?
    };
    let user = email::fetch_user(db, &claims).await?;
    let session = claims.session_snapshot()?;
    let recipient = email_model::pending_recipient(
        db,
        &user.id,
        EmailPurpose::Setup.as_str(),
        crate::utils::time::now_seconds(),
        &claims.session_token,
    )
    .await?
    .ok_or_else(|| AppError::bad_request("No email setup is pending"))?;
    let verification = email::prepare_code(
        db,
        access_secret,
        email::VerificationTarget {
            user: Some(&user),
            purpose: EmailPurpose::Setup,
            recipient: &recipient,
            context: "",
            session: &claims.session_token,
        },
        &payload.token,
    )
    .await?;
    email::set_email_provider(
        db,
        &state.env,
        &session,
        &recipient,
        &verification,
        authorization.as_ref(),
    )
    .await?;
    Ok(ApiResponse(EmailFactorStateResponse {
        enabled: true,
        email: Some(recipient),
        object: "twoFactorEmail",
    }))
}

#[worker::send]
pub(in crate::api) async fn disable_email_factor(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<EmailFactorStateResponse>> {
    let db = state.database();
    let previous =
        TwoFactorRow::find_provider(db, &claims.sub, i32::from(TwoFactorProvider::Email)).await?;
    let was_enabled = previous.as_ref().is_some_and(|factor| factor.is_enabled);
    let authorization =
        two_factor::prepare_email_factor_action(&state.email_verifier(), &claims, &payload).await?;
    email_model::disable_provider(db, &authorization, previous.as_ref()).await?;
    if was_enabled {
        admin_notify::emit(&state.env, Event::TwoFactorDisable, &claims.sub).await;
    }
    Ok(ApiResponse(EmailFactorStateResponse {
        enabled: false,
        email: None,
        object: "twoFactorEmail",
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct SendLoginCodeRequest {
    #[serde(alias = "Email")]
    email: Option<String>,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(rename = "deviceIdentifier", alias = "DeviceIdentifier")]
    device_id: Option<String>,
    #[serde(alias = "AuthRequestId")]
    auth_request_id: Option<String>,
    #[serde(alias = "AuthRequestAccessCode")]
    auth_request_access_code: Option<String>,
}

#[worker::send]
pub(in crate::api) async fn send_login_code(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    device_header: Result<DeviceTypeHeader, AppError>,
    Json(payload): Json<SendLoginCodeRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state.env, &ip, "email-login").await?;
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
        let request = crate::models::identity::auth_request::AuthRequestRow::find_by_id(db, id)
            .await?
            .ok_or_else(|| AppError::bad_request("Invalid authentication request"))?;
        let user = UserRow::fetch_by_id_with(
            db,
            &request.user_id,
            "Failed to fetch authentication request owner",
            || AuthError::InvalidPassword.into(),
        )
        .await?;
        let DeviceTypeHeader(device_type) = device_header?;
        if !crate::service::identity::auth_request::auth_request_matches_login(
            &request,
            &crate::service::identity::auth_request::LoginApprovalMatch {
                user_id: &user.id,
                device_id: device,
                device_type,
                request_ip: &ip,
                access_code: code,
                security_stamp: &user.security_stamp,
            },
        ) || payload
            .email
            .as_deref()
            .is_some_and(|address| !address.trim().eq_ignore_ascii_case(&user.email))
        {
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
    state.email_verifier().issue_login_code(&user).await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn password_hint(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<EmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state.env, &ip, "password-hint").await?;
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
            if email::send_password_hint(
                state.database(),
                &state.env,
                &state.jwt_keys.access_secret,
                &user,
            )
            .await
            .is_err()
            {
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
    State(state): State<Arc<AppState>>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = email::fetch_user(state.database(), &claims).await?;
    state
        .email_verifier()
        .issue_code(
            email::VerificationTarget {
                user: Some(&user),
                purpose: EmailPurpose::VerifyEmail,
                recipient: &user.email,
                context: "",
                session: "",
            },
            IssuePolicy {
                format: OtpFormat::LongToken,
                reservation: ReservationMode::Fresh,
            },
        )
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyEmailRequest {
    user_id: String,
    token: String,
}

#[worker::send]
pub(in crate::api) async fn verify_email_token(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<VerifyEmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state.env, &ip, "verify-email").await?;
    let db = state.database();
    let user = UserRow::fetch_by_id_with(
        db,
        &payload.user_id,
        "Failed to fetch verification owner",
        || AppError::not_found("User"),
    )
    .await?;
    let verification = email::prepare_code(
        db,
        &state.jwt_keys.access_secret,
        email::VerificationTarget {
            user: Some(&user),
            purpose: EmailPurpose::VerifyEmail,
            recipient: &user.email,
            context: "",
            session: "",
        },
        &payload.token,
    )
    .await?;
    email_model::update_verified(
        db,
        &user.id,
        &user.email,
        &user.security_stamp,
        &verification,
        &crate::utils::time::now_rfc3339(),
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct ChangeEmailTokenRequest {
    new_email: String,
    #[serde(flatten)]
    verification: AccountVerificationRequest,
}

#[worker::send]
pub(in crate::api) async fn request_email_change(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ChangeEmailTokenRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    state
        .email_verifier()
        .verify_password_or_otp(&claims, &payload.verification)
        .await?;
    let user = email::fetch_user(state.database(), &claims).await?;
    let address = email::normalize_email(&payload.new_email)?;
    if !state
        .config
        .allowed_emails
        .as_ref()
        .is_some_and(|emails| emails.contains(&address))
    {
        return Err(AppError::bad_request("Email address is not allowed"));
    }
    if email_model::email_in_use(state.database(), &address, &user.id).await? {
        return Err(AppError::bad_request("Email address is unavailable"));
    }
    state
        .email_verifier()
        .issue_code(
            email::VerificationTarget {
                user: Some(&user),
                purpose: EmailPurpose::ChangeEmail,
                recipient: &address,
                context: "",
                session: &claims.session_token,
            },
            IssuePolicy {
                format: OtpFormat::SixDigit,
                reservation: ReservationMode::Fresh,
            },
        )
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}

fn deserialize_code<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Code {
        Text(String),
        Number(u64),
    }
    Ok(match Code::deserialize(deserializer)? {
        Code::Text(value) => value,
        Code::Number(value) => format!("{value:06}"),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct ChangeEmailRequest {
    master_password_hash: String,
    new_master_password_hash: String,
    new_email: String,
    #[serde(alias = "key")]
    user_symmetric_key: String,
    #[serde(deserialize_with = "deserialize_code")]
    token: String,
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
}

#[worker::send]
pub(in crate::api) async fn change_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ChangeEmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    let user = email::fetch_user(state.database(), &claims).await?;
    if !crate::service::identity::user::verify_master_password(&user, &payload.master_password_hash)
        .await?
        .is_valid()
    {
        return Err(AuthError::InvalidPassword.into());
    }
    let address = email::normalize_email(&payload.new_email)?;
    if payload.user_symmetric_key.is_empty() || payload.new_master_password_hash.is_empty() {
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
    let kind = payload.kdf.unwrap_or(user.kdf_type);
    let iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let memory = if kind == KdfKind::Argon2id as i32 {
        payload.kdf_memory.or(user.kdf_memory)
    } else {
        None
    };
    let parallelism = if kind == KdfKind::Argon2id as i32 {
        payload.kdf_parallelism.or(user.kdf_parallelism)
    } else {
        None
    };
    let kdf = KdfParams::from(ValidatedKdfParams::try_from(KdfParams {
        kdf_type: kind,
        iterations,
        memory,
        parallelism,
    })?);
    let verification = email::prepare_code(
        state.database(),
        &state.jwt_keys.access_secret,
        email::VerificationTarget {
            user: Some(&user),
            purpose: EmailPurpose::ChangeEmail,
            recipient: &address,
            context: "",
            session: &claims.session_token,
        },
        &payload.token,
    )
    .await?;
    let password = crate::service::identity::user::stored_password_for_user(
        &payload.new_master_password_hash,
        &user,
    )
    .await?;
    email_model::change_email(
        state.database(),
        &user,
        &claims.session_snapshot()?,
        &verification,
        EmailChange {
            address: &address,
            password: &password,
            key: &payload.user_symmetric_key,
            kdf_type: kdf.kdf_type,
            kdf_iterations: kdf.iterations,
            kdf_memory: kdf.memory,
            kdf_parallelism: kdf.parallelism,
        },
        &crate::utils::time::now_rfc3339(),
    )
    .await?;
    admin_notify::emit(&state.env, Event::EmailChange, &user.id).await;
    notifications::publish_account_logout(&state.env, &claims, &crate::utils::time::now_rfc3339())
        .await;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn request_registration_verification(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(payload): Json<EmailRequest>,
) -> AppResult<ApiResponse<String>> {
    email::rate_unauthenticated(&state.env, &ip, "registration-email").await?;
    let address = state
        .setup_guard()
        .authorize_registration(&headers, &payload.email)
        .await?;
    if !email::registration_verification_required(&state.env) {
        // Registration remains possible for private deployments that do not
        // enable email verification. This marker is never accepted as proof
        // when REQUIRE_EMAIL_VERIFICATION is enabled.
        return Ok(ApiResponse("email-verification-not-required".into()));
    }
    state
        .email_verifier()
        .issue_code(
            email::VerificationTarget {
                user: None,
                purpose: EmailPurpose::Registration,
                recipient: &address,
                context: "",
                session: "",
            },
            IssuePolicy {
                format: OtpFormat::LongToken,
                reservation: ReservationMode::Fresh,
            },
        )
        .await?;
    // This is an acknowledgement, never the emailed proof itself.
    Ok(ApiResponse("verification-email-sent".into()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyRegistrationEmailRequest {
    email: String,
    email_verification_token: String,
}

#[worker::send]
pub(in crate::api) async fn verify_registration_email(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<VerifyRegistrationEmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state.env, &ip, "registration-check").await?;
    email::verify_code(
        state.database(),
        &state.jwt_keys.access_secret,
        email::VerificationTarget {
            user: None,
            purpose: EmailPurpose::Registration,
            recipient: &payload.email,
            context: "",
            session: "",
        },
        &payload.email_verification_token,
        false,
    )
    .await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn request_account_deletion_recovery(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<EmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state.env, &ip, "delete-recover").await?;
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
            if state
                .email_verifier()
                .issue_code(
                    email::VerificationTarget {
                        user: Some(&user),
                        purpose: EmailPurpose::DeleteRecover,
                        recipient: &user.email,
                        context: "",
                        session: "",
                    },
                    IssuePolicy {
                        format: OtpFormat::LongToken,
                        reservation: ReservationMode::ReuseActive,
                    },
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
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<VerifyEmailRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    email::rate_unauthenticated(&state.env, &ip, "delete-recover-token").await?;
    let db = state.database();
    let user = UserRow::fetch_by_id_with(
        db,
        &payload.user_id,
        "Failed to fetch deletion recovery owner",
        || AppError::not_found("User"),
    )
    .await?;
    let verification = email::prepare_code(
        db,
        &state.jwt_keys.access_secret,
        email::VerificationTarget {
            user: Some(&user),
            purpose: EmailPurpose::DeleteRecover,
            recipient: &user.email,
            context: "",
            session: "",
        },
        &payload.token,
    )
    .await?;
    crate::service::identity::user::delete_account_with_email(db, &state.env, &user, &verification)
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}

impl AppState {
    pub(in crate::api) fn email_verifier(&self) -> EmailVerifier<'_> {
        EmailVerifier {
            db: self.database(),
            env: &self.env,
            domain: self.domain(),
            access_secret: &self.jwt_keys.access_secret,
        }
    }
}
