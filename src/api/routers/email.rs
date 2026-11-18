use axum::{
    Router,
    routing::{
        post,
        put,
    },
};

use crate::api::{
    AppState,
    controller::email,
};

pub fn email_router() -> Router<AppState> {
    Router::new()
        .route(
            "/identity/accounts/register/send-verification-email",
            post(email::request_registration_verification),
        )
        .route("/api/accounts/request-otp", post(email::request_otp))
        .route("/accounts/request-otp", post(email::request_otp))
        .route("/api/accounts/verify-otp", post(email::verify_otp))
        .route("/accounts/verify-otp", post(email::verify_otp))
        .route("/api/accounts/password-hint", post(email::password_hint))
        .route(
            "/api/accounts/verify-email",
            post(email::request_verify_email),
        )
        .route(
            "/api/accounts/verify-email-token",
            post(email::verify_email_token),
        )
        .route(
            "/api/accounts/email-token",
            post(email::request_email_change),
        )
        .route("/api/accounts/email", post(email::change_email))
        .route(
            "/api/accounts/delete-recover",
            post(email::request_delete_recover),
        )
        .route(
            "/api/accounts/delete-recover-token",
            post(email::delete_recover_token),
        )
        .route(
            "/identity/accounts/register/verification-email-clicked",
            post(email::registration_clicked),
        )
        // root replaces the previous mock send-verification handler to avoid
        // duplicate paths when identity_router is merged.
        .route("/api/two-factor/get-email", post(email::get_email))
        .route("/api/two-factor/send-email", post(email::send_email))
        .route(
            "/api/two-factor/email",
            put(email::verify_email_factor)
                .post(email::verify_email_factor)
                .delete(email::disable_email),
        )
        .route(
            "/api/two-factor/send-email-login",
            post(email::send_email_login),
        )
        .route(
            "/two-factor/send-email-login",
            post(email::send_email_login),
        )
}
