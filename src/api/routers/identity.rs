//! Account, login and authentication routes for the API and Identity prefixes.
use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, post, put},
};

use crate::api::{
    AppState,
    controller::identity::{
        account_keys, accounts, api_keys, auth_requests, devices, email, setup, token, two_factor,
        webauthn,
    },
};

const ACCOUNT_ROTATION_MAX_BYTES: usize = 16 * 1024 * 1024;
const TOKEN_FORM_MAX_BYTES: usize = 65_536;

pub(super) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(accounts())
        .merge(token())
        .merge(account_keys())
        .merge(api_keys())
        .merge(devices())
        .merge(auth_requests())
        .merge(email())
        .merge(two_factor())
        .merge(webauthn())
        .merge(setup())
}

fn accounts() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/hibp/breach", get(accounts::hibp_breach))
        .route("/api/d1/usage", get(accounts::usage))
        .route("/api/accounts/prelogin", post(accounts::prelogin))
        .route("/api/accounts/prelogin/password", post(accounts::prelogin))
        .route("/api/accounts/register", post(accounts::register))
        // Bitwarden clients also use the Identity prefix for account bootstrap.
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/identity/accounts/prelogin/password",
            post(accounts::prelogin),
        )
        .route("/identity/accounts/register", post(accounts::register))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route(
            "/api/accounts/verify-password",
            post(accounts::verify_password),
        )
        .route("/accounts/verify-password", post(accounts::verify_password))
        .route("/api/tasks", get(accounts::get_tasks))
        .route("/api/accounts/tasks", get(accounts::get_tasks))
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        .route(
            "/api/accounts/profile",
            get(accounts::get_profile)
                .post(accounts::update_profile)
                .put(accounts::update_profile),
        )
        .route(
            "/api/accounts/avatar",
            put(accounts::update_avatar_color).post(accounts::update_avatar_color),
        )
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/accounts/delete", post(accounts::delete_account))
        .route(
            "/api/accounts/kdf",
            post(accounts::change_kdf).layer(DefaultBodyLimit::max(ACCOUNT_ROTATION_MAX_BYTES)),
        )
        .route(
            "/api/accounts/password",
            post(accounts::change_password)
                .layer(DefaultBodyLimit::max(ACCOUNT_ROTATION_MAX_BYTES)),
        )
        .route("/api/accounts/set-password", post(accounts::set_password))
}

fn token() -> Router<Arc<AppState>> {
    Router::new().route(
        "/identity/connect/token",
        post(token::exchange_token).layer(DefaultBodyLimit::max(TOKEN_FORM_MAX_BYTES)),
    )
}

fn account_keys() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/accounts/keys",
            get(account_keys::get_key_pair).post(account_keys::update_key_pair),
        )
        .route(
            "/api/users/{user_id}/public-key",
            get(account_keys::get_public_key),
        )
        .route(
            "/api/accounts/key-management/user-key-id",
            post(account_keys::update_user_key_id),
        )
        .route(
            "/api/accounts/key-management/rotate-user-keys",
            post(account_keys::rotate_user_keys)
                .layer(DefaultBodyLimit::max(ACCOUNT_ROTATION_MAX_BYTES)),
        )
        .route(
            "/api/accounts/key-management/key-rotation-data",
            get(account_keys::get_key_rotation_data),
        )
        .route(
            "/api/users/{id}/keys",
            get(account_keys::get_account_public_keys),
        )
        .route(
            "/api/accounts/key-management/rotate-user-account-keys",
            post(account_keys::rotate_account_keys)
                .layer(DefaultBodyLimit::max(ACCOUNT_ROTATION_MAX_BYTES)),
        )
}

fn api_keys() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/accounts/api-key", post(api_keys::get_api_key))
        .route(
            "/api/accounts/rotate-api-key",
            post(api_keys::rotate_api_key),
        )
}

fn devices() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/devices", get(devices::list_devices))
        .route("/api/devices/knowndevice", get(devices::get_known_device))
        .route(
            "/api/devices/identifier/{device_id}",
            delete(devices::delete_device).get(devices::get_device),
        )
        .route(
            "/api/devices/identifier/{device_id}/delete",
            post(devices::delete_device),
        )
        .route(
            "/api/devices/identifier/{device_id}/token",
            post(devices::set_device_push_token).put(devices::set_device_push_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/clear-token",
            put(devices::clear_device_push_token).post(devices::clear_device_push_token),
        )
        .route(
            "/api/accounts/security-stamp",
            post(devices::revoke_all_sessions),
        )
}

fn auth_requests() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/auth-requests",
            get(auth_requests::list_pending_auth_requests).post(auth_requests::create_auth_request),
        )
        .route(
            "/api/auth-requests/pending",
            get(auth_requests::list_pending_auth_requests),
        )
        .route(
            "/api/auth-requests/admin-request",
            post(auth_requests::create_auth_request),
        )
        .route(
            "/api/auth-requests/{id}",
            get(auth_requests::get_auth_request).put(auth_requests::respond_to_auth_request),
        )
        .route(
            "/api/auth-requests/{id}/response",
            get(auth_requests::get_auth_request_response),
        )
}

fn email() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/identity/accounts/register/send-verification-email",
            post(email::request_registration_verification),
        )
        .route(
            "/identity/accounts/register/verification-email-clicked",
            post(email::verify_registration_email),
        )
        .route(
            "/api/accounts/request-otp",
            post(email::request_protected_action_otp),
        )
        .route(
            "/api/accounts/verify-otp",
            post(email::verify_protected_action_otp),
        )
        // OTP clients also use paths without the API prefix.
        .route(
            "/accounts/request-otp",
            post(email::request_protected_action_otp),
        )
        .route(
            "/accounts/verify-otp",
            post(email::verify_protected_action_otp),
        )
        .route("/api/accounts/password-hint", post(email::password_hint))
        .route(
            "/api/accounts/verify-email",
            post(email::send_email_verification_code),
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
            post(email::request_account_deletion_recovery),
        )
        .route(
            "/api/accounts/delete-recover-token",
            post(email::delete_account_with_recovery_token),
        )
}

fn email_two_factor() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/two-factor/get-email", post(email::get_email_factor))
        .route(
            "/api/two-factor/send-email",
            post(email::send_email_factor_code),
        )
        .route(
            "/api/two-factor/email",
            put(email::verify_email_factor)
                .post(email::verify_email_factor)
                .delete(email::disable_email_factor),
        )
        .route(
            "/api/two-factor/send-email-login",
            post(email::send_login_code),
        )
        .route("/two-factor/send-email-login", post(email::send_login_code))
}

fn two_factor() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/two-factor/get-device-verification-settings",
            get(two_factor::device_verification_settings),
        )
        .route(
            "/api/two-factor",
            get(two_factor::list_two_factor_providers),
        )
        .route(
            "/api/two-factor/get-authenticator",
            post(two_factor::prepare_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            post(two_factor::activate_authenticator)
                .put(two_factor::activate_authenticator)
                .delete(two_factor::disable_authenticator),
        )
        .route(
            "/api/two-factor/disable",
            post(two_factor::disable_two_factor).put(two_factor::disable_two_factor),
        )
        .route(
            "/api/two-factor/get-recover",
            post(two_factor::get_two_factor_recovery_code),
        )
        .route("/api/two-factor/recover", post(two_factor::recover))
        .merge(email_two_factor())
}

fn webauthn() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/webauthn",
            get(webauthn::list_credentials)
                .post(webauthn::create_credential)
                .put(webauthn::update_credential),
        )
        .route(
            "/api/webauthn/attestation-options",
            post(webauthn::attestation_options),
        )
        .route("/api/webauthn/prf-probe", post(webauthn::prf_probe))
        .route(
            "/api/webauthn/assertion-options",
            post(webauthn::assertion_options),
        )
        .route(
            "/api/webauthn/{credential_id}",
            put(webauthn::update_credential_by_id),
        )
        .route(
            "/api/webauthn/{credential_id}/delete",
            post(webauthn::delete_credential),
        )
        .route(
            "/api/two-factor/get-webauthn",
            post(webauthn::list_two_factor_providers),
        )
        .route(
            "/api/two-factor/get-webauthn-challenge",
            post(webauthn::two_factor_challenge),
        )
        .route(
            "/api/two-factor/webauthn",
            post(webauthn::register_two_factor)
                .put(webauthn::register_two_factor)
                .delete(webauthn::delete_two_factor),
        )
        .route(
            "/api/two-factor/webauthn/all",
            delete(webauthn::delete_all_two_factors),
        )
        .route(
            "/accounts/webauthn/assertion-options",
            get(webauthn::identity_assertion_options).post(webauthn::identity_assertion_options),
        )
        .route(
            "/identity/accounts/webauthn/assertion-options",
            get(webauthn::identity_assertion_options).post(webauthn::identity_assertion_options),
        )
}

fn setup() -> Router<Arc<AppState>> {
    Router::new()
        .route("/setup", get(setup::page))
        .route("/api/accounts/setup", post(setup::authorize))
}
