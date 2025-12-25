use axum::{
    Router,
    routing::{
        get,
        post,
    },
};

use crate::warden::{
    AppState,
    api::{
        accounts,
        config,
        identity,
        sync,
    },
};

/// Build the main application router with all routes.
pub fn api_router(state: AppState) -> Router {
    Router::new()
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route("/identity/accounts/register", post(accounts::register))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        .route("/api/config", get(config::config))
        .route("/api/sync", get(sync::get_sync_data))
        // TODO: Add more routes as implemented
        .with_state(state)
}
