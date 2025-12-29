use axum::{
    Router,
    routing::post,
};

use crate::warden::{
    AppState,
    api::{
        accounts,
        identity,
    },
};

pub fn identity_router() -> Router<AppState> {
    Router::new()
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
}
