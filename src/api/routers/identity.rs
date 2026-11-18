use axum::{
    Router,
    routing::post,
};

use crate::api::{
    AppState,
    controller::{
        accounts,
        identity,
    },
};

pub fn identity_router() -> Router<AppState> {
    Router::new()
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
        .route("/identity/connect/token", post(identity::token))
}
