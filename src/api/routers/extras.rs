use axum::{
    Router,
    routing::{
        get,
        post,
    },
};

use crate::api::{
    AppState,
    controller::{
        extras,
        presentation,
    },
};

pub fn extras_router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/accounts/keys",
            get(extras::get_keys).post(extras::post_keys),
        )
        .route(
            "/api/users/{user_id}/public-key",
            get(extras::get_public_key),
        )
        .route(
            "/api/accounts/key-management/user-key-id",
            post(extras::post_user_key_id),
        )
        .route("/events/collect", post(extras::events))
        .route("/api/events/collect", post(extras::events))
        .route(
            "/.well-known/apple-app-site-association",
            get(extras::apple_association),
        )
        .route("/icons/{domain}/icon.png", get(presentation::icon))
        .route("/css/vaultwarden.css", get(presentation::css))
        .route("/js/raywarden.js", get(presentation::client_script))
        .route("/api/d1/usage", get(presentation::usage))
}
