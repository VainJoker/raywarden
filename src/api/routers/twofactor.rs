use axum::{
    Router,
    routing::{
        delete,
        get,
        post,
        put,
    },
};

use crate::api::{
    AppState,
    controller::twofactor,
};

pub fn twofactor_router() -> Router<AppState> {
    Router::new()
        .route("/api/two-factor", get(twofactor::get_twofactor))
        .route(
            "/api/two-factor/get-authenticator",
            post(twofactor::get_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            post(twofactor::activate_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            put(twofactor::activate_authenticator_put),
        )
        .route(
            "/api/two-factor/authenticator",
            delete(twofactor::disable_authenticator),
        )
        .route(
            "/api/two-factor/disable",
            post(twofactor::disable_twofactor),
        )
        .route(
            "/api/two-factor/disable",
            put(twofactor::disable_twofactor_put),
        )
        .route("/api/two-factor/get-recover", post(twofactor::get_recover))
        .route("/api/two-factor/recover", post(twofactor::recover))
}
