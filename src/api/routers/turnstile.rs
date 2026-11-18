use axum::{
    Router,
    routing::{
        get,
        post,
    },
};

use crate::api::{
    AppState,
    controller::turnstile,
};
pub fn turnstile_router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/send-verify/status",
            get(turnstile::send_verify_status),
        )
        .route("/send-verify", get(turnstile::send_verify_page))
        .route("/api/send-verify", post(turnstile::verify_send))
}
