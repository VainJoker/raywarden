use axum::{
    Router,
    routing::post,
};

use crate::api::{
    AppState,
    controller::sessions,
};

pub fn sessions_router() -> Router<AppState> {
    Router::new().route(
        "/api/accounts/security-stamp",
        post(sessions::post_security_stamp),
    )
}
