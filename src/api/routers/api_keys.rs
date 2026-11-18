use axum::{
    Router,
    routing::post,
};

use crate::api::{
    AppState,
    controller::api_keys,
};
pub fn api_keys_router() -> Router<AppState> {
    Router::new()
        .route("/api/accounts/api-key", post(api_keys::get_api_key))
        .route(
            "/api/accounts/rotate-api-key",
            post(api_keys::rotate_api_key),
        )
}
