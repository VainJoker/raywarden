use axum::{
    Router,
    routing::get,
};

use crate::api::{
    AppState,
    controller::auth_requests,
};

pub fn auth_requests_router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/auth-requests",
            get(auth_requests::get_auth_requests_pending)
                .post(auth_requests::post_auth_request),
        )
        .route(
            "/api/auth-requests/pending",
            get(auth_requests::get_auth_requests_pending),
        )
        .route(
            "/api/auth-requests/{id}",
            get(auth_requests::get_auth_request)
                .put(auth_requests::put_auth_request),
        )
        .route(
            "/api/auth-requests/{id}/response",
            get(auth_requests::get_auth_request_response),
        )
}
