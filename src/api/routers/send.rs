//! Routes for Send and human verification.
use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post, put},
};

use crate::api::{
    AppState,
    controller::send::{self, turnstile},
};

pub(super) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(turnstile_routes())
        .route(
            "/api/sends",
            get(send::list_sends).post(send::create_text_send),
        )
        .route(
            "/api/sends/{id}",
            get(send::get_send)
                .put(send::update_send)
                .delete(send::delete_send),
        )
        .route(
            "/api/sends/{id}/remove-password",
            put(send::remove_password),
        )
        .route("/api/sends/file/v2", post(send::reserve_send_file_upload))
        .route(
            "/api/sends/{id}/file/{file_id}",
            post(send::upload_send_file_multipart).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/sends/{id}/file/{file_id}/azure-upload",
            put(send::upload_send_file_with_token)
                .post(send::upload_send_file_with_token)
                .layer(DefaultBodyLimit::disable()),
        )
        // Some upload clients use the multipart path without the API prefix.
        .route(
            "/sends/{id}/file/{file_id}",
            post(send::upload_send_file_multipart).layer(DefaultBodyLimit::disable()),
        )
        .route("/api/sends/{id}/{file_id}", get(send::download_send_file))
        .route("/api/sends/access", post(send::access_send_with_token))
        .route(
            "/api/sends/access/file/{file_id}",
            post(send::grant_send_file_access_with_token),
        )
        .route("/api/sends/access/{access_id}", post(send::access_send))
        .route(
            "/api/sends/{id}/access/file/{file_id}",
            post(send::grant_send_file_access),
        )
}

fn turnstile_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/send-verify/status",
            get(turnstile::send_verify_status),
        )
        .route("/send-verify", get(turnstile::send_verify_page))
        .route("/api/send-verify", post(turnstile::verify_send))
}
