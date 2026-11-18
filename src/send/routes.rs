//! Public Send routes and per-upload body-limit policy.
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{
        get,
        post,
        put,
    },
};

use super::http;
use crate::api::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/sends",
            get(http::list_sends).post(http::create_text_send),
        )
        .route("/api/sends/file/v2", post(http::create_file_send_v2))
        .route(
            "/api/sends/file",
            post(http::create_file_send_legacy)
                .layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/sends/{id}/file/{file_id}",
            post(http::upload_file_send_direct)
                .layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/sends/{id}/file/{file_id}",
            post(http::upload_file_send_direct)
                .layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/sends/{id}/file/{file_id}/azure-upload",
            put(http::upload_file_send_azure)
                .post(http::upload_file_send_azure)
                .layer(DefaultBodyLimit::disable()),
        )
        .route("/api/sends/{id}/{file_id}", get(http::download_file_send))
        .route(
            "/api/sends/{id}",
            get(http::get_send)
                .put(http::update_send)
                .delete(http::delete_send),
        )
        .route(
            "/api/sends/{id}/remove-password",
            put(http::remove_password),
        )
        .route("/api/sends/access", post(http::access_send_with_token))
        .route(
            "/api/sends/access/file/{file_id}",
            post(http::access_file_send_with_token),
        )
        .route("/api/sends/access/{access_id}", post(http::access_send))
        .route(
            "/api/sends/{id}/access/file/{file_id}",
            post(http::access_file_send),
        )
}
