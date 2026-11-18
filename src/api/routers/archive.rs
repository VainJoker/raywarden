use axum::{
    Router,
    routing::put,
};

use crate::api::{
    AppState,
    controller::archive,
};

pub fn archive_router() -> Router<AppState> {
    Router::new()
        .route("/api/ciphers/{id}/archive", put(archive::archive_cipher))
        .route(
            "/api/ciphers/{id}/unarchive",
            put(archive::unarchive_cipher),
        )
        .route("/api/ciphers/archive", put(archive::archive_ciphers_bulk))
        .route(
            "/api/ciphers/unarchive",
            put(archive::unarchive_ciphers_bulk),
        )
}
