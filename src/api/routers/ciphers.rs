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
    controller::{
        ciphers,
        import,
    },
};

pub fn cipher_router() -> Router<AppState> {
    Router::new()
        .route("/api/ciphers", get(ciphers::list_ciphers))
        .route("/api/ciphers", post(ciphers::create_cipher_simple))
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route("/api/ciphers/{id}", get(ciphers::get_cipher))
        .route(
            "/api/ciphers/{id}/details",
            get(ciphers::get_cipher_details),
        )
        .route("/api/ciphers/{id}", put(ciphers::update_cipher))
        .route("/api/ciphers/{id}", post(ciphers::update_cipher))
        // Cipher soft delete (PUT sets deleted_at timestamp)
        .route("/api/ciphers/{id}/delete", put(ciphers::soft_delete_cipher))
        // Cipher hard delete (DELETE/POST permanently removes cipher)
        .route("/api/ciphers/{id}", delete(ciphers::hard_delete_cipher))
        .route(
            "/api/ciphers/{id}/delete",
            post(ciphers::hard_delete_cipher),
        )
        // Partial update for folder/favorite
        .route(
            "/api/ciphers/{id}/partial",
            put(ciphers::update_cipher_partial),
        )
        .route(
            "/api/ciphers/{id}/partial",
            post(ciphers::update_cipher_partial),
        )
        // Cipher bulk soft delete
        .route(
            "/api/ciphers/delete",
            put(ciphers::soft_delete_ciphers_bulk),
        )
        // Cipher bulk hard delete
        .route(
            "/api/ciphers/delete",
            post(ciphers::hard_delete_ciphers_bulk),
        )
        .route("/api/ciphers", delete(ciphers::hard_delete_ciphers_bulk))
        // Cipher restore (clears deleted_at)
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        // Cipher bulk restore
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers_bulk))
        // Move ciphers to folder
        .route("/api/ciphers/move", post(ciphers::move_cipher_selected))
        .route("/api/ciphers/move", put(ciphers::move_cipher_selected))
        // Purge vault - delete all ciphers and folders (requires password
        // verification)
        .route("/api/ciphers/purge", post(ciphers::purge_vault))
        .route("/api/ciphers/import", post(import::import_data))
}
