//! Routes for personal vault resources and settings.
use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post, put},
};

use crate::api::{
    AppState,
    controller::vault::{attachments, ciphers, domains, folders},
};

pub(super) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(attachments())
        .merge(ciphers())
        .merge(folders())
        .merge(domains())
}

fn attachments() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/ciphers/{id}/attachment/v2",
            post(attachments::reserve_attachment_upload),
        )
        // Only the upload methods bypass Axum's default body limit.
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            post(attachments::upload_attachment_multipart).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            get(attachments::get_attachment).delete(attachments::delete_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/azure-upload",
            put(attachments::upload_attachment_with_token).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/download",
            get(attachments::download_attachment).head(attachments::download_attachment),
        )
        // Compatibility paths used for uploads, downloads and deletion.
        .route(
            "/ciphers/{id}/attachment/{attachment_id}",
            post(attachments::upload_attachment_multipart).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/attachments/{id}/{attachment_id}",
            get(attachments::download_attachment).head(attachments::download_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/delete",
            post(attachments::delete_attachment),
        )
}

fn ciphers() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/ciphers",
            get(ciphers::list_ciphers)
                .post(ciphers::create_cipher)
                .delete(ciphers::hard_delete_ciphers_bulk),
        )
        .route(
            "/api/ciphers/create",
            post(ciphers::create_cipher_with_collections),
        )
        .route(
            "/api/ciphers/{id}",
            get(ciphers::get_cipher)
                .put(ciphers::update_cipher)
                .post(ciphers::update_cipher)
                .delete(ciphers::hard_delete_cipher),
        )
        .route("/api/ciphers/{id}/details", get(ciphers::get_cipher))
        .route(
            "/api/ciphers/{id}/delete",
            put(ciphers::soft_delete_cipher).post(ciphers::hard_delete_cipher),
        )
        .route(
            "/api/ciphers/{id}/partial",
            put(ciphers::update_cipher_partial).post(ciphers::update_cipher_partial),
        )
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        .route("/api/ciphers/{id}/archive", put(ciphers::archive_cipher))
        .route(
            "/api/ciphers/{id}/unarchive",
            put(ciphers::unarchive_cipher),
        )
        .route(
            "/api/ciphers/delete",
            put(ciphers::soft_delete_ciphers_bulk).post(ciphers::hard_delete_ciphers_bulk),
        )
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers_bulk))
        .route("/api/ciphers/archive", put(ciphers::archive_ciphers_bulk))
        .route(
            "/api/ciphers/unarchive",
            put(ciphers::unarchive_ciphers_bulk),
        )
        .route(
            "/api/ciphers/move",
            post(ciphers::move_ciphers).put(ciphers::move_ciphers),
        )
        .route("/api/ciphers/purge", post(ciphers::purge_vault))
        .route("/api/ciphers/import", post(ciphers::import_data))
}

fn folders() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/folders",
            get(folders::list_folders).post(folders::create_folder),
        )
        .route(
            "/api/folders/{id}",
            get(folders::get_folder)
                .put(folders::update_folder)
                .post(folders::update_folder)
                .delete(folders::delete_folder),
        )
        .route("/api/folders/{id}/delete", post(folders::delete_folder))
}

fn domains() -> Router<Arc<AppState>> {
    Router::new().route(
        "/api/settings/domains",
        get(domains::get_domains)
            .post(domains::update_domains)
            .put(domains::update_domains),
    )
}
