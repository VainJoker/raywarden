//! Routes for personal vault resources and settings.
use std::sync::Arc;

use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    handler::Handler,
    routing::{get, post, put},
};

use crate::{
    api::{
        AppState,
        controller::vault::{attachments, ciphers, domains, folders},
    },
    models::vault::cipher::CipherMutation,
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
    use CipherMutation::{Archive, HardDelete, Move, Restore, SoftDelete, Unarchive};

    let mutate = ciphers::mutate_cipher;
    let select = ciphers::mutate_cipher_selection;
    let archive = ciphers::mutate_cipher_archive;
    let move_ciphers = select.layer(Extension(Move { folder_id: None }));
    Router::new()
        .route(
            "/api/ciphers",
            get(ciphers::list_ciphers)
                .post(ciphers::create_cipher)
                .delete(select.layer(Extension(HardDelete))),
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
                .delete(mutate.layer(Extension(HardDelete))),
        )
        .route("/api/ciphers/{id}/details", get(ciphers::get_cipher))
        .route(
            "/api/ciphers/{id}/delete",
            put(mutate.layer(Extension(SoftDelete))).post(mutate.layer(Extension(HardDelete))),
        )
        .route(
            "/api/ciphers/{id}/partial",
            put(ciphers::update_cipher_partial).post(ciphers::update_cipher_partial),
        )
        .route(
            "/api/ciphers/{id}/restore",
            put(mutate.layer(Extension(Restore))),
        )
        .route(
            "/api/ciphers/{id}/archive",
            put(mutate.layer(Extension(Archive))),
        )
        .route(
            "/api/ciphers/{id}/unarchive",
            put(mutate.layer(Extension(Unarchive))),
        )
        .route(
            "/api/ciphers/delete",
            put(select.layer(Extension(SoftDelete))).post(select.layer(Extension(HardDelete))),
        )
        .route(
            "/api/ciphers/restore",
            put(select.layer(Extension(Restore))),
        )
        .route(
            "/api/ciphers/archive",
            put(archive.layer(Extension(Archive))),
        )
        .route(
            "/api/ciphers/unarchive",
            put(archive.layer(Extension(Unarchive))),
        )
        .route(
            "/api/ciphers/move",
            post(move_ciphers.clone()).put(move_ciphers),
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
