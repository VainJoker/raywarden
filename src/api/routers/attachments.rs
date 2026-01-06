use axum::{
    Router,
    routing::{
        delete,
        get,
        post,
    },
};

use crate::api::{
    AppState,
    controller::attachments,
};

pub fn attachment_router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/ciphers/{id}/attachment/v2",
            post(attachments::create_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment",
            post(attachments::upload_attachment_legacy),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            post(attachments::upload_attachment_v2_data),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            get(attachments::get_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            delete(attachments::delete_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/delete",
            post(attachments::delete_attachment_post),
        )
}
