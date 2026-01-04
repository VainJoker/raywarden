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
    controller::folders,
};

pub fn folders_router() -> Router<AppState> {
    Router::new()
        .route("/api/folders", get(folders::list_folders))
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", get(folders::get_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        .route("/api/folders/{id}/delete", post(folders::delete_folder))
}
