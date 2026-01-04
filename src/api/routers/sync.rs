use axum::{
    Router,
    routing::get,
};

use crate::api::{
    AppState,
    controller::sync,
};

pub fn sync_router() -> Router<AppState> {
    Router::new().route("/api/sync", get(sync::get_sync_data))
}
