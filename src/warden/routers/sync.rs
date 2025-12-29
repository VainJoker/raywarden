use axum::{
    Router,
    routing::get,
};

use crate::warden::{
    AppState,
    api::sync,
};

pub fn sync_router() -> Router<AppState> {
    Router::new().route("/api/sync", get(sync::get_sync_data))
}
