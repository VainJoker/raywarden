use axum::{
    Router,
    routing::get,
};

use crate::api::{
    AppState,
    controller::config,
};

pub fn config_router() -> Router<AppState> {
    Router::new().route("/api/config", get(config::config))
}
