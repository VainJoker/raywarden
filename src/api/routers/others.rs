use axum::{
    Router,
    routing::{
        get,
        post,
        put,
    },
};

use crate::api::{
    AppState,
    controller::{
        domains,
        import,
        meta,
    },
};

pub fn others_router() -> Router<AppState> {
    Router::new()
        .route("/api/ciphers/import", post(import::import_data))
        // Meta
        .route("/api/now", get(meta::now))
        .route("/api/version", get(meta::version))
        .route("/api/hibp/breach", get(meta::hibp_breach))
        // Settings (stubbed)
        .route("/api/settings/domains", get(domains::get_domains))
        .route("/api/settings/domains", post(domains::post_domains))
        .route("/api/settings/domains", put(domains::put_domains))
}
