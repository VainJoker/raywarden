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
        config,
        domains,
        emergency,
        import,
        meta,
        sync,
        webauth,
    },
};

pub fn others_router() -> Router<AppState> {
    Router::new()
        .route("/api/config", get(config::config))
        .route("/api/sync", get(sync::get_sync_data))
        .route("/api/ciphers/import", post(import::import_data))
        // Meta
        .route("/api/now", get(meta::now))
        .route("/api/version", get(meta::version))
        .route("/api/hibp/breach", get(meta::hibp_breach))
        // Settings (stubbed)
        .route("/api/settings/domains", get(domains::get_domains))
        .route("/api/settings/domains", post(domains::post_domains))
        .route("/api/settings/domains", put(domains::put_domains))
        .route(
            "/api/emergency-access/trusted",
            get(emergency::get_trusted_contacts),
        )
        .route(
            "/api/emergency-access/granted",
            get(emergency::get_granted_access),
        )
        .route("/api/webauthn", get(webauth::get_webauthn_credentials))
}
