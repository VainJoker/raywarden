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
        demo,
        domains,
        emergency,
        import,
        meta,
        setup,
        sync,
    },
};

pub fn others_router() -> Router<AppState> {
    Router::new()
        .route("/setup", get(setup::page))
        .route("/api/accounts/setup", post(setup::authorize))
        .route("/demo.html", get(demo::page))
        .route("/api/config", get(config::config))
        .route("/api/sync", get(sync::get_sync_data))
        .route("/api/ciphers/import", post(import::import_data))
        // Meta
        .route("/api/now", get(meta::now))
        .route("/api/version", get(meta::version))
        .route("/api/hibp/breach", get(meta::hibp_breach))
        .route("/api/alive", get(meta::alive))
        .route("/alive", get(meta::alive))
        .route("/api/collections", get(meta::empty_personal_list))
        .route("/api/organizations", get(meta::empty_personal_list))
        .route("/api/policies", get(meta::empty_personal_list))
        // Domain settings
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
}
