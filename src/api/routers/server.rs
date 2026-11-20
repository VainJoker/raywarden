use axum::{
    Router,
    routing::{
        get,
        post,
    },
};

use crate::api::{
    AppState,
    controller::{
        client_assets,
        server,
        sync,
    },
};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/sync", get(sync::sync_vault))
        .route("/api/config", get(server::client_config))
        .route("/api/now", get(server::current_time))
        .route("/api/version", get(server::server_version))
        .route("/api/alive", get(server::health_check))
        .route("/alive", get(server::health_check))
        .route("/api/collections", get(server::empty_personal_list))
        .route("/api/organizations", get(server::empty_personal_list))
        .route("/api/policies", get(server::empty_personal_list))
        .route(
            "/api/emergency-access/trusted",
            get(server::empty_emergency_contacts),
        )
        .route(
            "/api/emergency-access/granted",
            get(server::empty_emergency_contacts),
        )
        .route("/events/collect", post(server::accept_events))
        .route("/api/events/collect", post(server::accept_events))
        .route("/icons/{*path}", get(client_assets::icon))
        .route("/css/vaultwarden.css", get(client_assets::stylesheet))
        .route("/js/raywarden.js", get(client_assets::client_script))
        .route("/demo.html", get(client_assets::demo_page))
        .route(
            "/.well-known/apple-app-site-association",
            get(client_assets::apple_app_site_association),
        )
}
