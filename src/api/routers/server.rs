//! Client configuration, compatibility responses and web assets.
use std::sync::{Arc, OnceLock};

use axum::{
    Router,
    routing::{get, post},
};
use worker::Env;

use crate::api::{
    AppState,
    controller::{client_assets, server, sync},
};

pub(super) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/sync", get(sync::sync_vault))
        .route("/api/config", get(server::client_config))
        .route("/api/alive", get(server::health_check))
        .route("/alive", get(server::health_check))
        .route("/events/collect", post(server::accept_events))
        .route("/api/events/collect", post(server::accept_events))
        // Personal-vault clients expect these collection endpoints to exist.
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
}

macro_rules! public_routes {
    ($($path:literal => $handler:path),+ $(,)?) => {
        pub(in crate::api) fn public_router(path: &str) -> Option<Router<Env>> {
            static PUBLIC: OnceLock<Router<Env>> = OnceLock::new();
            if !matches!(path, $($path)|+) && !path.strip_prefix("/icons/").is_some_and(|path| !path.is_empty()) {
                return None;
            }
            Some(PUBLIC.get_or_init(|| {
                Router::new()
                    $(.route($path, get($handler)))+
                    .route("/icons/{*path}", get(client_assets::icon))
            }).clone())
        }
    };
}

public_routes! {
    "/api/now" => server::current_time,
    "/api/version" => server::server_version,
    "/css/vaultwarden.css" => client_assets::stylesheet,
    "/js/raywarden.js" => client_assets::client_script,
    "/.well-known/apple-app-site-association" => client_assets::apple_app_site_association,
}
