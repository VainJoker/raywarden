//! Server discovery, health, usage and compatibility endpoints.
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse as _, Response},
};
use serde::de::IgnoredAny;
use serde_json::json;

use crate::{
    api::{
        AppState,
        common::{
            json::Json,
            response::{ApiResponse, EmptyListResponse, NoStore},
        },
    },
    errors::AppResult,
    infra::config::{client_feature_flags, fill_assist_rules_url, release_id},
    models::health,
    service::{identity::session::Claims, web_vault_ui},
};

const SERVER_VERSION: &str = "2026.6.0";

/// Compatibility discovery for capabilities outside the personal-vault scope.
#[worker::send]
pub(in crate::api) async fn empty_personal_list(_claims: Claims) -> ApiResponse<EmptyListResponse> {
    ApiResponse(EmptyListResponse::new())
}

/// GET /api/now
///
/// Mirrors vaultwarden's `/api/now`: returns current UTC timestamp as an
/// RFC3339 string.
#[worker::send]
pub(in crate::api) async fn current_time() -> ApiResponse<String> {
    ApiResponse(crate::utils::time::now_rfc3339())
}

/// GET /api/alive
///
/// Simple healthcheck. Vaultwarden uses this to also verify DB connectivity.
#[worker::send]
pub(in crate::api) async fn health_check(
    State(state): State<Arc<AppState>>,
) -> AppResult<Response> {
    health::ping(state.database()).await?;
    let mut response = NoStore::private(current_time().await).into_response();
    if let Some(id) = release_id(&state.env)
        && let Ok(value) = HeaderValue::from_str(&id)
    {
        response
            .headers_mut()
            .insert("x-raywarden-release-id", value);
    }
    Ok(response)
}

/// GET /api/version
///
/// Returns a Bitwarden-server-like version string. Clients sometimes call this
/// endpoint.
#[worker::send]
pub(in crate::api) async fn server_version() -> ApiResponse<&'static str> {
    ApiResponse(SERVER_VERSION)
}

/// GET /emergency-access/trusted
///
/// Returns the list of trusted emergency access contacts (grantees) for the
/// current user. This is a stub implementation that always returns an empty
/// list since emergency access is not supported in this minimal
/// Bitwarden-compatible implementation.
///
/// In vaultwarden, when `emergency_access_allowed` is disabled, it returns an
/// empty list. We follow the same pattern here.
#[worker::send]
pub(in crate::api) async fn empty_emergency_contacts() -> ApiResponse<EmptyListResponse> {
    ApiResponse(EmptyListResponse::new())
}

#[worker::send]
pub(in crate::api) async fn accept_events(_claims: Claims, Json(_events): Json<Vec<IgnoredAny>>) {}

#[worker::send]
pub(in crate::api) async fn client_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> AppResult<axum::response::Response> {
    let registration_disabled = !state.setup_guard().registration_enabled(&headers).await?;
    let domain = state.domain();
    let mut features = client_feature_flags(&state.env);
    features.insert(
        "email-verification".into(),
        crate::service::identity::email::registration_verification_required(&state.env),
    );
    let response = ApiResponse(json!({
        // Clients use this version to select compatible server features.
        "version": SERVER_VERSION,
        "gitHash": option_env!("GIT_REV"),
        "server": {
            "name": "Vaultwarden",
            "url": "https://github.com/dani-garcia/vaultwarden",
        },
        "settings": {
            "disableUserRegistration": registration_disabled,
            "suppressOnboardingInterstitials": web_vault_ui::suppress_onboarding(&state.env),
        },
        "environment": {
            "vault": domain,
            "api": format!("{domain}/api"),
            "identity": format!("{domain}/identity"),
            "notifications": format!("{domain}/notifications"),
            "sso": "",
            "fillAssistRules": fill_assist_rules_url(&state.env),
            "cloudRegion": null,
        },
        "push": {"pushTechnology": 0, "vapidPublicKey": null},
        "featureStates": features,
        "communication": null,
        "object": "config",
    }));
    Ok(NoStore(response).into_response())
}
