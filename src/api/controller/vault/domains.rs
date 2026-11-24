//! Equivalent-domain settings HTTP handlers.
use std::sync::Arc;

use axum::extract::State;

use crate::{
    api::{
        AppState,
        common::{
            json::Json,
            response::{ApiResponse, EmptyObject},
        },
    },
    errors::AppResult,
    service::{
        identity::session::Claims,
        vault::domains::{DomainsResponse, UpdateDomainsRequest},
    },
};

/// GET /api/settings/domains
///
/// Equivalent domains (`eq_domains`) are used by clients to treat some domains
/// as interchangeable for URI matching (e.g. `google.com` vs `youtube.com` in
/// predefined "global" groups).
///
/// Vaultwarden persists per-user:
/// - `equivalentDomains`: custom groups set by the user
/// - `excludedGlobalEquivalentDomains`: which predefined groups are disabled
///
/// Per-user settings live in `users`. Global groups are fetched from
/// Vaultwarden upstream when due and cached in D1; responses are built in SQL.
#[worker::send]
pub(in crate::api) async fn get_domains(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<ApiResponse<DomainsResponse>> {
    Ok(ApiResponse(
        crate::service::vault::domains::settings(state.database(), &claims.sub).await?,
    ))
}

/// POST /api/settings/domains
///
/// Commit personal settings and publish their settings-specific revision.
#[worker::send]
pub(in crate::api) async fn update_domains(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateDomainsRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    crate::service::vault::domains::update_settings(state.database(), &state.env, &claims, payload)
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}
