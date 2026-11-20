//! Equivalent-domain settings HTTP handlers.
use axum::{
    Json,
    extract::State,
};

use crate::{
    api::{
        AppState,
        common::response::{
            ApiResponse,
            EmptyObject,
            RawJson,
        },
    },
    errors::AppResult,
    service::{
        identity::session::Claims,
        vault::domains::UpdateDomainsRequest,
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
    State(state): State<AppState>,
) -> AppResult<RawJson> {
    Ok(RawJson(
        crate::service::vault::domains::settings(&state, &claims).await?,
    ))
}

/// POST /api/settings/domains
///
/// Commit personal settings and publish their settings-specific revision.
#[worker::send]
pub(in crate::api) async fn update_domains(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<UpdateDomainsRequest>,
) -> AppResult<ApiResponse<EmptyObject>> {
    crate::service::vault::domains::update_settings(&state, &claims, payload)
        .await?;
    Ok(ApiResponse(EmptyObject {}))
}
