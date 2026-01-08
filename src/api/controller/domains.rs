use axum::{
    Json,
    extract::State,
};
use chrono::Utc;
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::AppError,
    models::domains::{
        DomainsDB,
        EquivDomainData,
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
/// This server persists only the per-user settings in `users`.
/// The optional global dataset can be seeded into D1 (see README), and will
/// then be included in responses without parsing the large JSON in the Worker.
#[worker::send]
pub async fn get_domains(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    let domains = DomainsDB::fetch_by_user_id(&db, &claims.sub).await?;
    let equivalent_domains = domains.equivalent_domains;
    let excluded_globals = domains.excluded_globals;

    // Include ALL global groups and mark `excluded` (settings UI semantics).
    // Falls back to [] if the dataset isn't seeded yet.
    let global_equivalent_domains =
        EquivDomainData::global_equivalent_domains_json(
            &db,
            &excluded_globals,
            true,
        )
        .await;

    let response = format!(
        r#"{{"equivalentDomains":{equivalent_domains},"globalEquivalentDomains":{global_equivalent_domains},"object":"domains"}}"#
    );
    Ok(Json(json!(response)))
}

/// POST /api/settings/domains
///
/// Persist per-user `eq_domains` settings (no notifications/push).
#[worker::send]
pub async fn post_domains(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<EquivDomainData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    let excluded_globals = payload
        .excluded_global_equivalent_domains
        .unwrap_or_default();
    let equivalent_domains = payload.equivalent_domains.unwrap_or_default();

    let excluded_globals_json = serde_json::to_string(&excluded_globals)
        .map_err(|err| {
            log::warn!("Failed to serialize excluded globals: {err}");
            AppError::Params("Invalid excluded globals".to_string())
        })?;
    let equivalent_domains_json = serde_json::to_string(&equivalent_domains)
        .map_err(|err| {
            log::warn!("Failed to serialize equivalent domains: {err}");
            AppError::Params("Invalid equivalent domains".to_string())
        })?;

    let now = Utc::now().to_rfc3339();
    DomainsDB::update_for_user(
        &db,
        &claims.sub,
        &equivalent_domains_json,
        &excluded_globals_json,
        &now,
    )
    .await?;

    Ok(Json(json!({})))
}

/// PUT /api/settings/domains
///
/// Behaves like POST.
#[worker::send]
pub async fn put_domains(
    claims: Claims,
    State(state): State<AppState>,
    payload: Json<EquivDomainData>,
) -> Result<Json<Value>, AppError> {
    post_domains(claims, State(state), payload).await
}
