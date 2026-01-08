use axum::{
    Json,
    extract::State,
};
use chrono::{
    SecondsFormat,
    Utc,
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};

use crate::{
    api::AppState,
    errors::AppError,
    models::meta::MetaDB,
};

/// GET /api/now
///
/// Mirrors vaultwarden's `/api/now`: returns current UTC timestamp as an
/// RFC3339 string.
#[worker::send]
pub async fn now() -> Json<String> {
    Json(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// GET /api/alive
///
/// Simple healthcheck. Vaultwarden uses this to also verify DB connectivity.
#[worker::send]
pub async fn alive(
    State(state): State<AppState>,
) -> Result<Json<String>, AppError> {
    // Verify D1 binding is present + basic query works.
    let db = state.get_db();
    MetaDB::ping(&db).await?;
    Ok(now().await)
}

/// GET /api/version
///
/// Returns a Bitwarden-server-like version string. Clients sometimes call this
/// endpoint.
#[worker::send]
pub async fn version() -> Json<&'static str> {
    // Keep this in sync with `src/handlers/config.rs`'s `version`.
    Json("2025.12.0")
}

#[derive(Debug, Deserialize)]
pub struct HibpBreachQuery {
    #[allow(dead_code)] // stub endpoint doesn't use it yet
    pub username: String,
}

/// GET /api/hibp/breach?username=...
///
/// Vaultwarden can proxy `HaveIBeenPwned` if configured. This minimal server
/// doesn't. We return an empty array to indicate "no breach data" without
/// surfacing an error in clients.
#[worker::send]
pub async fn hibp_breach(
    _query: axum::extract::Query<HibpBreachQuery>,
) -> Json<Value> {
    Json(json!([]))
}
