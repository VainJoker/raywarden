use axum::{
    Json,
    extract::State,
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

pub const SERVER_VERSION: &str = "2026.6.0";

/// Compatibility discovery for capabilities outside the personal-vault scope.
#[worker::send]
pub async fn empty_personal_list(
    _claims: crate::api::service::claims::Claims,
) -> Json<Value> {
    Json(json!({"data": [], "object": "list", "continuationToken": null}))
}

/// GET /api/now
///
/// Mirrors vaultwarden's `/api/now`: returns current UTC timestamp as an
/// RFC3339 string.
#[worker::send]
pub async fn now() -> Json<String> {
    Json(crate::infra::time::now_rfc3339())
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
    Json(SERVER_VERSION)
}

#[derive(Debug, Deserialize)]
pub struct HibpBreachQuery {
    #[allow(dead_code)] // stub endpoint doesn't use it yet
    pub username: String,
}

/// Proxy HIBP only when configured; no fabricated breach records.
#[worker::send]
pub async fn hibp_breach(
    claims: crate::api::service::claims::Claims,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<HibpBreachQuery>,
) -> Result<Json<Value>, AppError> {
    crate::api::service::rate::check_rate_limit(
        &state,
        format!("hibp:{}", claims.sub),
    )
    .await?;
    let secret = crate::infra::config::env_text(&state.env, "HIBP_API_KEY")
        .ok_or_else(|| {
            AppError::bad_request("HIBP_API_KEY is not configured")
        })?;
    let mut url =
        url::Url::parse("https://haveibeenpwned.com/api/v3/breachedaccount/")
            .map_err(|_| AppError::Internal)?;
    url.path_segments_mut()
        .map_err(|_| AppError::Internal)?
        .push(&query.username);
    url.set_query(Some("truncateResponse=false&includeUnverified=false"));
    let mut request = worker::Request::new(url.as_str(), worker::Method::Get)?;
    request.headers_mut()?.set("hibp-api-key", &secret)?;
    request.headers_mut()?.set("user-agent", "raywarden")?;
    let mut response = worker::Fetch::Request(request).send().await?;
    if response.status_code() == 404 {
        return Ok(Json(json!([])));
    }
    if response.status_code() != 200 {
        return Err(AppError::bad_request("HIBP service is unavailable"));
    }
    Ok(Json(response.json().await?))
}
