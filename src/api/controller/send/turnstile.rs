//! Send human-verification HTTP handlers and responses.
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        AppState,
        common::{
            json::Json,
            response::{ApiResponse, NoStore, WithCookies},
        },
    },
    errors::{AppError, AppResult},
    service::send::turnstile,
};

const VERIFY_PAGE_CSP: &str = concat!(
    "default-src 'none'; ",
    "script-src 'unsafe-inline' https://challenges.cloudflare.com; ",
    "frame-src https://challenges.cloudflare.com; ",
    "connect-src 'self' https://challenges.cloudflare.com; ",
    "style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyTurnstileRequest {
    token: String,
    #[serde(default)]
    send_id: String,
}

#[derive(Serialize)]
struct VerifyTurnstileResponse<'a> {
    ok: bool,
    token: &'a str,
}

#[derive(Serialize)]
struct TurnstileStatusResponse {
    enabled: bool,
    valid: bool,
}

#[worker::send]
pub(in crate::api) async fn send_verify_page(
    State(state): State<Arc<AppState>>,
) -> AppResult<Response> {
    let site = turnstile::configured_site_key(&state.env)?;
    let html = include_str!("../../../../static/turnstile-verify.html")
        .replace("__RAYWARDEN_TURNSTILE_SITE_KEY__", &site);
    let headers = [
        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CONTENT_SECURITY_POLICY, VERIFY_PAGE_CSP),
    ];
    Ok(NoStore::private((headers, html)).into_response())
}

#[worker::send]
pub(in crate::api) async fn verify_send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<VerifyTurnstileRequest>,
) -> AppResult<Response> {
    let verifier = turnstile::TurnstileVerifier {
        db: state.database(),
        env: &state.env,
        domain: state.domain(),
        access_secret: &state.jwt_keys.access_secret,
    };
    let token = verifier
        .issue_send_access(&headers, &payload.token, &payload.send_id)
        .await?;
    let cookie = format!(
        "cf_send_pass={token}; Path=/; HttpOnly; Secure; SameSite=Lax; \
         Max-Age=300"
    );
    let cookies = vec![
        HeaderValue::from_str(&cookie).map_err(AppError::internal_error)?,
        HeaderValue::from_static("cf_send_pass_ok=1; Path=/; Secure; SameSite=Lax; Max-Age=300"),
    ];
    Ok(NoStore::private(WithCookies {
        response: ApiResponse(VerifyTurnstileResponse {
            ok: true,
            token: &token,
        }),
        cookies,
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct StatusQuery {
    #[serde(default)]
    send_id: String,
}

#[worker::send]
pub(in crate::api) async fn send_verify_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> Response {
    let enabled = turnstile::enabled(&state.env);
    let valid = turnstile::verify_send_access(
        &state.env,
        &state.jwt_keys.access_secret,
        &headers,
        &query.send_id,
    )
    .is_ok();
    NoStore::private(ApiResponse(TurnstileStatusResponse { enabled, valid })).into_response()
}
