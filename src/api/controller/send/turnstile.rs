//! Send human-verification HTTP handlers and responses.
use axum::{
    Json,
    extract::{
        Query,
        State,
    },
    http::{
        HeaderMap,
        HeaderValue,
        header,
    },
    response::{
        IntoResponse,
        Response,
    },
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    api::{
        AppState,
        common::response::ApiResponse,
    },
    errors::{
        AppError,
        AppResult,
    },
    service::send::turnstile,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct VerifyTurnstileRequest {
    token:   String,
    #[serde(default)]
    send_id: String,
}

#[derive(Serialize)]
struct VerifyTurnstileResponse<'a> {
    ok:    bool,
    token: &'a str,
}

#[derive(Serialize)]
struct TurnstileStatusResponse {
    enabled: bool,
    valid:   bool,
}

#[worker::send]
pub(in crate::api) async fn send_verify_page(
    State(state): State<AppState>,
) -> AppResult<Response> {
    let site = turnstile::configured_site_key(&state)?;
    let html = include_str!("../../../../static/turnstile-verify.html")
        .replace("__RAYWARDEN_TURNSTILE_SITE_KEY__", &site);
    Ok(([(header::CONTENT_TYPE,"text/html; charset=utf-8"),
        (header::CACHE_CONTROL,"private, no-store"),
        (header::REFERRER_POLICY,"no-referrer"),
        (header::CONTENT_SECURITY_POLICY,"default-src 'none'; script-src 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")],html).into_response())
}

#[worker::send]
pub(in crate::api) async fn verify_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyTurnstileRequest>,
) -> AppResult<Response> {
    let token = turnstile::issue_send_access(
        &state,
        &headers,
        &payload.token,
        &payload.send_id,
    )
    .await?;
    let mut response = ApiResponse(VerifyTurnstileResponse {
        ok:    true,
        token: &token,
    })
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    let cookie = format!(
        "cf_send_pass={token}; Path=/; HttpOnly; Secure; SameSite=Lax; \
         Max-Age=300"
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(AppError::internal_error)?,
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "cf_send_pass_ok=1; Path=/; Secure; SameSite=Lax; Max-Age=300",
        ),
    );
    Ok(response)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct StatusQuery {
    #[serde(default)]
    send_id: String,
}

#[worker::send]
pub(in crate::api) async fn send_verify_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> Response {
    let enabled = turnstile::enabled(&state);
    let valid =
        turnstile::verify_send_access(&state, &headers, &query.send_id).is_ok();
    (
        [(header::CACHE_CONTROL, "private, no-store")],
        ApiResponse(TurnstileStatusResponse { enabled, valid }),
    )
        .into_response()
}
