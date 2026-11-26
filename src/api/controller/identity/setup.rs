use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        AppState,
        common::{
            extract::ClientIp,
            json::Json,
            response::{ApiResponse, NoStore, WithCookies},
        },
    },
    errors::{AppError, AppResult},
    service::{identity::setup, rate_limit},
};

#[derive(Deserialize)]
pub(in crate::api) struct SetupRequest {
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerSetupResponse {
    object: &'static str,
    expires_in: i64,
}

fn private_response(response: impl IntoResponse) -> Response {
    let mut response = NoStore(response).into_response();
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src \
             'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; \
             form-action 'self'; base-uri 'none'; object-src 'none'",
        ),
    );
    response
}

#[worker::send]
pub(in crate::api) async fn page() -> AppResult<Response> {
    Ok(private_response(Html(include_str!(
        "../../../../static/setup.html"
    ))))
}

#[worker::send]
pub(in crate::api) async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ClientIp(ip): ClientIp,
    Json(payload): Json<SetupRequest>,
) -> AppResult<Response> {
    rate_limit::check_auth_attempt(&state.env, format!("owner-setup:{ip}")).await?;
    let cookie = state
        .setup_guard()
        .issue_cookie(&headers, &payload.token)
        .await?;
    Ok(private_response(WithCookies {
        response: ApiResponse(OwnerSetupResponse {
            object: "ownerSetup",
            expires_in: setup::TTL_SECONDS,
        }),
        cookies: vec![
            HeaderValue::from_str(&cookie)
                .map_err(|error| AppError::internal_debug("Failed to build setup cookie", error))?,
        ],
    }))
}

impl AppState {
    pub(in crate::api) fn setup_guard(&self) -> setup::SetupGuard<'_> {
        setup::SetupGuard {
            db: self.database(),
            env: &self.env,
            config: &self.config,
            access_secret: &self.jwt_keys.access_secret,
        }
    }
}
