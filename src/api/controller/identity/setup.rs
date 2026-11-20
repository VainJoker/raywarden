use axum::{
    Json,
    extract::State,
    http::{
        HeaderMap,
        HeaderValue,
        header,
    },
    response::{
        Html,
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
    service::{
        identity::setup,
        rate_limit,
    },
};

#[derive(Deserialize)]
pub(in crate::api) struct SetupRequest {
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerSetupResponse {
    object:     &'static str,
    expires_in: i64,
}

fn private_response(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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
    Ok(private_response(
        Html(include_str!("../../../../static/setup.html")).into_response(),
    ))
}

#[worker::send]
pub(in crate::api) async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SetupRequest>,
) -> AppResult<Response> {
    rate_limit::check_auth_attempt(
        &state,
        format!("owner-setup:{}", rate_limit::client_ip(&headers)),
    )
    .await?;
    let cookie = setup::issue_cookie(&state, &headers, &payload.token).await?;
    let mut response = ApiResponse(OwnerSetupResponse {
        object:     "ownerSetup",
        expires_in: setup::TTL_SECONDS,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(AppError::internal_error)?,
    );
    Ok(private_response(response))
}
