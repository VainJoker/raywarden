use axum::{
    Json,
    extract::State,
    http::{
        HeaderMap,
        HeaderValue,
        StatusCode,
        header,
    },
    response::{
        Html,
        IntoResponse,
        Response,
    },
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    api::{
        AppState,
        service::{
            rate,
            setup,
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    models::user::UserDB,
};

#[derive(Deserialize)]
pub struct SetupRequest {
    token: String,
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
pub async fn page(State(state): State<AppState>) -> AppResult<Response> {
    let response = if UserDB::exists_any(&state.get_db()).await? {
        (
            StatusCode::CONFLICT,
            "Owner initialization is complete. Return to the Web Vault to log \
             in.",
        )
            .into_response()
    } else {
        Html(include_str!("../../../static/setup.html")).into_response()
    };
    Ok(private_response(response))
}

#[worker::send]
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SetupRequest>,
) -> AppResult<Response> {
    rate::check_rate_limit(
        &state,
        format!("owner-setup:{}", rate::client_ip(&headers)),
    )
    .await?;
    let cookie = setup::issue_cookie(&state, &headers, &payload.token).await?;
    let mut response =
        Json(json!({"object":"ownerSetup", "expiresIn": setup::TTL_SECONDS}))
            .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_error| AppError::Internal)?,
    );
    Ok(private_response(response))
}
