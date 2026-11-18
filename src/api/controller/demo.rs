//! Opt-in same-origin self-test page; its API calls retain ordinary
//! authorization.
use axum::{
    extract::State,
    http::{
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

use crate::{
    api::AppState,
    infra::config::env_bool,
};

#[worker::send]
pub async fn page(State(state): State<AppState>) -> Response {
    let mut response = if env_bool(&state.env, "DEMO_PAGE_ENABLED", false) {
        Html(include_str!("../../../static/demo.html")).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src \
             'self' 'unsafe-inline'; img-src 'self' data:; connect-src \
             'self'; frame-ancestors 'self'; form-action 'self'; base-uri \
             'self'; object-src 'none'",
        ),
    );
    response
}
