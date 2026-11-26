//! Assemble the application stack shared by the Worker and `heavydo`.
use std::sync::Arc;

use axum::{
    http::Method,
    response::{IntoResponse as _, Response},
};
use tower_service::Service as _;
use worker::{Env, HttpRequest};

use super::{
    AppState,
    middleware::{
        cors::{CorsContext, CorsPolicy},
        headers,
    },
    routers,
};
use crate::{
    errors::{AppError, AppResult, extract_ray_id_from_headers, finalize_error_response},
    infra::{config::Config, db},
    service::identity::jwt_keys,
};

pub(crate) async fn handle_request(
    request: HttpRequest,
    env: Env,
    cors: &CorsPolicy,
) -> AppResult<Response> {
    let head = request.method() == Method::HEAD;
    let path = request.uri().path().to_owned();
    let ray_id = extract_ray_id_from_headers(request.headers());
    let router = if let Some(public) = routers::public_router(&path) {
        public.with_state(env)
    } else {
        let database = db::binding(&env)?;
        let config = Config::from_env(&env)?;
        let jwt_keys = jwt_keys::load(&env, &database).await?;
        routers::router().with_state(Arc::new(AppState {
            env,
            config,
            jwt_keys,
            database,
        }))
    };
    let mut app = router.layer(cors.layer());
    let mut response = match app.call(request).await {
        Ok(response) => response,
        Err(infallible) => match infallible {},
    };
    finalize_error_response(&mut response, ray_id.as_deref(), head);
    headers::apply_http(&path, &mut response);
    Ok(response)
}

/// Render an application error that occurred before Axum applied CORS.
pub(super) fn worker_error_response(
    error: AppError,
    cors: &CorsContext,
    ray_id: Option<&str>,
    head: bool,
) -> worker::Result<worker::Response> {
    let mut response = error.into_response();
    finalize_error_response(&mut response, ray_id, head);
    let response = response.try_into()?;
    Ok(cors.apply(response)?)
}
