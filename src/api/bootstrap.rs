//! Assemble the application stack shared by the Worker and `heavydo`.
use std::sync::Arc;

use axum::response::{IntoResponse as _, Response};
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
    errors::{AppError, AppResult},
    infra::{config::Config, db},
    service::identity::jwt_keys,
};

pub(crate) async fn handle_request(
    request: HttpRequest,
    env: Env,
    cors: &CorsPolicy,
) -> AppResult<Response> {
    let path = request.uri().path().to_owned();
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
    headers::apply_http(&path, &mut response);
    Ok(response)
}

/// Render an application error that occurred before Axum applied CORS.
pub(super) fn worker_error_response(
    error: AppError,
    cors: &CorsContext,
) -> worker::Result<worker::Response> {
    let response = error.into_response().try_into()?;
    Ok(cors.apply(response)?)
}
