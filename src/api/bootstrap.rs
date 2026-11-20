//! Assemble the application stack shared by the Worker and `HeavyDo`.
use axum::response::Response;
use tower_service::Service as _;
use worker::{
    Env,
    HttpRequest,
};

use super::{
    middleware::{
        cors::CorsPolicy,
        security_headers,
    },
    routers,
};
use crate::{
    app::AppContext,
    config::Config,
    errors::AppResult,
    infra::db,
    service::identity::jwt_keys,
};

pub(crate) async fn handle_request(
    request: HttpRequest,
    env: Env,
    cors: &CorsPolicy,
) -> AppResult<Response> {
    let path = request.uri().path().to_owned();
    let database = db::binding(&env)?;
    let config = Config::from_env(&env)?;
    let keys = jwt_keys::load(&env, &database).await?;
    let state =
        super::AppState::new(AppContext::new(env, config, keys, database));
    let mut app = routers::router().with_state(state).layer(cors.layer());
    let mut response = match app.call(request).await {
        Ok(response) => response,
        Err(infallible) => match infallible {},
    };
    security_headers::apply_http(&path, &mut response);
    Ok(response)
}
