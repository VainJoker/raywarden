pub mod controller;
pub(crate) mod response;
pub mod routers;
pub mod service;
mod state;

use axum::response::Response;
pub use response::RawJson;
pub use state::AppState;
use tower_service::Service as _;
use worker::{
    Env,
    HttpRequest,
};

use crate::errors::AppResult;

/// Execute the same application stack for ordinary Worker and `HeavyDo`
/// requests.
pub async fn handle_request(req: HttpRequest, env: Env) -> AppResult<Response> {
    let state = AppState::from_env(env.clone()).await?;
    let config = state.config.clone();
    let mutation = service::mutation::Mutation::from_request(&req, &config);
    let mut app = routers::api_router(state).layer(config.cors.layer());
    let response = match app.call(req).await {
        Ok(response) => response,
        Err(infallible) => match infallible {},
    };

    if response.status().is_success() &&
        let Some(mutation) = mutation
    {
        mutation.publish(&env).await;
    }
    Ok(response)
}
