pub mod api;
mod dispatch;
pub mod durable;
pub mod errors;
pub mod infra;
pub mod models;
pub mod send;

use std::sync::OnceLock;

use axum::response::IntoResponse as _;
use worker::*;

use crate::api::handle_request;

/// Initialize panic hook and logger (once per Worker instance).
static INIT: OnceLock<()> = OnceLock::new();

pub(crate) fn init(env: &Env) {
    INIT.get_or_init(|| {
        console_error_panic_hook::set_once();
        infra::logging::init(env);
    });
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    init(&env);
    let cors = dispatch::CorsContext::new(&req, &env);
    let result: errors::AppResult<Response> = async {
        match dispatch::route(req, &env, &cors).await? {
            dispatch::DispatchResult::Handled(response) => Ok(response),
            dispatch::DispatchResult::Continue(request) => {
                let request: HttpRequest = request.try_into()?;
                let response = handle_request(request, env).await?;
                Ok(infra::storage::into_worker_response(response)?)
            }
        }
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            let response: Response = error.into_response().try_into()?;
            cors.apply(response).map_err(Into::into)
        }
    }
}

#[event(scheduled)]
pub async fn scheduled(
    _event: ScheduledEvent,
    env: Env,
    _ctx: ScheduleContext,
) {
    init(&env);
    api::service::maintenance::run_scheduled(&env).await;
}
