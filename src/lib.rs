mod api;
mod app;
mod config;
mod errors;
mod infra;
mod models;
mod service;
mod utils;

pub use api::durable::{
    HeavyDo,
    NotifyDo,
};
use worker::{
    Context,
    Env,
    Request,
    Response,
    Result,
    ScheduleContext,
    ScheduledEvent,
    event,
};

#[event(fetch)]
pub async fn main(
    request: Request,
    env: Env,
    _context: Context,
) -> Result<Response> {
    infra::init(&env);
    api::handle_fetch(request, env).await
}

#[event(scheduled)]
pub async fn scheduled(
    _event: ScheduledEvent,
    env: Env,
    _context: ScheduleContext,
) {
    infra::init(&env);
    service::run_maintenance(&env).await;
}
