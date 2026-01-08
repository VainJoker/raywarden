#![feature(once_cell_try)]

pub mod api;
pub mod errors;
pub mod infra;
pub mod models;
pub mod utils;

use std::sync::OnceLock;

use axum::{
    body::Body,
    response::Response,
};
use log::Level;
use worker::*;

use crate::api::ApiService;

/// Initialize panic hook and logger (once per Worker instance).
pub static INIT: OnceLock<()> = OnceLock::new();

fn init() {
    INIT.get_or_init(|| {
        console_error_panic_hook::set_once();
        let _ = console_log::init_with_level(Level::Info);
    });
}

#[event(fetch)]
pub async fn main(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<Response<Body>> {
    init();
    ApiService::run(req, env).await.map_err(|e| {
        log::error!("API service error: {e:?}");
        e.into()
    })
}
