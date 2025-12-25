pub mod api;
pub mod middleware;
pub mod routers;
pub mod service;

use std::sync::Arc;

use axum::{
    body::Body,
    response::Response,
};
use tower_service::Service as _;
use worker::{
    Env,
    HttpRequest,
};

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::{
        DB,
        cfg::{
            Config,
            load_config,
        },
    },
    warden::{
        middleware::cors_layer,
        routers::api_router,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub env:    Env,
    pub config: Config,
    pub db:     DB,
}

impl AppState {
    pub const fn new(config: Config, db: DB, env: Env) -> Self {
        Self { env, config, db }
    }

    pub fn get_db(&self) -> Arc<worker::D1Database> {
        self.db.d1.clone()
    }

    pub fn get_domain(&self) -> &str {
        &self.config.domain
    }
}

pub struct ApiService;

impl Default for ApiService {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiService {
    pub const fn new() -> Self {
        Self {}
    }

    pub async fn run(req: HttpRequest, env: Env) -> AppResult<Response<Body>> {
        let config = load_config(&env)?;
        let db = DB::new(&env);
        let state = AppState::new(config.clone(), db, env.clone());

        let mut app = api_router(state).layer(cors_layer(config));

        match app.call(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                log::error!("Router handler error: {e:?}");
                Err(AppError::Internal)
            }
        }
    }
}
