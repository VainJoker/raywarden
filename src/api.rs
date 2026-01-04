pub mod controller;
pub mod middleware;
pub mod routers;
pub mod service;

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    http::StatusCode,
    response::{
        IntoResponse,
        Response,
    },
};
use bizerror::BizError;
use serde::{
    Deserialize,
    Serialize,
};
use tower_service::Service as _;
use worker::{
    Env,
    HttpRequest,
};

use crate::{
    api::{
        middleware::cors_layer,
        routers::api_router,
    },
    errors::{
        AppError,
        AppResult,
        HttpStatusMapping as _,
    },
    infra::{
        DB,
        cfg::{
            Config,
            load_config,
        },
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

        let response = app.call(req).await.expect("Infallible router error");

        Ok(response)
    }
}

/// API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub data: Option<T>,
    pub msg:  Option<String>,
    pub code: u32,
}

impl<T> ApiResponse<T>
where
    T: Serialize,
{
    /// Create a successful response
    pub const fn success(data: T) -> Self {
        Self {
            data: Some(data),
            msg:  None,
            code: 0,
        }
    }

    /// Create a successful response with custom message
    pub fn success_with_message(data: T, msg: impl Into<String>) -> Self {
        Self {
            data: Some(data),
            msg:  Some(msg.into()),
            code: 0,
        }
    }

    /// Create an error response
    pub fn error(code: u32, msg: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            data: None,
            msg: Some(msg.into()),
            code,
        }
    }

    /// Create an error response with data
    pub fn error_with_data(code: u32, msg: impl Into<String>, data: T) -> Self {
        Self {
            data: Some(data),
            msg: Some(msg.into()),
            code,
        }
    }
}

impl<T> IntoResponse for ApiResponse<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {}", self);

        let status_code = self.http_status_code();
        let error_code = self.code();
        let message = self.to_string();

        let response = ApiResponse::<()>::error(error_code, message);
        (status_code, Json(response)).into_response()
    }
}

/// Helper functions for common response patterns
impl ApiResponse<()> {
    /// Create a successful response with no data
    pub fn ok() -> Self {
        Self {
            data: None,
            msg:  Some("OK".to_string()),
            code: 200,
        }
    }

    /// Create a successful response with message
    pub fn ok_with_message(msg: impl Into<String>) -> Self {
        Self {
            data: None,
            msg:  Some(msg.into()),
            code: 200,
        }
    }
}
