use std::sync::Arc;

use worker::{
    D1Database,
    Env,
};

use crate::{
    errors::AppResult,
    infra::config::Config,
};

/// Bindings and configuration shared within one request, never across requests.
#[derive(Clone)]
pub struct AppState {
    pub env:    Env,
    pub config: Arc<Config>,
    db:         Arc<D1Database>,
}

impl AppState {
    pub async fn from_env(env: Env) -> AppResult<Self> {
        let config = Arc::new(Config::from_env(&env).await?);
        let db = Arc::new(env.d1("warden-db")?);
        Ok(Self { env, config, db })
    }

    pub fn get_db(&self) -> Arc<D1Database> {
        self.db.clone()
    }

    pub fn get_domain(&self) -> &str {
        &self.config.domain
    }
}
