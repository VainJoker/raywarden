//! Application resources shared by handlers and services during one request.
use worker::{
    D1Database,
    Env,
};

use crate::config::Config;

/// Bindings and configuration shared within one request, never across requests.
pub(crate) struct AppContext {
    pub env:             Env,
    pub(crate) config:   Config,
    pub(crate) jwt_keys: JwtKeys,
    database:            D1Database,
}

impl AppContext {
    pub(crate) const fn new(
        env: Env,
        config: Config,
        jwt_keys: JwtKeys,
        database: D1Database,
    ) -> Self {
        Self {
            env,
            config,
            jwt_keys,
            database,
        }
    }

    pub(crate) const fn database(&self) -> &D1Database {
        &self.database
    }

    pub(crate) fn domain(&self) -> &str {
        &self.config.domain
    }
}

pub(crate) struct JwtKeys {
    pub access_secret:  String,
    pub refresh_secret: String,
}
