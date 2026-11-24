pub(crate) mod bootstrap;
mod common;
mod controller;
mod edge;
pub(crate) mod middleware;
mod routers;

pub(crate) use edge::handle_fetch;
pub use edge::{heavydo, notifydo};
use worker::{D1Database, Env};

use crate::{infra::config::Config, service::identity::jwt_keys::JwtKeys};

/// Resources shared by handlers within one request.
struct AppState {
    env: Env,
    config: Config,
    jwt_keys: JwtKeys,
    database: D1Database,
}

impl AppState {
    const fn database(&self) -> &D1Database {
        &self.database
    }

    fn domain(&self) -> &str {
        &self.config.domain
    }
}
