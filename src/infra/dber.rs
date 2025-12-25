use std::sync::Arc;

use worker::D1Database;

#[derive(Clone, Debug)]
pub struct DB {
    pub d1: Arc<D1Database>,
}

impl DB {
    pub fn new(env: &worker::Env) -> Self {
        let d1 = env.d1("warden-db").expect("Failed to get D1 database");
        Self { d1: Arc::new(d1) }
    }
}