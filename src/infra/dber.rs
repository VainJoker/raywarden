use std::sync::Arc;

use worker::{
    D1Database,
    Result as WorkerResult,
};

use crate::errors::{
    AppError,
    DatabaseError,
};

#[derive(Clone, Debug)]
pub struct DB {
    pub d1: Arc<D1Database>,
}

impl DB {
    pub fn new(env: &worker::Env) -> Self {
        let d1 = env.d1("warden-db").expect("Failed to get D1 database");
        Self { d1: Arc::new(d1) }
    }

    pub async fn run_query<Fut, T>(exec: Fut, msg: &str) -> Result<T, AppError>
    where
        Fut: Future<Output = WorkerResult<T>>,
    {
        exec.await.map_err(|e| {
            log::error!("{msg}: {e}");
            AppError::Database(DatabaseError::QueryFailed(msg.to_string()))
        })
    }
}
