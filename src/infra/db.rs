use worker::{
    D1Database,
    Env,
    Result as WorkerResult,
};

use crate::errors::{
    AppError,
    AppResult,
    DatabaseError,
};

const D1_BINDING: &str = "DB";

/// Resolve the application's D1 binding for the current Worker environment.
pub(crate) fn binding(env: &Env) -> WorkerResult<D1Database> {
    env.d1(D1_BINDING)
}

/// Decode rows explicitly: a malformed stored row fails the entire read.
pub fn decode_results<T: serde::de::DeserializeOwned>(
    result: &worker::D1Result,
) -> AppResult<Vec<T>> {
    result
        .results::<serde_json::Value>()?
        .into_iter()
        .map(|row| {
            serde_json::from_value(row).map_err(AppError::internal_error)
        })
        .collect()
}

pub async fn run_query<F, T>(query: F, context: &str) -> AppResult<T>
where
    F: Future<Output = WorkerResult<T>>,
{
    query
        .await
        .map_err(|error| DatabaseError::query(context, error))
}
