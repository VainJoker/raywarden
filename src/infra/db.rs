use worker::Result as WorkerResult;

use crate::errors::{
    AppError,
    DatabaseError,
};

/// Decode rows explicitly: a malformed stored row fails the entire read.
pub fn decode_results<T: serde::de::DeserializeOwned>(
    result: &worker::D1Result,
) -> Result<Vec<T>, AppError> {
    result
        .results::<serde_json::Value>()?
        .into_iter()
        .map(|row| serde_json::from_value(row).map_err(|_| AppError::Internal))
        .collect()
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
