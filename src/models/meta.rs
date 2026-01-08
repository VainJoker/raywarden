use log::error;
use worker::D1Database;

use crate::errors::{
    AppError,
    DatabaseError,
};

pub struct MetaDB;

impl MetaDB {
    /// Simple connectivity check: runs a trivial query to ensure the DB is
    /// reachable.
    pub async fn ping(db: &D1Database) -> Result<(), AppError> {
        db.prepare("SELECT 1 as ok")
            .first::<i32>(Some("ok"))
            .await
            .map_err(|err| {
                error!("Failed to verify database connectivity: {err}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to verify database connectivity".to_string(),
                ))
            })?;
        Ok(())
    }
}
