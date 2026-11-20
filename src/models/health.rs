use worker::D1Database;

use crate::errors::{
    AppResult,
    DatabaseError,
};

/// Verify D1 connectivity without reading application tables.
pub(crate) async fn ping(db: &D1Database) -> AppResult<()> {
    db.prepare("SELECT 1 as ok")
        .first::<i32>(Some("ok"))
        .await
        .map_err(|err| {
            DatabaseError::query("Failed to verify database connectivity", err)
        })?;
    Ok(())
}
