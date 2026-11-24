use worker::D1Database;

use crate::{errors::AppResult, infra::db};

/// Verify D1 connectivity without reading application tables.
pub(crate) async fn ping(db: &D1Database) -> AppResult<()> {
    db::query_first::<i32>(
        db.prepare("SELECT 1 as ok"),
        Some("ok"),
        "Failed to verify database connectivity",
    )
    .await?;
    Ok(())
}
