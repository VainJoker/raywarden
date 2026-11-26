//! Durable file-deletion jobs and guarded D1 outbox operations.
use serde::{Deserialize, Serialize};
use worker::{D1Database, D1PreparedStatement};

use crate::{
    errors::{AppError, AppResult},
    infra::db,
    models::mutation,
};

#[derive(Deserialize, Serialize)]
struct CleanupJobRow {
    pub object_key: String,
    pub generation: String,
}

pub struct CleanupBatch<'a> {
    db: &'a D1Database,
    jobs: Vec<CleanupJobRow>,
}

pub async fn register_stage(db: &D1Database, key: &str) -> AppResult<()> {
    db::query_run(
        db.prepare(
            "INSERT INTO storage_upload_stages(object_key, expires_at) VALUES \
             (?1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+1 day'))",
        )
        .bind(&db::d1_params![key]),
        "Failed to register staged file",
    )
    .await?;
    Ok(())
}

pub fn stage_guard(db: &D1Database, key: &str) -> AppResult<D1PreparedStatement> {
    mutation::guard(
        db,
        "EXISTS(SELECT 1 FROM storage_upload_stages WHERE object_key=?1 AND \
         julianday(expires_at)>julianday('now'))",
        &db::d1_params![key],
    )
}

pub fn remove_stage(db: &D1Database, key: &str) -> AppResult<D1PreparedStatement> {
    Ok(db
        .prepare("DELETE FROM storage_upload_stages WHERE object_key=?1")
        .bind(&db::d1_params![key])?)
}

pub async fn expire_stages(db: &D1Database) -> AppResult<()> {
    db::query_run(
        Ok(db.prepare(
            "DELETE FROM storage_upload_stages WHERE object_key IN (SELECT \
             object_key FROM storage_upload_stages WHERE \
             julianday(expires_at)<=julianday('now') ORDER BY \
             julianday(expires_at), object_key LIMIT 128)",
        )),
        "Failed to expire staged files",
    )
    .await?;
    Ok(())
}

fn unreferenced_sql(comparison: &str) -> String {
    format!(
        "NOT EXISTS (SELECT 1 FROM attachments WHERE \
         COALESCE(storage_key, cipher_id || '/' || id) {comparison}) AND NOT EXISTS (\
         SELECT 1 FROM sends WHERE file_id IS NOT NULL AND \
         COALESCE(storage_key, 'sends/' || id || '/' || file_id) {comparison})"
    )
}

pub async fn enqueue_if_unreferenced(db: &D1Database, key: &str, now: &str) -> AppResult<bool> {
    let removed = db::run_query(
        remove_stage(db, key)?.run(),
        "Failed to release staged file",
    )
    .await?;
    if db::changes_count(&removed)? == 1 {
        return Ok(true);
    }

    // Publication may have removed the stage before its acknowledgement was
    // lost. A late upload can also finish after its stage has expired.
    let result = db
        .prepare(format!(
            "INSERT INTO storage_cleanup_jobs(object_key, created_at) SELECT ?1, ?2 WHERE {} \
             ON CONFLICT(object_key) DO UPDATE SET \
             created_at=excluded.created_at, generation=excluded.generation",
            unreferenced_sql("= ?1")
        ))
        .bind(&db::d1_params![key, now])?
        .run()
        .await?;
    Ok(db::changes_count(&result)? == 1)
}

pub async fn pending_batch(db: &D1Database) -> AppResult<CleanupBatch<'_>> {
    // A single-value IN lets SQLite seek the expression indexes with an outer key.
    let jobs = db
        .prepare(format!(
            "SELECT object_key, generation FROM storage_cleanup_jobs jobs WHERE {} \
             ORDER BY created_at, object_key LIMIT 128",
            unreferenced_sql("IN (jobs.object_key)")
        ))
        .all()
        .await?
        .results::<CleanupJobRow>()?;
    Ok(CleanupBatch { db, jobs })
}

impl CleanupBatch<'_> {
    pub fn object_keys(&self) -> Vec<&str> {
        self.jobs
            .iter()
            .map(|job| job.object_key.as_str())
            .collect()
    }

    pub async fn acknowledge(self) -> AppResult<u32> {
        let jobs = serde_json::to_string(&self.jobs).map_err(AppError::internal_json(
            "Failed to serialize storage cleanup jobs",
        ))?;
        let result = self
            .db
            .prepare(
                "DELETE FROM storage_cleanup_jobs WHERE (object_key, \
                 generation) IN (SELECT json_extract(value, '$.object_key'), \
                 json_extract(value, '$.generation') FROM json_each(?1))",
            )
            .bind(&db::d1_params![jobs])?
            .run()
            .await?;
        Ok(db::changes_count(&result)? as u32)
    }
}
