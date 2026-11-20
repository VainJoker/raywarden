//! Durable file-deletion jobs and guarded D1 outbox operations.
use serde::{
    Deserialize,
    Serialize,
};
use worker::D1Database;

use crate::errors::{
    AppError,
    AppResult,
};

#[derive(Deserialize, Serialize)]
struct CleanupJobRow {
    pub object_key: String,
    pub generation: String,
}

pub struct CleanupBatch<'a> {
    db:   &'a D1Database,
    jobs: Vec<CleanupJobRow>,
}

pub async fn enqueue_if_unreferenced(
    db: &D1Database,
    key: &str,
    now: &str,
) -> AppResult<bool> {
    let result = db
        .prepare(
            "INSERT INTO storage_cleanup_jobs(object_key, created_at) SELECT \
             ?1, ?2 WHERE NOT EXISTS (SELECT 1 FROM attachments WHERE \
             COALESCE(storage_key, cipher_id || '/' || id) = ?1) AND NOT \
             EXISTS (SELECT 1 FROM sends WHERE file_id IS NOT NULL AND \
             COALESCE(storage_key, 'sends/' || id || '/' || file_id) = ?1) ON \
             CONFLICT(object_key) DO UPDATE SET \
             created_at=excluded.created_at, generation=excluded.generation",
        )
        .bind(&[key.into(), now.into()])?
        .run()
        .await?;
    Ok(result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 1)
}

pub async fn pending_batch(db: &D1Database) -> AppResult<CleanupBatch<'_>> {
    let jobs = db
        .prepare(
            "SELECT object_key, generation FROM storage_cleanup_jobs jobs \
             WHERE NOT EXISTS (SELECT 1 FROM attachments WHERE \
             COALESCE(storage_key, cipher_id || '/' || id) = jobs.object_key) \
             AND NOT EXISTS (SELECT 1 FROM sends WHERE file_id IS NOT NULL \
             AND COALESCE(storage_key, 'sends/' || id || '/' || file_id) = \
             jobs.object_key) ORDER BY created_at, object_key LIMIT 128",
        )
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
        let result = self
            .db
            .prepare(
                "DELETE FROM storage_cleanup_jobs WHERE (object_key, \
                 generation) IN (SELECT json_extract(value, '$.object_key'), \
                 json_extract(value, '$.generation') FROM json_each(?1))",
            )
            .bind(&[serde_json::to_string(&self.jobs)
                .map_err(AppError::internal_error)?
                .into()])?
            .run()
            .await?;
        Ok(result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) as u32)
    }
}
