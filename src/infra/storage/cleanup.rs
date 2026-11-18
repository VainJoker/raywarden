//! Durable file-deletion outbox shared by R2 and the bounded KV fallback.
use serde::{
    Deserialize,
    Serialize,
};
use worker::{
    D1Database,
    Env,
};

use crate::{
    errors::AppResult,
    infra::storage::Storage,
};

#[derive(Deserialize, Serialize)]
struct CleanupJob {
    object_key: String,
    generation: String,
}

/// Retain bytes when a failed D1 response might hide a committed publication.
/// Uploaders use fresh keys, so an unreferenced failed attempt cannot replace
/// a previously committed object. Failed deletions remain discoverable.
pub async fn discard_staged_object(env: &Env, db: &D1Database, key: &str) {
    let queued = async {
        let result = db
            .prepare(
                "INSERT INTO storage_cleanup_jobs(object_key, created_at) \
                 SELECT ?1, ?2 WHERE NOT EXISTS (SELECT 1 FROM attachments \
                 WHERE COALESCE(storage_key, cipher_id || '/' || id) = ?1) \
                 AND NOT EXISTS (SELECT 1 FROM sends WHERE file_id IS NOT \
                 NULL AND COALESCE(storage_key, 'sends/' || id || '/' || \
                 file_id) = ?1) ON CONFLICT(object_key) DO UPDATE SET \
                 created_at=excluded.created_at, \
                 generation=excluded.generation",
            )
            .bind(&[key.into(), crate::infra::time::now_rfc3339().into()])?
            .run()
            .await?;
        Ok::<bool, crate::errors::AppError>(
            result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 1,
        )
    }
    .await;
    match queued {
        Ok(true) => {
            if let Err(error) = drain(env, db).await {
                log::warn!("Staged file cleanup deferred: {error}");
            }
        }
        Ok(false) => {}
        Err(error) => log::warn!(
            "Cannot confirm staged object is unreferenced; retaining bytes: \
             {error}"
        ),
    }
}

/// Process at most 128 jobs. A failed backend delete never acknowledges jobs.
/// Random generations keep acknowledgement from removing a re-enqueued job.
pub async fn drain(env: &Env, db: &D1Database) -> AppResult<u32> {
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
        .results::<CleanupJob>()?;
    if jobs.is_empty() {
        return Ok(0);
    }
    let storage = Storage::from_env(env)?;
    let keys = jobs
        .iter()
        .map(|job| job.object_key.clone())
        .collect::<Vec<_>>();
    storage.delete_many(&keys).await?;
    let result = db
        .prepare(
            "DELETE FROM storage_cleanup_jobs WHERE (object_key, generation) \
             IN (SELECT json_extract(value, '$.object_key'), \
             json_extract(value, '$.generation') FROM json_each(?1))",
        )
        .bind(&[serde_json::to_string(&jobs)
            .map_err(|_| crate::errors::AppError::Internal)?
            .into()])?
        .run()
        .await?;
    Ok(result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) as u32)
}
