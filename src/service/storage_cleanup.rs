//! File-deletion retries shared by vault, Send and account workflows.
use worker::{
    D1Database,
    Env,
};

use crate::{
    errors::AppResult,
    infra::storage::Storage,
    models::storage_cleanup,
    utils::time,
};

/// Retain bytes when a failed D1 response might hide a committed publication.
/// Uploaders use fresh keys, so an unreferenced failed attempt cannot replace
/// a previously committed object. Failed deletions remain discoverable.
pub async fn discard_staged_object(env: &Env, db: &D1Database, key: &str) {
    let now = time::now_rfc3339();
    let queued = storage_cleanup::enqueue_if_unreferenced(db, key, &now).await;
    match queued {
        Ok(true) => {
            if let Err(error) = process_batch(env, db).await {
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
pub async fn process_batch(env: &Env, db: &D1Database) -> AppResult<u32> {
    let batch = storage_cleanup::pending_batch(db).await?;
    let keys = batch.object_keys();
    if keys.is_empty() {
        return Ok(0);
    }
    let storage = Storage::from_env(env)?;
    storage.delete_many(&keys).await?;
    batch.acknowledge().await
}
