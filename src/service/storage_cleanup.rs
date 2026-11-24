//! File-deletion retries shared by vault, Send and account workflows.
use bytes::Bytes;
use futures_util::Stream;
use worker::{D1Database, Env};

pub(crate) use crate::models::storage::{expire_stages, remove_stage, stage_guard};
use crate::{
    errors::{AppError, AppResult},
    infra::storage::{Storage, StorageWriteError},
    models::storage,
    utils::time,
};

/// One fresh object key whose cleanup is recorded before storage writes.
pub(crate) struct StagedObject<'a> {
    db: &'a D1Database,
    env: &'a Env,
    key: String,
    written_bytes: Option<u64>,
}

impl<'a> StagedObject<'a> {
    pub(crate) fn new(
        db: &'a D1Database,
        env: &'a Env,
        namespace: &str,
        parent_id: &str,
        object_id: &str,
    ) -> Self {
        Self {
            db,
            env,
            key: format!(
                "{namespace}/{parent_id}/{object_id}/{}",
                uuid::Uuid::new_v4()
            ),
            written_bytes: None,
        }
    }

    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    pub(crate) fn size(&self) -> AppResult<u64> {
        self.written_bytes.ok_or(AppError::Internal)
    }

    pub(crate) const fn ensure_unwritten(&self) -> AppResult<()> {
        if self.written_bytes.is_some() {
            return Err(AppError::Internal);
        }
        Ok(())
    }

    pub(crate) async fn write<S: Stream<Item = AppResult<Bytes>>>(
        &mut self,
        storage: &Storage,
        stream: S,
        max_bytes: u64,
        content_type: Option<&str>,
    ) -> AppResult<()> {
        self.ensure_unwritten()?;
        storage::register_stage(self.db, self.key()).await?;
        match storage
            .put_stream(self.key(), stream, max_bytes, content_type)
            .await
        {
            Ok(size) => {
                self.written_bytes = Some(size);
                Ok(())
            }
            Err(StorageWriteError::Incomplete(error)) => {
                discard_staged_object(self.env, self.db, self.key()).await;
                Err(error)
            }
            // The object may appear after this request returns. Keep its
            // stage available for scheduled cleanup.
            Err(StorageWriteError::Unconfirmed(error)) => Err(error),
        }
    }

    pub(crate) async fn discard_written(&self) {
        if self.written_bytes.is_some() {
            discard_staged_object(self.env, self.db, self.key()).await;
        }
    }
}

/// Retain bytes when a failed D1 response might hide a committed publication.
/// Uploaders use fresh keys, so an unreferenced failed attempt cannot replace
/// a previously committed object. Failed deletions remain discoverable.
async fn discard_staged_object(env: &Env, db: &D1Database, key: &str) {
    let now = time::now_rfc3339();
    let queued = storage::enqueue_if_unreferenced(db, key, &now).await;
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

/// Process at most 128 jobs. Failed backend deletes never acknowledge
/// uncompleted keys; completed prefixes are acknowledged with generation guards.
pub async fn process_batch(env: &Env, db: &D1Database) -> AppResult<u32> {
    let batch = storage::pending_batch(db).await?;
    let keys = batch.object_keys();
    if keys.is_empty() {
        return Ok(0);
    }
    let storage = Storage::from_env(env)?;
    let (completed, delete_error) = storage.delete_many(&keys).await;
    let acknowledged = batch.acknowledge_prefix(completed).await?;
    if let Some(error) = delete_error {
        return Err(error);
    }
    Ok(acknowledged)
}
