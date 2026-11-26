//! File-deletion retries shared by vault, Send and account workflows.
use bytes::Bytes;
use futures_util::Stream;
use worker::{D1Database, D1PreparedStatement, Env};

pub(crate) use crate::models::storage::expire_stages;
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
        self.written_bytes
            .ok_or_else(|| AppError::internal("Staged object size read before upload completed"))
    }

    pub(crate) const fn ensure_unwritten(&self) -> AppResult<()> {
        if self.written_bytes.is_some() {
            return Err(AppError::internal("Staged object has already been written"));
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

    /// Publish the object and remove its stage in one transaction. On failure
    /// the cleanup outbox preserves referenced objects if D1 already committed.
    pub(crate) async fn publish(
        &self,
        prepare: impl AsyncFnOnce(
            &Self,
        )
            -> AppResult<(Vec<D1PreparedStatement>, Vec<D1PreparedStatement>)>,
        commit: impl AsyncFnOnce(
            Vec<D1PreparedStatement>,
            Vec<D1PreparedStatement>,
        ) -> AppResult<String>,
    ) -> AppResult<String> {
        let result = async {
            let (mut guards, mut writes) = prepare(self).await?;
            guards.push(storage::stage_guard(self.db, self.key())?);
            writes.push(storage::remove_stage(self.db, self.key())?);
            commit(guards, writes).await
        }
        .await;
        if result.is_err() && self.written_bytes.is_some() {
            discard_staged_object(self.env, self.db, self.key()).await;
        }
        result
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
                log::warn!("Staged file cleanup deferred: {error:?}");
            }
        }
        Ok(false) => {}
        Err(error) => log::warn!(
            "Cannot confirm staged object is unreferenced; retaining bytes: \
             {error:?}"
        ),
    }
}

/// Acknowledge at most 128 jobs after R2 confirms the batch deletion.
pub async fn process_batch(env: &Env, db: &D1Database) -> AppResult<u32> {
    let batch = storage::pending_batch(db).await?;
    let keys = batch.object_keys();
    if keys.is_empty() {
        return Ok(0);
    }
    Storage::from_env(env)?.delete_batch(keys).await?;
    batch.acknowledge().await
}
