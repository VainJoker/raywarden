//! Attachment upload limits, mutable-source checks and publication lifecycle.
use std::fmt::Display;

use bytes::Bytes;
use futures_util::Stream;
use uuid::Uuid;
use worker::{
    D1Database,
    D1PreparedStatement,
    Env,
};

use crate::{
    app::AppContext,
    config::files::{
        attachment_max_bytes,
        attachment_quota_bytes,
    },
    errors::{
        AppError,
        AppResult,
    },
    infra::storage::Storage,
    models::{
        mutation::commit as commit_capability,
        vault::{
            attachment::AttachmentRow,
            cipher::CipherRow,
        },
    },
    service::{
        identity::session::Claims,
        notifications,
        notifications::{
            UpdateType,
            admin as admin_notify,
            admin::Event,
        },
        vault_write,
    },
};
const SIZE_LEEWAY_BYTES: i64 = 1024 * 1024;

pub(crate) enum UploadAuthorization<'a> {
    Session(&'a Claims),
    Capability {
        user_id: &'a str,
        device:  Option<&'a str>,
    },
}

impl UploadAuthorization<'_> {
    fn user_id(&self) -> &str {
        match self {
            Self::Session(claims) => &claims.sub,
            Self::Capability { user_id, .. } => user_id,
        }
    }
}

/// One object write and its guarded publication.
#[must_use]
pub(crate) struct AttachmentUpload<'a> {
    state:          &'a AppContext,
    row:            AttachmentRow,
    is_replacement: bool,
    owner:          UploadAuthorization<'a>,
    storage:        Storage,
    staged_key:     String,
    max_bytes:      u64,
    guards:         Vec<D1PreparedStatement>,
    written_bytes:  Option<u64>,
}

impl<'a> AttachmentUpload<'a> {
    pub(crate) fn new(
        state: &'a AppContext,
        row: AttachmentRow,
        is_replacement: bool,
        owner: UploadAuthorization<'a>,
        storage: Storage,
        max_bytes: u64,
        guards: Vec<D1PreparedStatement>,
    ) -> Self {
        let staged_key = staged_key(&row.cipher_id, &row.id);
        Self {
            state,
            row,
            is_replacement,
            owner,
            storage,
            staged_key,
            max_bytes,
            guards,
            written_bytes: None,
        }
    }

    pub(crate) async fn write<S, E>(
        &mut self,
        stream: S,
        content_type: Option<&str>,
    ) -> AppResult<()>
    where
        S: Stream<Item = Result<Bytes, E>>,
        E: Display,
    {
        if self.written_bytes.is_some() {
            return Err(AppError::Internal);
        }
        self.written_bytes = Some(
            self.storage
                .put_stream(
                    &self.staged_key,
                    stream,
                    self.max_bytes,
                    content_type,
                )
                .await?,
        );
        Ok(())
    }

    pub(crate) async fn finish(
        mut self,
        encrypted_key: Option<String>,
        content_length: Option<u64>,
    ) -> AppResult<()> {
        let db = self.state.database();
        let writes = async {
            let row = &mut self.row;
            let size = self.written_bytes.ok_or(AppError::Internal)?;
            if content_length.is_some_and(|expected| expected != size) {
                return Err(AppError::bad_request(
                    "Content-Length does not match uploaded size",
                ));
            }
            let size = checked_attachment_size_bytes(size)?;
            validate_declared_attachment_size(row, size)?;
            let user_id = self.owner.user_id();
            let usage_limit = enforce_attachment_size_limits(
                db,
                &self.state.env,
                user_id,
                size,
                Some(&row.id),
            )
            .await?;
            if let Some(encrypted_key) = encrypted_key {
                row.encrypted_key = Some(encrypted_key);
            }
            if matches!(&self.owner, UploadAuthorization::Session(_)) &&
                row.encrypted_key.is_none()
            {
                return Err(AppError::bad_request(
                    "No attachment key provided",
                ));
            }
            row.file_size_bytes = size;
            row.storage_key = Some(self.staged_key.clone());
            let now = crate::utils::time::now_rfc3339();
            if let Some(usage_limit) = usage_limit {
                self.guards.push(AttachmentRow::quota_guard(
                    db,
                    user_id,
                    Some(&row.id),
                    usage_limit,
                )?);
            }
            if self.is_replacement {
                AttachmentRow::replace_upload(db, row, user_id, &now)
            } else {
                AttachmentRow::finalize_upload(db, row, user_id, &now)
            }
        }
        .await;
        self.commit(writes).await
    }

    async fn commit(
        self,
        writes: AppResult<Vec<D1PreparedStatement>>,
    ) -> AppResult<()> {
        let db = self.state.database();
        let result = async {
            let writes = writes?;
            match &self.owner {
                UploadAuthorization::Session(claims) => {
                    vault_write::commit(db, claims, self.guards, writes).await
                }
                UploadAuthorization::Capability { user_id, .. } => {
                    commit_capability(db, user_id, self.guards, writes).await
                }
            }
        }
        .await;
        let revision = match result {
            Ok(revision) => revision,
            Err(error) => {
                crate::service::storage_cleanup::discard_staged_object(
                    &self.state.env,
                    db,
                    &self.staged_key,
                )
                .await;
                return Err(error);
            }
        };
        let device = match &self.owner {
            UploadAuthorization::Session(claims) => claims.device(),
            UploadAuthorization::Capability { device, .. } => *device,
        };
        let env = &self.state.env;
        let user_id = self.owner.user_id();
        notifications::publish_cipher_update(
            env,
            user_id,
            UpdateType::SyncCipherUpdate,
            &self.row.cipher_id,
            &revision,
            device,
        )
        .await;
        admin_notify::emit(env, Event::VaultChanged, user_id).await;
        if let Err(error) =
            crate::service::storage_cleanup::process_batch(env, db).await
        {
            log::warn!("Completed attachment object cleanup deferred: {error}");
        }
        Ok(())
    }

    pub(crate) async fn abort(self) {
        let db = self.state.database();
        crate::service::storage_cleanup::discard_staged_object(
            &self.state.env,
            db,
            &self.staged_key,
        )
        .await;
    }
}

fn staged_key(cipher_id: &str, attachment_id: &str) -> String {
    format!("attachments/{cipher_id}/{attachment_id}/{}", Uuid::new_v4())
}

pub(crate) async fn ensure_mutable_cipher(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
) -> AppResult<CipherRow> {
    let cipher = CipherRow::fetch_for_user(db, cipher_id, user_id).await?;
    if cipher.organization_id.is_some() {
        return Err(AppError::bad_request(
            "Organization attachments are not supported",
        ));
    }
    if cipher.deleted_at.is_some() {
        return Err(AppError::bad_request(
            "Cannot modify attachments for deleted cipher",
        ));
    }
    Ok(cipher)
}

pub(crate) async fn fetch_pending_attachment_for_cipher(
    db: &D1Database,
    cipher_id: &str,
    attachment_id: &str,
) -> AppResult<AttachmentRow> {
    let pending =
        AttachmentRow::fetch_pending_attachment(db, attachment_id).await?;
    if pending.cipher_id != cipher_id {
        return Err(AppError::bad_request(
            "Attachment does not belong to cipher",
        ));
    }
    Ok(pending)
}

pub(crate) fn checked_attachment_size_bytes(size: u64) -> AppResult<i64> {
    i64::try_from(size)
        .map_err(|_error| AppError::bad_request("Attachment size overflow"))
}

pub(crate) async fn attachment_upload_limit_bytes(
    db: &D1Database,
    env: &Env,
    user_id: &str,
    attachment: &AttachmentRow,
    expected_size: i64,
) -> AppResult<u64> {
    let (limit, _) = attachment_limits(
        db,
        env,
        user_id,
        expected_size,
        Some(&attachment.id),
    )
    .await?;
    let declared = u64::try_from(attachment.file_size_bytes)
        .map_err(|_error| AppError::bad_request("Invalid attachment size"))?;
    Ok(limit.min(declared + SIZE_LEEWAY_BYTES as u64))
}

/// Check the current limits and return the transaction allowance for other
/// attachments, when an account quota is configured.
pub(crate) async fn enforce_attachment_size_limits(
    db: &D1Database,
    env: &Env,
    user_id: &str,
    new_size: i64,
    exclude_attachment: Option<&str>,
) -> AppResult<Option<u64>> {
    let (_, usage_limit) =
        attachment_limits(db, env, user_id, new_size, exclude_attachment)
            .await?;
    Ok(usage_limit)
}

async fn attachment_limits(
    db: &D1Database,
    env: &Env,
    user_id: &str,
    size: i64,
    exclude_attachment: Option<&str>,
) -> AppResult<(u64, Option<u64>)> {
    let size = u64::try_from(size).map_err(|_error| {
        AppError::Params("Attachment size cannot be negative".to_string())
    })?;
    let mut max_bytes = i64::MAX as u64;
    if let Some(max) = Storage::max_bytes(env) {
        let max = max as u64;
        if size > max {
            return Err(AppError::bad_request(
                "File exceeds the 25 MiB KV limit",
            ));
        }
        max_bytes = max_bytes.min(max);
    }
    if let Some(max) = attachment_max_bytes(env)? {
        if size > max {
            return Err(AppError::Params(
                "Attachment size exceeds limit".to_string(),
            ));
        }
        max_bytes = max_bytes.min(max);
    }
    let Some(total) = attachment_quota_bytes(env)? else {
        return Ok((max_bytes, None));
    };
    let used =
        AttachmentRow::user_attachment_usage(db, user_id, exclude_attachment)
            .await?;
    let used = u64::try_from(used).map_err(AppError::internal_error)?;
    let usage_limit = total
        .checked_sub(size)
        .filter(|&limit| used <= limit)
        .ok_or_else(|| {
            AppError::Params("Attachment storage limit reached".to_string())
        })?;
    Ok((max_bytes.min(total - used), Some(usage_limit)))
}

fn validate_declared_attachment_size(
    attachment: &AttachmentRow,
    actual_size: i64,
) -> AppResult<()> {
    let max_size = attachment
        .file_size_bytes
        .checked_add(SIZE_LEEWAY_BYTES)
        .ok_or_else(|| {
            AppError::Params("Attachment size overflow".to_string())
        })?;
    let min_size = attachment
        .file_size_bytes
        .checked_sub(SIZE_LEEWAY_BYTES)
        .ok_or_else(|| {
            AppError::Params("Attachment size overflow".to_string())
        })?;

    if actual_size < min_size || actual_size > max_size {
        return Err(AppError::Params(format!(
            "Attachment size mismatch (expected within [{min_size}, \
             {max_size}], got {actual_size})"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pending(size: i64) -> AttachmentRow {
        AttachmentRow {
            id:              "attachment".to_string(),
            cipher_id:       "cipher".to_string(),
            file_name:       "encrypted".to_string(),
            file_size_bytes: size,
            encrypted_key:   Some("wrapped-key".to_string()),
            created_at:      String::new(),
            updated_at:      String::new(),
            organization_id: None,
            storage_key:     None,
        }
    }

    #[test]
    fn declared_size_leeway_is_inclusive_and_detects_overflow() {
        let attachment = pending(2 * SIZE_LEEWAY_BYTES);
        assert!(
            validate_declared_attachment_size(&attachment, SIZE_LEEWAY_BYTES)
                .is_ok()
        );
        assert!(
            validate_declared_attachment_size(
                &attachment,
                3 * SIZE_LEEWAY_BYTES
            )
            .is_ok()
        );
        assert!(
            validate_declared_attachment_size(
                &attachment,
                SIZE_LEEWAY_BYTES - 1
            )
            .is_err()
        );
        assert!(
            validate_declared_attachment_size(
                &attachment,
                3 * SIZE_LEEWAY_BYTES + 1
            )
            .is_err()
        );
        assert!(
            validate_declared_attachment_size(&pending(i64::MAX), 1).is_err()
        );
        assert!(validate_declared_attachment_size(&pending(1), 0).is_ok());
    }
}
