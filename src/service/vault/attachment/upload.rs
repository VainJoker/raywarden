//! Attachment upload limits, mutable-source checks and publication lifecycle.
use bytes::Bytes;
use futures_util::{Stream, StreamExt as _};
use worker::{D1Database, D1PreparedStatement, Env};

use super::require_owned_cipher;
use crate::{
    errors::{AppError, AppResult},
    infra::{
        config::{attachment_max_bytes, attachment_quota_bytes},
        storage::Storage,
    },
    models::{
        mutation::{account_snapshot_guard, cipher_snapshot_guard, commit as commit_capability},
        vault::attachment::{AttachmentRow, upload_snapshot_guard},
    },
    service::{
        identity::session::Claims,
        notifications,
        notifications::{UpdateType, admin as admin_notify, admin::Event},
        storage_cleanup::{self, StagedObject},
        vault_write,
    },
};
const SIZE_LEEWAY_BYTES: i64 = 1024 * 1024;

pub(crate) enum UploadAuthorization<'a> {
    Session(&'a Claims),
    Capability {
        user_id: &'a str,
        device: Option<&'a str>,
    },
}

impl UploadAuthorization<'_> {
    fn user_id(&self) -> &str {
        match self {
            Self::Session(claims) => &claims.sub,
            Self::Capability { user_id, .. } => user_id,
        }
    }

    fn device(&self) -> Option<&str> {
        match self {
            Self::Session(claims) => claims.device(),
            Self::Capability { device, .. } => *device,
        }
    }
}

/// One object write and its guarded publication.
#[must_use]
pub(crate) struct AttachmentUpload<'a> {
    db: &'a D1Database,
    env: &'a Env,
    row: AttachmentRow,
    is_replacement: bool,
    owner: UploadAuthorization<'a>,
    storage: Storage,
    staged: StagedObject<'a>,
    max_bytes: u64,
    content_length: Option<u64>,
    guards: Vec<D1PreparedStatement>,
}

impl<'a> AttachmentUpload<'a> {
    pub(crate) async fn prepare(
        db: &'a D1Database,
        env: &'a Env,
        owner: UploadAuthorization<'a>,
        cipher_id: &str,
        attachment_id: &str,
        content_length: AppResult<Option<u64>>,
    ) -> AppResult<Self> {
        let storage = Storage::from_env(env)?;
        let user_id = owner.user_id();
        let (_, key_guard) = match &owner {
            UploadAuthorization::Session(claims) => {
                vault_write::account_key_guard(db, claims).await?
            }
            UploadAuthorization::Capability { .. } => account_snapshot_guard(db, user_id).await?,
        };
        let cipher = require_owned_cipher(
            db,
            cipher_id,
            user_id,
            "Cannot modify attachments for deleted cipher",
        )
        .await?;
        let (row, is_replacement) =
            match AttachmentRow::fetch_pending_for_cipher(db, cipher_id, attachment_id).await {
                Ok(row) => (row, false),
                Err(AppError::NotFound { .. })
                    if matches!(&owner, UploadAuthorization::Session(_)) =>
                {
                    (
                        AttachmentRow::fetch_for_cipher(db, cipher_id, attachment_id).await?,
                        true,
                    )
                }
                Err(error) => return Err(error),
            };
        let content_length = content_length?;
        let size = content_length
            .map(checked_attachment_size_bytes)
            .transpose()?
            .unwrap_or(row.file_size_bytes);
        let limits = attachment_limits(db, env, user_id, size, Some(&row.id)).await?;
        let declared = u64::try_from(row.file_size_bytes)
            .map_err(|_error| AppError::bad_request("Invalid attachment size"))?;
        let max_bytes = limits
            .max_upload_bytes
            .min(declared + SIZE_LEEWAY_BYTES as u64);
        if content_length.is_some_and(|size| size > max_bytes) {
            return Err(AppError::bad_request("Attachment size exceeds limit"));
        }
        let guards = vec![
            key_guard,
            cipher_snapshot_guard(db, &cipher)?,
            upload_snapshot_guard(db, &row, is_replacement)?,
        ];
        Ok(Self {
            db,
            env,
            staged: StagedObject::new(db, env, "attachments", cipher_id, attachment_id),
            row,
            is_replacement,
            owner,
            storage,
            max_bytes,
            content_length,
            guards,
        })
    }

    pub(crate) async fn write<S, E>(
        &mut self,
        stream: S,
        content_type: Option<&str>,
    ) -> AppResult<()>
    where
        S: Stream<Item = Result<Bytes, E>>,
    {
        let stream = stream
            .map(|chunk| chunk.map_err(|_error| AppError::bad_request("Invalid upload body")));
        self.staged
            .write(&self.storage, stream, self.max_bytes, content_type)
            .await
    }

    pub(crate) async fn finish(mut self, received: AppResult<Option<String>>) -> AppResult<()> {
        let db = self.db;
        let owner = &self.owner;
        let revision = self
            .staged
            .publish(
                async |object| {
                    let encrypted_key = received?;
                    let row = &mut self.row;
                    let size = object.size()?;
                    if self.content_length.is_some_and(|expected| expected != size) {
                        return Err(AppError::bad_request(
                            "Content-Length does not match uploaded size",
                        ));
                    }
                    let size = checked_attachment_size_bytes(size)?;
                    validate_declared_attachment_size(row, size)?;
                    let user_id = owner.user_id();
                    let limits =
                        attachment_limits(db, self.env, user_id, size, Some(&row.id)).await?;
                    if let Some(encrypted_key) = encrypted_key {
                        row.encrypted_key = Some(encrypted_key);
                    }
                    if matches!(owner, UploadAuthorization::Session(_))
                        && row.encrypted_key.is_none()
                    {
                        return Err(AppError::bad_request("No attachment key provided"));
                    }
                    let domain = crate::infra::config::Config::from_env(self.env)?.domain;
                    super::enforce_cipher_attachment_metadata_budget(
                        db,
                        &domain,
                        row,
                        self.is_replacement.then_some(row.id.as_str()),
                    )
                    .await?;
                    row.file_size_bytes = size;
                    row.storage_key = Some(object.key().to_owned());
                    let now = crate::utils::time::now_rfc3339();
                    if let Some(usage_limit) = limits.remaining_usage_limit {
                        self.guards.push(AttachmentRow::quota_guard(
                            db,
                            user_id,
                            Some(&row.id),
                            usage_limit,
                        )?);
                    }
                    let writes = row.upload_statements(db, user_id, &now, self.is_replacement)?;
                    Ok((self.guards, writes))
                },
                async |guards, writes| match owner {
                    UploadAuthorization::Session(claims) => {
                        vault_write::commit(db, claims, guards, writes).await
                    }
                    UploadAuthorization::Capability { user_id, .. } => {
                        commit_capability(db, user_id, guards, writes).await
                    }
                },
            )
            .await?;
        let device = self.owner.device();
        let env = self.env;
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
        if let Err(error) = storage_cleanup::process_batch(env, db).await {
            log::warn!("Completed attachment object cleanup deferred: {error:?}");
        }
        Ok(())
    }
}

fn checked_attachment_size_bytes(size: u64) -> AppResult<i64> {
    i64::try_from(size).map_err(|_error| AppError::bad_request("Attachment size overflow"))
}

pub(crate) struct AttachmentLimits {
    pub max_upload_bytes: u64,
    pub remaining_usage_limit: Option<u64>,
}

/// Return the upload byte cap and quota allowance for other attachments.
pub(crate) async fn attachment_limits(
    db: &D1Database,
    env: &Env,
    user_id: &str,
    size: i64,
    exclude_attachment: Option<&str>,
) -> AppResult<AttachmentLimits> {
    let size = u64::try_from(size)
        .map_err(|_error| AppError::Params("Attachment size cannot be negative".into()))?;
    let mut max_bytes = i64::MAX as u64;
    if let Some(max) = attachment_max_bytes(env)? {
        if size > max {
            return Err(AppError::Params("Attachment size exceeds limit".into()));
        }
        max_bytes = max_bytes.min(max);
    }
    let Some(total) = attachment_quota_bytes(env)? else {
        return Ok(AttachmentLimits {
            max_upload_bytes: max_bytes,
            remaining_usage_limit: None,
        });
    };
    let used = AttachmentRow::user_attachment_usage(db, user_id, exclude_attachment).await?;
    let used = u64::try_from(used)
        .map_err(|error| AppError::internal_debug("Invalid stored attachment byte usage", error))?;
    let usage_limit = total
        .checked_sub(size)
        .filter(|&limit| used <= limit)
        .ok_or_else(|| AppError::Params("Attachment storage limit reached".into()))?;
    Ok(AttachmentLimits {
        max_upload_bytes: max_bytes.min(total - used),
        remaining_usage_limit: Some(usage_limit),
    })
}

fn validate_declared_attachment_size(
    attachment: &AttachmentRow,
    actual_size: i64,
) -> AppResult<()> {
    let max_size = attachment
        .file_size_bytes
        .checked_add(SIZE_LEEWAY_BYTES)
        .ok_or_else(|| AppError::Params("Attachment size overflow".into()))?;
    let min_size = attachment
        .file_size_bytes
        .checked_sub(SIZE_LEEWAY_BYTES)
        .ok_or_else(|| AppError::Params("Attachment size overflow".into()))?;

    if !(min_size..=max_size).contains(&actual_size) {
        return Err(AppError::Params(
            format!(
                "Attachment size mismatch (expected within [{min_size}, \
             {max_size}], got {actual_size})"
            )
            .into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pending(size: i64) -> AttachmentRow {
        AttachmentRow {
            id: "attachment".to_string(),
            cipher_id: "cipher".to_string(),
            file_name: "encrypted".to_string(),
            file_size_bytes: size,
            encrypted_key: Some("wrapped-key".to_string()),
            created_at: String::new(),
            updated_at: String::new(),
            organization_id: None,
            storage_key: None,
        }
    }

    #[test]
    fn byte_count_must_fit_signed_storage_size() {
        assert!(checked_attachment_size_bytes(i64::MAX as u64).is_ok());
        assert!(checked_attachment_size_bytes(i64::MAX as u64 + 1).is_err());
    }

    #[test]
    fn declared_size_leeway_is_inclusive_and_detects_overflow() {
        let attachment = pending(2 * SIZE_LEEWAY_BYTES);
        assert!(validate_declared_attachment_size(&attachment, SIZE_LEEWAY_BYTES).is_ok());
        assert!(validate_declared_attachment_size(&attachment, 3 * SIZE_LEEWAY_BYTES).is_ok());
        assert!(validate_declared_attachment_size(&attachment, SIZE_LEEWAY_BYTES - 1).is_err());
        assert!(validate_declared_attachment_size(&attachment, 3 * SIZE_LEEWAY_BYTES + 1).is_err());
        assert!(validate_declared_attachment_size(&pending(i64::MAX), 1).is_err());
        assert!(validate_declared_attachment_size(&pending(1), 0).is_ok());
    }
}
