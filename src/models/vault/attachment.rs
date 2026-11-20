//! Persisted attachment records and D1 queries and transaction builders.
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
};

use crate::{
    errors::{
        AppError,
        AppResult,
        DatabaseError,
    },
    infra::db,
    models::mutation::{
        ATTACHMENT_QUOTA_SENTINEL,
        batch_count_last_write,
    },
};

const USER_ATTACHMENT_USAGE_SQL: &str =
    "SELECT COALESCE(SUM(file_size_bytes), 0) AS total FROM (
        SELECT a.file_size_bytes FROM attachments a
        JOIN ciphers c ON c.id = a.cipher_id
        WHERE c.user_id = ?1 AND (?2 IS NULL OR a.id != ?2)
        UNION ALL
        SELECT p.file_size_bytes FROM attachments_pending p
        JOIN ciphers c ON c.id = p.cipher_id
        WHERE c.user_id = ?1 AND (?2 IS NULL OR p.id != ?2)
    ) AS files";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttachmentRow {
    pub id:              String,
    pub cipher_id:       String,
    pub file_name:       String,
    pub file_size_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_key:   Option<String>,
    pub created_at:      String,
    pub updated_at:      String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub storage_key:     Option<String>,
}

impl AttachmentRow {
    /// Prepare publication; the caller supplies account/source assertions and
    /// commits these statements with the sync cursor in the same transaction.
    pub fn finalize_upload(
        db: &D1Database,
        attachment: &Self,
        user_id: &str,
        now: &str,
    ) -> AppResult<Vec<D1PreparedStatement>> {
        Ok(vec![
            query!(
                db,
                "INSERT INTO attachments \
                 (id,cipher_id,file_name,file_size_bytes,encrypted_key,\
                 created_at,updated_at,organization_id,storage_key) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                attachment.id,
                attachment.cipher_id,
                attachment.file_name,
                attachment.file_size_bytes,
                attachment.encrypted_key,
                attachment.created_at,
                now,
                attachment.organization_id,
                attachment.storage_key
            )?,
            query!(
                db,
                "DELETE FROM attachments_pending WHERE id=?1",
                attachment.id
            )?,
            query!(
                db,
                "UPDATE ciphers SET updated_at=?1 WHERE id=?2 AND user_id=?3",
                now,
                attachment.cipher_id,
                user_id
            )?,
        ])
    }

    /// Replace a committed file only after its captured row is asserted by
    /// the bearer upload transaction. The storage trigger queues the old key.
    pub fn replace_upload(
        db: &D1Database,
        attachment: &Self,
        user_id: &str,
        now: &str,
    ) -> AppResult<Vec<D1PreparedStatement>> {
        Ok(vec![
            query!(
                db,
                "UPDATE attachments SET \
                 file_size_bytes=?1,encrypted_key=?2,storage_key=?3,\
                 updated_at=?4 WHERE id=?5 AND cipher_id=?6",
                attachment.file_size_bytes,
                attachment.encrypted_key,
                attachment.storage_key,
                now,
                attachment.id,
                attachment.cipher_id
            )?,
            query!(
                db,
                "UPDATE ciphers SET updated_at=?1 WHERE id=?2 AND user_id=?3",
                now,
                attachment.cipher_id,
                user_id
            )?,
        ])
    }

    pub async fn purge_pending_before(
        db: &D1Database,
        cutoff_exclusive: &str,
    ) -> AppResult<u32> {
        let delete = query!(
            db,
            "DELETE FROM attachments_pending WHERE julianday(created_at) < \
             julianday(?1)",
            cutoff_exclusive
        )?;
        batch_count_last_write(
            db,
            vec![delete],
            "Failed to purge pending attachments",
        )
        .await
    }

    pub async fn fetch_attachment(
        db: &D1Database,
        attachment_id: &str,
    ) -> AppResult<Self> {
        db.prepare("SELECT * FROM attachments WHERE id = ?1")
            .bind(&[attachment_id.into()])?
            .first(None)
            .await
            .map_err(|e| DatabaseError::query("Failed to fetch attachment", e))?
            .ok_or_else(|| AppError::not_found("Attachment"))
    }

    pub async fn fetch_pending_attachment(
        db: &D1Database,
        attachment_id: &str,
    ) -> AppResult<Self> {
        db.prepare("SELECT * FROM attachments_pending WHERE id = ?1")
            .bind(&[attachment_id.into()])?
            .first(None)
            .await
            .map_err(|e| {
                DatabaseError::query("Failed to fetch pending attachment", e)
            })?
            .ok_or_else(|| AppError::not_found("Pending attachment"))
    }

    pub async fn list_for_ciphers_json(
        db: &D1Database,
        json_body: &str,
        ids_path: &str,
    ) -> AppResult<Vec<Self>> {
        let result = db
            .prepare(
                "SELECT * FROM attachments WHERE cipher_id IN (SELECT value \
                 FROM json_each(?1, ?2))",
            )
            .bind(&[json_body.to_owned().into(), ids_path.to_owned().into()])?
            .all()
            .await?;
        db::decode_results(&result)
    }

    pub async fn user_attachment_usage(
        db: &D1Database,
        user_id: &str,
        exclude_attachment: Option<&str>,
    ) -> AppResult<i64> {
        let row: Option<Value> = db
            .prepare(USER_ATTACHMENT_USAGE_SQL)
            .bind(&[
                user_id.into(),
                exclude_attachment.map_or(JsValue::NULL, Into::into),
            ])?
            .first(None)
            .await
            .map_err(|e| {
                DatabaseError::query(
                    "Failed to calculate user attachment usage",
                    e,
                )
            })?;

        let total = row
            .and_then(|v| v.get("total").cloned())
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        Ok(total)
    }

    /// Check the allowance for other files before writing this upload's size.
    pub(crate) fn quota_guard(
        db: &D1Database,
        user_id: &str,
        exclude_attachment: Option<&str>,
        usage_limit: u64,
    ) -> AppResult<D1PreparedStatement> {
        // The aggregate fits a SQLite integer. Bind as decimal text to avoid
        // rounding the allowance through a JavaScript number.
        let usage_limit = i64::try_from(usage_limit).unwrap_or(i64::MAX);
        Ok(db
            .prepare(format!(
                "SELECT CASE WHEN ({USER_ATTACHMENT_USAGE_SQL}) <= CAST(?3 AS \
                 INTEGER) THEN 1 ELSE json_extract('[]', \
                 '{ATTACHMENT_QUOTA_SENTINEL}') END"
            ))
            .bind(&[
                user_id.into(),
                exclude_attachment.map_or(JsValue::NULL, Into::into),
                usage_limit.to_string().into(),
            ])?)
    }

    pub(crate) async fn find_for_user(
        db: &D1Database,
        attachment_id: &str,
        user_id: &str,
    ) -> AppResult<Option<Self>> {
        Ok(db
            .prepare(
                "SELECT a.* FROM attachments a JOIN ciphers c ON \
                 c.id=a.cipher_id WHERE a.id=?1 AND c.user_id=?2",
            )
            .bind(&[attachment_id.into(), user_id.into()])?
            .first(None)
            .await?)
    }

    pub(crate) fn rotate_key_statements(
        db: &D1Database,
        row: &Self,
        file_name: &str,
        key: &str,
        now: &str,
    ) -> AppResult<Vec<D1PreparedStatement>> {
        let snapshot = crate::models::mutation::guard(
            db,
            "EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2 \
             AND file_name IS ?3 AND encrypted_key IS ?4 AND updated_at IS ?5 \
             AND storage_key IS ?6 AND file_size_bytes IS ?7)",
            &[
                row.id.clone().into(),
                row.cipher_id.clone().into(),
                row.file_name.clone().into(),
                row.encrypted_key
                    .as_deref()
                    .map_or(JsValue::NULL, JsValue::from_str),
                row.updated_at.clone().into(),
                row.storage_key
                    .as_deref()
                    .map_or(JsValue::NULL, JsValue::from_str),
                JsValue::from_f64(row.file_size_bytes as f64),
            ],
        )?;
        let update = db
            .prepare(
                "UPDATE attachments SET \
                 file_name=?1,encrypted_key=?2,updated_at=?3 WHERE id=?4 AND \
                 cipher_id=?5",
            )
            .bind(&[
                file_name.into(),
                key.into(),
                now.into(),
                row.id.clone().into(),
                row.cipher_id.clone().into(),
            ])?;
        Ok(vec![snapshot, update])
    }

    pub(crate) fn reserve_upload(
        &self,
        db: &D1Database,
    ) -> AppResult<D1PreparedStatement> {
        Ok(db
            .prepare(
                "INSERT INTO \
                 attachments_pending(id,cipher_id,file_name,file_size_bytes,\
                 encrypted_key,created_at,updated_at,organization_id) \
                 VALUES(?1,?2,?3,?4,?5,?6,?6,?7)",
            )
            .bind(&[
                self.id.clone().into(),
                self.cipher_id.clone().into(),
                self.file_name.clone().into(),
                JsValue::from_f64(self.file_size_bytes as f64),
                self.encrypted_key.clone().map_or(JsValue::NULL, Into::into),
                self.created_at.clone().into(),
                self.organization_id
                    .clone()
                    .map_or(JsValue::NULL, Into::into),
            ])?)
    }

    pub(crate) fn deletion_guard(
        &self,
        db: &D1Database,
    ) -> AppResult<D1PreparedStatement> {
        crate::models::mutation::guard(
            db,
            "EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2 \
             AND file_name IS ?3 AND encrypted_key IS ?4 AND storage_key IS \
             ?5 AND updated_at IS ?6)",
            &[
                self.id.clone().into(),
                self.cipher_id.clone().into(),
                self.file_name.clone().into(),
                self.encrypted_key.clone().map_or(JsValue::NULL, Into::into),
                self.storage_key.clone().map_or(JsValue::NULL, Into::into),
                self.updated_at.clone().into(),
            ],
        )
    }

    pub(crate) fn delete_statements(
        &self,
        db: &D1Database,
        owner: &str,
        now: &str,
    ) -> AppResult<Vec<D1PreparedStatement>> {
        Ok(vec![
            db.prepare("DELETE FROM attachments WHERE id=?1 AND cipher_id=?2")
                .bind(&[
                    self.id.clone().into(),
                    self.cipher_id.clone().into(),
                ])?,
            db.prepare(
                "UPDATE ciphers SET updated_at=?1 WHERE id=?2 AND user_id=?3",
            )
            .bind(&[
                now.into(),
                self.cipher_id.clone().into(),
                owner.into(),
            ])?,
        ])
    }
}

pub(crate) fn pending_snapshot_guard(
    db: &D1Database,
    row: &AttachmentRow,
) -> AppResult<D1PreparedStatement> {
    crate::models::mutation::guard(
        db,
        "EXISTS(SELECT 1 FROM attachments_pending WHERE id=?1 AND \
         cipher_id=?2 AND file_name IS ?3 AND file_size_bytes IS ?4 AND \
         encrypted_key IS ?5 AND created_at IS ?6 AND updated_at IS ?7 AND \
         organization_id IS ?8)",
        &[
            row.id.clone().into(),
            row.cipher_id.clone().into(),
            row.file_name.clone().into(),
            JsValue::from_f64(row.file_size_bytes as f64),
            row.encrypted_key.clone().map_or(JsValue::NULL, Into::into),
            row.created_at.clone().into(),
            row.updated_at.clone().into(),
            row.organization_id
                .clone()
                .map_or(JsValue::NULL, Into::into),
        ],
    )
}

pub(crate) fn attachment_snapshot_guard(
    db: &D1Database,
    row: &AttachmentRow,
) -> AppResult<D1PreparedStatement> {
    crate::models::mutation::guard(
        db,
        "EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2 AND \
         file_name IS ?3 AND file_size_bytes IS ?4 AND encrypted_key IS ?5 \
         AND created_at IS ?6 AND updated_at IS ?7 AND organization_id IS ?8 \
         AND storage_key IS ?9) AND NOT EXISTS(SELECT 1 FROM \
         attachments_pending WHERE id=?1)",
        &[
            row.id.clone().into(),
            row.cipher_id.clone().into(),
            row.file_name.clone().into(),
            JsValue::from_f64(row.file_size_bytes as f64),
            row.encrypted_key.clone().map_or(JsValue::NULL, Into::into),
            row.created_at.clone().into(),
            row.updated_at.clone().into(),
            row.organization_id
                .clone()
                .map_or(JsValue::NULL, Into::into),
            row.storage_key.clone().map_or(JsValue::NULL, Into::into),
        ],
    )
}
