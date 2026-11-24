//! Persisted attachment records and D1 queries and transaction builders.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::{D1Database, D1PreparedStatement, query};

use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
    models::{
        mutation::batch_count_last_write,
        page::{Page, PageCursor, PageOrder, PageQuery},
    },
};

const USER_ATTACHMENT_USAGE_SQL: &str = "SELECT COALESCE(SUM(file_size_bytes), 0) AS total FROM (
        SELECT a.file_size_bytes FROM attachments a
        JOIN ciphers c ON c.id = a.cipher_id
        WHERE c.user_id = ?1 AND (?2 IS NULL OR a.id != ?2)
        UNION ALL
        SELECT p.file_size_bytes FROM attachments_pending p
        JOIN ciphers c ON c.id = p.cipher_id
        WHERE c.user_id = ?1 AND (?2 IS NULL OR p.id != ?2)
    ) AS files";

#[derive(Deserialize)]
struct AttachmentUsageRow {
    #[serde(default, deserialize_with = "attachment_total")]
    total: i64,
}

fn attachment_total<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    Ok(Value::deserialize(deserializer)?.as_i64().unwrap_or(0))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttachmentRow {
    pub id: String,
    pub cipher_id: String,
    pub file_name: String,
    pub file_size_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_key: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub storage_key: Option<String>,
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

    pub async fn purge_pending_before(db: &D1Database, cutoff_exclusive: &str) -> AppResult<u32> {
        let delete = query!(
            db,
            "DELETE FROM attachments_pending WHERE julianday(created_at) < \
             julianday(?1)",
            cutoff_exclusive
        )?;
        batch_count_last_write(db, vec![delete], "Failed to purge pending attachments").await
    }

    pub async fn fetch_for_cipher(
        db: &D1Database,
        cipher_id: &str,
        attachment_id: &str,
    ) -> AppResult<Self> {
        db.prepare("SELECT * FROM attachments WHERE id = ?1 AND cipher_id = ?2")
            .bind(&db::d1_params![attachment_id, cipher_id])?
            .first(None)
            .await
            .map_err(|e| DatabaseError::query("Failed to fetch attachment", &e))?
            .ok_or_else(|| AppError::not_found("Attachment"))
    }

    pub async fn fetch_pending_for_cipher(
        db: &D1Database,
        cipher_id: &str,
        attachment_id: &str,
    ) -> AppResult<Self> {
        db.prepare(
            "SELECT * FROM attachments_pending WHERE id = ?1 AND cipher_id = \
             ?2",
        )
        .bind(&db::d1_params![attachment_id, cipher_id])?
        .first(None)
        .await
        .map_err(|e| DatabaseError::query("Failed to fetch pending attachment", &e))?
        .ok_or_else(|| AppError::not_found("Pending attachment"))
    }

    pub(crate) async fn list_page(
        db: &D1Database,
        cipher_ids_json: &str,
        after: Option<&PageCursor>,
    ) -> AppResult<Page<Self>> {
        Self::paged("cipher_id IN (SELECT value FROM json_each(?))")
            .fetch(db, &db::d1_params![cipher_ids_json], after)
            .await
    }

    pub(crate) async fn list_key_update_page(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
        attachment_ids_json: &str,
        after: Option<&PageCursor>,
    ) -> AppResult<Page<Self>> {
        Self::paged("cipher_id=? AND id IN (SELECT value FROM json_each(?)) AND                      EXISTS (SELECT 1 FROM ciphers WHERE ciphers.id=attachments.cipher_id AND user_id=?)")
            .fetch(db, &db::d1_params![cipher_id, attachment_ids_json, user_id], after)
            .await
    }

    const fn paged(filter: &'static str) -> PageQuery {
        PageQuery {
            table: "attachments",
            filter,
            text_columns: &[
                "id",
                "cipher_id",
                "file_name",
                "encrypted_key",
                "created_at",
                "updated_at",
                "organization_id",
                "storage_key",
            ],
            order: PageOrder::RowId,
            related_bytes: None,
        }
    }

    pub async fn user_attachment_usage(
        db: &D1Database,
        user_id: &str,
        exclude_attachment: Option<&str>,
    ) -> AppResult<i64> {
        let row: Option<AttachmentUsageRow> = db
            .prepare(USER_ATTACHMENT_USAGE_SQL)
            .bind(&db::d1_params![user_id, exclude_attachment,])?
            .first(None)
            .await
            .map_err(|e| DatabaseError::query("Failed to calculate user attachment usage", &e))?;

        Ok(row.map_or(0, |row| row.total))
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
        let abort = DbSentinel::AttachmentQuotaExceeded.sql_abort_expr();
        let usage_limit = i64::try_from(usage_limit).unwrap_or(i64::MAX);
        Ok(db
            .prepare(format!(
                "SELECT CASE WHEN ({USER_ATTACHMENT_USAGE_SQL}) <= CAST(?3 AS \
                 INTEGER) THEN 1 ELSE {abort} END"
            ))
            .bind(&db::d1_params![
                user_id,
                exclude_attachment,
                usage_limit.to_string(),
            ])?)
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
            &db::d1_params![
                row.id,
                row.cipher_id,
                row.file_name,
                row.encrypted_key,
                row.updated_at,
                row.storage_key,
                row.file_size_bytes as f64,
            ],
        )?;
        let update = db
            .prepare(
                "UPDATE attachments SET \
                 file_name=?1,encrypted_key=?2,updated_at=?3 WHERE id=?4 AND \
                 cipher_id=?5",
            )
            .bind(&db::d1_params![file_name, key, now, row.id, row.cipher_id,])?;
        Ok(vec![snapshot, update])
    }

    pub(crate) fn reserve_upload(&self, db: &D1Database) -> AppResult<D1PreparedStatement> {
        Ok(db
            .prepare(
                "INSERT INTO \
                 attachments_pending(id,cipher_id,file_name,file_size_bytes,\
                 encrypted_key,created_at,updated_at,organization_id) \
                 VALUES(?1,?2,?3,?4,?5,?6,?6,?7)",
            )
            .bind(&db::d1_params![
                self.id,
                self.cipher_id,
                self.file_name,
                self.file_size_bytes as f64,
                self.encrypted_key,
                self.created_at,
                self.organization_id,
            ])?)
    }

    pub(crate) fn deletion_guard(&self, db: &D1Database) -> AppResult<D1PreparedStatement> {
        crate::models::mutation::guard(
            db,
            "EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2 \
             AND file_name IS ?3 AND encrypted_key IS ?4 AND storage_key IS \
             ?5 AND updated_at IS ?6)",
            &db::d1_params![
                self.id,
                self.cipher_id,
                self.file_name,
                self.encrypted_key,
                self.storage_key,
                self.updated_at,
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
                .bind(&db::d1_params![self.id, self.cipher_id])?,
            db.prepare("UPDATE ciphers SET updated_at=?1 WHERE id=?2 AND user_id=?3")
                .bind(&db::d1_params![now, self.cipher_id, owner])?,
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
        &db::d1_params![
            row.id,
            row.cipher_id,
            row.file_name,
            row.file_size_bytes as f64,
            row.encrypted_key,
            row.created_at,
            row.updated_at,
            row.organization_id,
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
        &db::d1_params![
            row.id,
            row.cipher_id,
            row.file_name,
            row.file_size_bytes as f64,
            row.encrypted_key,
            row.created_at,
            row.updated_at,
            row.organization_id,
            row.storage_key,
        ],
    )
}
