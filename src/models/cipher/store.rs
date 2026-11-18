//! Production D1 reads for Cipher lookup, projection and cleanup counts.
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{
    D1Database,
    query,
};

use super::types::CipherDB;
use crate::{
    errors::{
        AppError,
        DatabaseError,
    },
    infra::db,
    models::attachment::AttachmentResponse,
};

#[derive(Deserialize)]
struct CipherProjectionRow {
    #[serde(flatten)]
    cipher:           CipherDB,
    attachments_json: Option<String>,
}

#[derive(Deserialize, Default)]
struct CountRow {
    count: u32,
}

impl CipherDB {
    pub async fn count_soft_deleted_before(
        db: &D1Database,
        cutoff_exclusive: &str,
    ) -> Result<u32, AppError> {
        let count_row = query!(
            db,
            "SELECT COUNT(*) as count FROM ciphers WHERE deleted_at IS NOT \
             NULL AND julianday(deleted_at) < julianday(?1)",
            cutoff_exclusive
        )
        .map_err(|e| {
            AppError::Database(DatabaseError::QueryFailed(format!(
                "Failed to prepare soft-delete count query: {e}"
            )))
        })?
        .first::<CountRow>(None)
        .await
        .map_err(|e| {
            AppError::Database(DatabaseError::QueryFailed(format!(
                "Failed to count soft-deleted ciphers: {e}"
            )))
        })?;

        Ok(count_row.map_or(0, |row| row.count))
    }

    pub async fn fetch_for_user(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
    ) -> Result<Self, AppError> {
        db.prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
            .bind(&[cipher_id.to_string().into(), user_id.to_string().into()])
            .map_err(|e| {
                log::error!("Failed to bind fetch cipher query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch cipher".to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to execute fetch cipher query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch cipher".to_string(),
                ))
            })?
            .ok_or_else(|| AppError::not_found("Cipher not found"))
    }

    pub async fn ensure_cipher_for_user(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
    ) -> Result<Self, AppError> {
        let cipher: Option<Self> = db
            .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
            .bind(&[cipher_id.into(), user_id.into()])?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to fetch cipher for user: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch cipher".to_string(),
                ))
            })?;

        let cipher = cipher.ok_or_else(|| {
            AppError::Database(DatabaseError::QueryFailed(
                "Cipher not found".to_string(),
            ))
        })?;

        if cipher.organization_id.is_some() {
            return Err(AppError::Database(DatabaseError::QueryFailed(
                "Organization attachments are not supported".to_string(),
            )));
        }

        if cipher.deleted_at.is_some() {
            return Err(AppError::Database(DatabaseError::QueryFailed(
                "Cipher is deleted".to_string(),
            )));
        }

        Ok(cipher)
    }

    pub async fn fetch_cipher_json_array_raw(
        db: &D1Database,
        attachments_enabled: bool,
        where_clause: &str,
        params: &[JsValue],
        order_clause: &str,
        domain: &str,
    ) -> Result<String, AppError> {
        let sql = Self::cipher_row_sql(
            attachments_enabled,
            where_clause,
            order_clause,
        );
        let result = db.prepare(sql).bind(params)?.all().await?;
        let rows: Vec<CipherProjectionRow> = db::decode_results(&result)?;
        let mut ciphers = Vec::with_capacity(rows.len());
        for row in rows {
            let mut cipher = row.cipher.into_api()?;
            if let Some(raw) = row.attachments_json {
                let mut attachments: Vec<AttachmentResponse> =
                    serde_json::from_str(&raw)
                        .map_err(|_| AppError::Internal)?;
                for attachment in &mut attachments {
                    attachment.url = Some(format!(
                        "{}/attachments/{}/{}",
                        domain.trim_end_matches('/'),
                        cipher.id,
                        attachment.id
                    ));
                }
                cipher.attachments =
                    (!attachments.is_empty()).then_some(attachments);
            }
            ciphers.push(cipher);
        }
        serde_json::to_string(&ciphers).map_err(|_| AppError::Internal)
    }

    fn cipher_row_sql(
        attachments_enabled: bool,
        where_clause: &str,
        order_clause: &str,
    ) -> String {
        let attachments_expr = if attachments_enabled {
            "
            (
                SELECT CASE WHEN COUNT(1)=0 THEN NULL ELSE json_group_array(
                    json_object(
                        'id', a.id,
                        'url', NULL,
                        'fileName', a.file_name,
                        'size', CAST(a.file_size AS TEXT),
                        'sizeName',
                            CASE
                                WHEN a.file_size < 1024 THEN printf('%d B', \
             a.file_size)
                                WHEN a.file_size < 1048576 THEN printf('%.1f \
             KB', a.file_size / 1024.0)
                                WHEN a.file_size < 1073741824 THEN \
             printf('%.1f MB', a.file_size / 1048576.0)
                                WHEN a.file_size < 1099511627776 THEN \
             printf('%.1f GB', a.file_size / 1073741824.0)
                                ELSE printf('%.1f TB', a.file_size / \
             1099511627776.0)
                            END,
                        'key', a.akey,
                        'object', 'attachment'
                    )
                ) END
                FROM attachments a
                WHERE a.cipher_id = c.id
            )
        "
        } else {
            "NULL"
        };
        format!(
            "SELECT c.*, {attachments_expr} AS attachments_json FROM ciphers \
             c {where_clause} {order_clause}"
        )
    }
}
