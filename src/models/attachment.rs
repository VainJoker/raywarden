use std::collections::HashMap;

use log;
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{
    Bucket,
    D1Database,
    Env,
    query,
};

use crate::{
    errors::{
        AppError,
        DatabaseError,
    },
    infra::DB,
};

pub const ATTACHMENTS_BUCKET: &str = "ATTACHMENTS_BUCKET";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttachmentDB {
    pub id:              String,
    pub cipher_id:       String,
    pub file_name:       String,
    pub file_size:       i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub akey:            Option<String>,
    pub created_at:      String,
    pub updated_at:      String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentResponse {
    pub id:        String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url:       Option<String>,
    pub file_name: String,
    pub size:      String,
    pub size_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key:       Option<String>,
    pub object:    String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct AttachmentKeyRow {
    pub cipher_id: String,
    pub id:        String,
}

#[derive(Debug, Deserialize, Default)]
struct CountRow {
    count: u32,
}

impl AttachmentDB {
    pub async fn insert_pending(
        db: &D1Database,
        pending: &Self,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO attachments_pending (id, cipher_id, \
                     file_name, file_size, akey, created_at, updated_at, \
                     organization_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
                    pending.id,
                    pending.cipher_id,
                    pending.file_name,
                    pending.file_size,
                    pending.akey,
                    pending.created_at,
                    pending.organization_id,
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to insert pending attachment",
        )
        .await
    }

    pub async fn insert_finalized(
        db: &D1Database,
        attachment: &Self,
        now: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO attachments (id, cipher_id, file_name, \
                     file_size, akey, created_at, updated_at, organization_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    attachment.id,
                    attachment.cipher_id,
                    attachment.file_name,
                    attachment.file_size,
                    attachment.akey,
                    attachment.created_at,
                    now,
                    attachment.organization_id,
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to finalize attachment",
        )
        .await
    }

    pub async fn delete_pending(
        db: &D1Database,
        attachment_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM attachments_pending WHERE id = ?1",
                    attachment_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to delete pending attachment",
        )
        .await
    }

    pub async fn purge_pending_before(
        db: &D1Database,
        cutoff_exclusive: &str,
    ) -> Result<u32, AppError> {
        let pending_count = query!(
            db,
            "SELECT COUNT(*) as count FROM attachments_pending WHERE \
             created_at < ?1",
            cutoff_exclusive
        )
        .map_err(|e| {
            log::error!("Failed to prepare pending attachment count: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to count pending attachments".to_string(),
            ))
        })?
        .first::<CountRow>(None)
        .await
        .map_err(|e| {
            log::error!("Failed to count pending attachments: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to count pending attachments".to_string(),
            ))
        })?
        .map_or(0, |row| row.count);

        if pending_count > 0 {
            DB::run_query(
                async {
                    query!(
                        db,
                        "DELETE FROM attachments_pending WHERE created_at < ?1",
                        cutoff_exclusive
                    )?
                    .run()
                    .await
                    .map(|_| ())
                },
                "Failed to purge pending attachments",
            )
            .await?;
        }

        Ok(pending_count)
    }

    pub async fn delete_attachment(
        db: &D1Database,
        attachment_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM attachments WHERE id = ?1",
                    attachment_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to delete attachment",
        )
        .await
    }

    pub fn r2_key(&self) -> String {
        format!("{}/{}", self.cipher_id, self.id)
    }

    pub fn to_response(&self, url: Option<String>) -> AttachmentResponse {
        AttachmentResponse {
            id: self.id.clone(),
            url,
            file_name: self.file_name.clone(),
            size: self.file_size.to_string(),
            size_name: display_size(self.file_size),
            key: self.akey.clone(),
            object: "attachment".to_string(),
        }
    }
}

fn display_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    if bytes < 0 {
        return "0 B".to_string();
    }
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}

impl AttachmentDB {
    pub async fn fetch_attachment(
        db: &D1Database,
        attachment_id: &str,
    ) -> Result<Self, AppError> {
        db.prepare("SELECT * FROM attachments WHERE id = ?1")
            .bind(&[attachment_id.into()])?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to fetch attachment: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch attachment".to_string(),
                ))
            })?
            .ok_or_else(|| AppError::not_found("Attachment"))
    }

    pub async fn fetch_pending_attachment(
        db: &D1Database,
        attachment_id: &str,
    ) -> Result<Self, AppError> {
        db.prepare("SELECT * FROM attachments_pending WHERE id = ?1")
            .bind(&[attachment_id.into()])?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to fetch pending attachment: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch pending attachment".to_string(),
                ))
            })?
            .ok_or_else(|| AppError::not_found("Pending attachment"))
    }

    pub async fn load_attachment_map_json(
        db: &D1Database,
        json_body: &str,
        ids_path: &str,
    ) -> Result<HashMap<String, Vec<AttachmentResponse>>, AppError> {
        let attachments: Vec<Self> = db
            .prepare(
                "SELECT * FROM attachments WHERE cipher_id IN (SELECT value \
                 FROM json_each(?1, ?2))",
            )
            .bind(&[json_body.to_owned().into(), ids_path.to_owned().into()])?
            .all()
            .await
            .map_err(|e| {
                log::error!("Failed to load attachments: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to load attachments".to_string(),
                ))
            })?
            .results()
            .map_err(|e| {
                log::error!("Failed to parse attachments: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to parse attachments".to_string(),
                ))
            })?;

        let mut map: HashMap<String, Vec<AttachmentResponse>> = HashMap::new();

        for attachment in attachments {
            map.entry(attachment.cipher_id.clone())
                .or_default()
                // URLs are minted on-demand via the download endpoint; skip
                // pre-signing here.
                .push(attachment.to_response(None));
        }

        Ok(map)
    }

    pub async fn user_attachment_usage(
        db: &D1Database,
        user_id: &str,
        exclude_attachment: Option<&str>,
    ) -> Result<i64, AppError> {
        let (query_str, bindings): (String, Vec<JsValue>) =
            if let Some(id) = exclude_attachment {
                (
                    "SELECT COALESCE(SUM(file_size), 0) as total FROM (
                SELECT a.file_size AS file_size
                FROM attachments a
                JOIN ciphers c ON c.id = a.cipher_id
                WHERE c.user_id = ?1 AND a.id != ?2
                UNION ALL
                SELECT p.file_size AS file_size
                FROM attachments_pending p
                JOIN ciphers c2 ON c2.id = p.cipher_id
                WHERE c2.user_id = ?1 AND p.id != ?2
            ) AS files"
                        .to_string(),
                    vec![JsValue::from_str(user_id), JsValue::from_str(id)],
                )
            } else {
                (
                    "SELECT COALESCE(SUM(file_size), 0) as total FROM (
                SELECT a.file_size AS file_size
                FROM attachments a
                JOIN ciphers c ON c.id = a.cipher_id
                WHERE c.user_id = ?1
                UNION ALL
                SELECT p.file_size AS file_size
                FROM attachments_pending p
                JOIN ciphers c2 ON c2.id = p.cipher_id
                WHERE c2.user_id = ?1
            ) AS files"
                        .to_string(),
                    vec![JsValue::from_str(user_id)],
                )
            };

        let row: Option<Value> = db
            .prepare(query_str)
            .bind(&bindings)?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to calculate user attachment usage: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to calculate user attachment usage".to_string(),
                ))
            })?;

        let total = row
            .and_then(|v| v.get("total").cloned())
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        Ok(total)
    }

    pub(crate) async fn list_attachment_keys_for_soft_deleted_before(
        db: &D1Database,
        cutoff_exclusive: &str,
    ) -> Result<Vec<String>, AppError> {
        let rows: Vec<AttachmentKeyRow> = db
            .prepare(
                "SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c \
                 ON a.cipher_id = c.id WHERE c.deleted_at IS NOT NULL AND \
                 c.deleted_at < ?1",
            )
            .bind(&[cutoff_exclusive.into()])?
            .all()
            .await
            .map_err(|e| {
                log::error!(
                    "Failed to query attachment keys for soft-deleted \
                     ciphers: {e}"
                );
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to query attachment keys for soft-deleted ciphers"
                        .to_string(),
                ))
            })?
            .results()
            .map_err(|e| {
                log::error!(
                    "Failed to parse attachment keys for soft-deleted \
                     ciphers: {e}"
                );
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to parse attachment keys for soft-deleted ciphers"
                        .to_string(),
                ))
            })?;

        Ok(Self::map_rows_to_keys(rows))
    }

    pub fn attachments_enabled(env: &Env) -> bool {
        env.bucket(ATTACHMENTS_BUCKET).is_ok()
    }

    pub fn require_bucket(env: &Env) -> Result<Bucket, AppError> {
        env.bucket(ATTACHMENTS_BUCKET).map_err(|e| {
            log::warn!("Attachments bucket not available: {e}");
            AppError::Params("Attachments are not enabled".to_string())
        })
    }

    fn is_not_found_error(err: &worker::Error) -> bool {
        let msg = err.to_string();
        msg.contains("NoSuchKey") ||
            msg.contains("404") ||
            msg.contains("NotFound")
    }

    pub async fn delete_r2_objects(
        bucket: &Bucket,
        keys: &[String],
    ) -> Result<(), AppError> {
        for key in keys {
            if let Err(err) = bucket.delete(key).await &&
                !Self::is_not_found_error(&err)
            {
                return Err(AppError::Worker(err));
            }
        }
        Ok(())
    }

    /// List attachment keys for given cipher IDs.
    /// - `json_body`: JSON text containing the ids array
    /// - `ids_path`: path to ids array within `json_body` (e.g. "$.ids" or "$"
    ///   if top-level)
    pub async fn list_attachment_keys_for_cipher_ids_json(
        db: &D1Database,
        json_body: &str,
        ids_path: &str,
        user_id: Option<&str>,
    ) -> Result<Vec<String>, AppError> {
        let mut sql = "SELECT a.cipher_id, a.id FROM attachments a JOIN \
                       ciphers c ON a.cipher_id = c.id WHERE c.id IN (SELECT \
                       value FROM json_each(?1, ?2))"
            .to_string();
        let mut params: Vec<worker::wasm_bindgen::JsValue> =
            vec![json_body.to_owned().into(), ids_path.to_owned().into()];

        if let Some(uid) = user_id {
            sql.push_str(" AND c.user_id = ?3");
            params.push(uid.into());
        }

        let rows: Vec<AttachmentKeyRow> = db
            .prepare(&sql)
            .bind(&params)?
            .all()
            .await
            .map_err(|e| {
                log::error!("Failed to query attachment keys: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to query attachment keys".to_string(),
                ))
            })?
            .results()
            .map_err(|e| {
                log::error!("Failed to parse attachment key rows: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to parse attachment key rows".to_string(),
                ))
            })?;

        Ok(Self::map_rows_to_keys(rows))
    }

    pub async fn list_attachment_keys_for_user(
        db: &D1Database,
        user_id: &str,
    ) -> Result<Vec<String>, AppError> {
        let rows: Vec<AttachmentKeyRow> = db
            .prepare(
                "SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c \
                 ON a.cipher_id = c.id WHERE c.user_id = ?1",
            )
            .bind(&[user_id.into()])?
            .all()
            .await
            .map_err(|e| {
                log::error!("Failed to query attachment keys for user: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to query attachment keys for user".to_string(),
                ))
            })?
            .results()
            .map_err(|e| {
                log::error!("Failed to parse attachment keys for user: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to parse attachment keys for user".to_string(),
                ))
            })?;

        Ok(Self::map_rows_to_keys(rows))
    }

    fn map_rows_to_keys(rows: Vec<AttachmentKeyRow>) -> Vec<String> {
        rows.into_iter()
            .map(|row| format!("{}/{}", row.cipher_id, row.id))
            .collect()
    }
}
