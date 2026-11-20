//! Persisted cipher records, D1 queries and guarded mutation statements.
use serde::{
    Deserialize,
    Serialize,
};
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
        NEXT_USER_REVISION_SQL,
        batch_count_last_write,
        cipher_snapshot_guard,
        guard,
    },
};
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CipherRow {
    pub id:              String,
    pub user_id:         String,
    pub organization_id: Option<String>,
    pub cipher_type:     i32,
    pub data:            String,
    pub is_favorite:     i32,
    pub folder_id:       Option<String>,
    pub deleted_at:      Option<String>,
    #[serde(default)]
    pub archived_at:     Option<String>,
    pub created_at:      String,
    pub updated_at:      String,
}

#[derive(Deserialize)]
pub(crate) struct CipherWithAttachmentsRow {
    #[serde(flatten)]
    pub cipher:           CipherRow,
    pub attachments_json: Option<String>,
}

impl CipherRow {
    pub async fn fetch_for_user(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
    ) -> AppResult<Self> {
        db.prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
            .bind(&[cipher_id.to_string().into(), user_id.to_string().into()])
            .map_err(|e| {
                DatabaseError::query("Failed to bind fetch cipher query", e)
            })?
            .first(None)
            .await
            .map_err(|e| {
                DatabaseError::query("Failed to execute fetch cipher query", e)
            })?
            .ok_or_else(|| AppError::not_found("Cipher not found"))
    }

    pub async fn fetch_for_attachment_owner(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
    ) -> AppResult<Self> {
        let cipher: Option<Self> = db
            .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
            .bind(&[cipher_id.into(), user_id.into()])?
            .first(None)
            .await
            .map_err(|e| {
                DatabaseError::query("Failed to fetch cipher for user", e)
            })?;

        let cipher = cipher.ok_or_else(DatabaseError::missing_cipher)?;

        Ok(cipher)
    }

    pub async fn fetch_with_attachments(
        db: &D1Database,
        user_id: &str,
        include_attachments: bool,
        include_ssh_keys: bool,
        newest_first: bool,
    ) -> AppResult<Vec<CipherWithAttachmentsRow>> {
        let sql = Self::cipher_row_sql(
            include_attachments,
            "WHERE c.user_id = ?1 AND (?2 = 1 OR c.cipher_type != 5)",
            if newest_first {
                "ORDER BY c.updated_at DESC"
            } else {
                ""
            },
        );
        let result = db
            .prepare(sql)
            .bind(&[user_id.into(), i32::from(include_ssh_keys).into()])?
            .all()
            .await?;
        db::decode_results(&result)
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
                        'cipher_id', a.cipher_id,
                        'file_name', a.file_name,
                        'file_size_bytes', a.file_size_bytes,
                        'encrypted_key', a.encrypted_key,
                        'created_at', a.created_at,
                        'updated_at', a.updated_at,
                        'organization_id', a.organization_id,
                        'storage_key', a.storage_key
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

    pub(crate) async fn fetch_selected(
        db: &D1Database,
        user_id: &str,
        ids_json: &str,
    ) -> AppResult<Vec<Self>> {
        let result = db
            .prepare(
                "SELECT * FROM ciphers WHERE user_id=?1 AND id IN(SELECT \
                 value FROM json_each(?2))",
            )
            .bind(&[user_id.into(), ids_json.into()])?
            .all()
            .await?;
        crate::infra::db::decode_results(&result)
    }

    pub(crate) fn save_statement(
        db: &D1Database,
        row: &Self,
        update: bool,
    ) -> AppResult<D1PreparedStatement> {
        if update {
            Ok(db
                .prepare(
                    "UPDATE ciphers SET \
                     cipher_type=?1,data=?2,is_favorite=?3,folder_id=?4,\
                     archived_at=?5,updated_at=?6 WHERE id=?7 AND user_id=?8",
                )
                .bind(&[
                    row.cipher_type.into(),
                    row.data.clone().into(),
                    row.is_favorite.into(),
                    optional(row.folder_id.as_deref()),
                    optional(row.archived_at.as_deref()),
                    row.updated_at.clone().into(),
                    row.id.clone().into(),
                    row.user_id.clone().into(),
                ])?)
        } else {
            Ok(db
                .prepare(
                    "INSERT INTO \
                     ciphers(id,user_id,organization_id,cipher_type,data,\
                     is_favorite,folder_id,archived_at,created_at,updated_at) \
                     VALUES(?1,?2,NULL,?3,?4,?5,?6,?7,?8,?8)",
                )
                .bind(&[
                    row.id.clone().into(),
                    row.user_id.clone().into(),
                    row.cipher_type.into(),
                    row.data.clone().into(),
                    row.is_favorite.into(),
                    optional(row.folder_id.as_deref()),
                    optional(row.archived_at.as_deref()),
                    row.updated_at.clone().into(),
                ])?)
        }
    }

    pub(crate) fn partial_statement(
        db: &D1Database,
        user_id: &str,
        cipher_id: &str,
        folder_id: Option<&str>,
        is_favorite: bool,
        now: &str,
    ) -> AppResult<D1PreparedStatement> {
        Ok(db
            .prepare(
                "UPDATE ciphers SET folder_id=?1,is_favorite=?2,updated_at=?3 \
                 WHERE id=?4 AND user_id=?5",
            )
            .bind(&[
                optional(folder_id),
                is_favorite.into(),
                now.into(),
                cipher_id.into(),
                user_id.into(),
            ])?)
    }

    pub(crate) async fn purge_statements(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<(D1PreparedStatement, Vec<D1PreparedStatement>)> {
        let revision: String = db
            .prepare("SELECT updated_at FROM users WHERE id=?1")
            .bind(&[user_id.into()])?
            .first(Some("updated_at"))
            .await?
            .ok_or(AppError::Internal)?;
        let snapshot = guard(
            db,
            "EXISTS(SELECT 1 FROM users WHERE id=?1 AND updated_at IS ?2)",
            &[user_id.into(), revision.into()],
        )?;
        let writes = vec![
            db.prepare("DELETE FROM ciphers WHERE user_id=?1")
                .bind(&[user_id.into()])?,
            db.prepare("DELETE FROM folders WHERE user_id=?1")
                .bind(&[user_id.into()])?,
        ];
        Ok((snapshot, writes))
    }

    pub async fn delete_ciphers_before(
        db: &D1Database,
        cutoff: &str,
        now: &str,
    ) -> AppResult<u32> {
        let statements = vec![
            query!(
                db,
                format!(
                    "UPDATE users SET updated_at = {NEXT_USER_REVISION_SQL} \
                     WHERE id IN (SELECT user_id FROM ciphers WHERE \
                     deleted_at IS NOT NULL AND julianday(deleted_at) < \
                     julianday(?2))"
                ),
                now,
                cutoff
            )?,
            query!(
                db,
                "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND \
                 julianday(deleted_at) < julianday(?1)",
                cutoff
            )?,
        ];

        batch_count_last_write(
            db,
            statements,
            "Failed to purge ciphers and update user revisions",
        )
        .await
    }
}

fn optional(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}

#[derive(PartialEq)]
pub(crate) enum CipherMutation {
    SoftDelete,
    Restore,
    HardDelete,
    Move { folder_id: Option<String> },
    Archive,
    Unarchive,
}

pub(crate) fn selected_snapshot_guards(
    db: &D1Database,
    user_id: &str,
    rows: &[CipherRow],
) -> AppResult<Vec<D1PreparedStatement>> {
    let mut guards = Vec::new();
    let mut snapshots = Vec::new();
    let mut bytes = 2;
    let flush = |snapshots: &mut Vec<String>,
                 guards: &mut Vec<D1PreparedStatement>|
     -> AppResult<()> {
        if snapshots.is_empty() {
            return Ok(());
        }
        let encoded = format!("[{}]", snapshots.join(","));
        guards.push(guard(
            db,
            "(SELECT COUNT(*) FROM ciphers c JOIN json_each(?2) s ON \
             c.id=json_extract(s.value,'$.id') WHERE c.user_id=?1 AND \
             c.organization_id IS json_extract(s.value,'$.organization_id') \
             AND c.cipher_type IS json_extract(s.value,'$.cipher_type') AND \
             c.data IS json_extract(s.value,'$.data') AND c.is_favorite IS \
             json_extract(s.value,'$.is_favorite') AND c.folder_id IS \
             json_extract(s.value,'$.folder_id') AND c.deleted_at IS \
             json_extract(s.value,'$.deleted_at') AND c.archived_at IS \
             json_extract(s.value,'$.archived_at') AND c.created_at IS \
             json_extract(s.value,'$.created_at') AND c.updated_at IS \
             json_extract(s.value,'$.updated_at'))=json_array_length(?2)",
            &[user_id.into(), encoded.into()],
        )?);
        snapshots.clear();
        Ok(())
    };
    for row in rows {
        let encoded =
            serde_json::to_string(row).map_err(AppError::internal_error)?;
        let size = encoded.len();
        if size > 1_900_000 {
            guards.push(cipher_snapshot_guard(db, row)?);
            continue;
        }
        if snapshots.len() >= 200 || bytes + size + 1 > 1_900_000 {
            flush(&mut snapshots, &mut guards)?;
            bytes = 2;
        }
        snapshots.push(encoded);
        bytes += size + 1;
    }
    flush(&mut snapshots, &mut guards)?;
    Ok(guards)
}

pub(crate) fn selected_mutation(
    db: &D1Database,
    user_id: &str,
    ids_json: &str,
    kind: &CipherMutation,
    now: &str,
) -> AppResult<D1PreparedStatement> {
    let suffix = " WHERE user_id=?1 AND id IN(SELECT value FROM json_each(?2))";
    let query = match kind {
        CipherMutation::SoftDelete => {
            format!("UPDATE ciphers SET deleted_at=?3,updated_at=?3{suffix}")
        }
        CipherMutation::Restore => {
            format!("UPDATE ciphers SET deleted_at=NULL,updated_at=?3{suffix}")
        }
        CipherMutation::Archive => {
            format!("UPDATE ciphers SET archived_at=?3,updated_at=?3{suffix}")
        }
        CipherMutation::Unarchive => {
            format!("UPDATE ciphers SET archived_at=NULL,updated_at=?3{suffix}")
        }
        CipherMutation::Move { .. } => {
            format!("UPDATE ciphers SET folder_id=?4,updated_at=?3{suffix}")
        }
        CipherMutation::HardDelete => {
            format!("DELETE FROM ciphers{suffix}")
        }
    };
    let mut values = vec![user_id.into(), ids_json.into()];
    if kind != &CipherMutation::HardDelete {
        values.push(now.into());
    }
    if let CipherMutation::Move { folder_id } = kind {
        values.push(optional(folder_id.as_deref()));
    }
    Ok(db.prepare(query).bind(&values)?)
}
