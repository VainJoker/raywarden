//! Persisted cipher records, D1 queries and guarded mutation statements.
use serde::{Deserialize, Serialize};
use worker::{D1Database, D1PreparedStatement, query};

use crate::{
    errors::{AppError, AppResult, DatabaseError},
    infra::db::{self, IntoD1Param},
    models::{
        mutation::{NEXT_USER_REVISION_SQL, batch_count_last_write, cipher_snapshot_guard, guard},
        page::{Page, PageCursor, PageOrder, PageQuery},
    },
};
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CipherRow {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub cipher_type: i32,
    pub data: String,
    pub is_favorite: i32,
    pub folder_id: Option<String>,
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// Charge attachment metadata in the same budget while fetching it from
// separate rows. The subquery returns only a number, even for a huge set.
const ATTACHMENT_METADATA_BYTES: &str = "SELECT COALESCE(SUM(
        length(CAST(a.file_name AS BLOB)) +
        COALESCE(length(CAST(a.encrypted_key AS BLOB)),0) +
        length(CAST(a.id AS BLOB)) + 128
    ),0)
    FROM attachments a WHERE a.cipher_id=source.id";

impl CipherRow {
    pub async fn fetch_for_user(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
    ) -> AppResult<Self> {
        db.prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
            .bind(&db::d1_params![cipher_id, user_id])
            .map_err(|e| DatabaseError::query("Failed to bind fetch cipher query", &e))?
            .first(None)
            .await
            .map_err(|e| DatabaseError::query("Failed to execute fetch cipher query", &e))?
            .ok_or_else(|| AppError::not_found("Cipher not found"))
    }

    pub(crate) async fn list_page(
        db: &D1Database,
        user_id: &str,
        include_attachments: bool,
        include_ssh_keys: bool,
        newest_first: bool,
        after: Option<&PageCursor>,
    ) -> AppResult<Page<Self>> {
        PageQuery {
            table: "ciphers",
            filter: "user_id=? AND (?=1 OR cipher_type!=5)",
            text_columns: &[
                "id",
                "user_id",
                "organization_id",
                "data",
                "folder_id",
                "deleted_at",
                "archived_at",
                "created_at",
                "updated_at",
            ],
            order: if newest_first {
                PageOrder::NewestFirst
            } else {
                PageOrder::RowId
            },
            related_bytes: include_attachments.then_some(ATTACHMENT_METADATA_BYTES),
        }
        .fetch(
            db,
            &db::d1_params![user_id, i32::from(include_ssh_keys)],
            after,
        )
        .await
    }

    pub(crate) async fn fetch_selected(
        db: &D1Database,
        user_id: &str,
        ids_json: &str,
    ) -> AppResult<Vec<Self>> {
        PageQuery {
            table: "ciphers",
            filter: "user_id=? AND id IN (SELECT value FROM json_each(?))",
            text_columns: &[
                "id",
                "user_id",
                "organization_id",
                "data",
                "folder_id",
                "deleted_at",
                "archived_at",
                "created_at",
                "updated_at",
            ],
            order: PageOrder::RowId,
            related_bytes: None,
        }
        .fetch_all(db, &db::d1_params![user_id, ids_json])
        .await
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
                .bind(&db::d1_params![
                    row.cipher_type,
                    row.data,
                    row.is_favorite,
                    row.folder_id,
                    row.archived_at,
                    row.updated_at,
                    row.id,
                    row.user_id,
                ])?)
        } else {
            Ok(db
                .prepare(
                    "INSERT INTO \
                     ciphers(id,user_id,organization_id,cipher_type,data,\
                     is_favorite,folder_id,archived_at,created_at,updated_at) \
                     VALUES(?1,?2,NULL,?3,?4,?5,?6,?7,?8,?8)",
                )
                .bind(&db::d1_params![
                    row.id,
                    row.user_id,
                    row.cipher_type,
                    row.data,
                    row.is_favorite,
                    row.folder_id,
                    row.archived_at,
                    row.updated_at,
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
            .bind(&db::d1_params![
                folder_id,
                is_favorite,
                now,
                cipher_id,
                user_id,
            ])?)
    }

    pub(crate) async fn purge_statements(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<(D1PreparedStatement, Vec<D1PreparedStatement>)> {
        let revision: String = db
            .prepare("SELECT updated_at FROM users WHERE id=?1")
            .bind(&db::d1_params![user_id])?
            .first(Some("updated_at"))
            .await?
            .ok_or(AppError::Internal)?;
        let snapshot = guard(
            db,
            "EXISTS(SELECT 1 FROM users WHERE id=?1 AND updated_at IS ?2)",
            &db::d1_params![user_id, revision],
        )?;
        let writes = vec![
            db.prepare("DELETE FROM ciphers WHERE user_id=?1")
                .bind(&db::d1_params![user_id])?,
            db.prepare("DELETE FROM folders WHERE user_id=?1")
                .bind(&db::d1_params![user_id])?,
        ];
        Ok((snapshot, writes))
    }

    pub async fn delete_ciphers_before(db: &D1Database, cutoff: &str, now: &str) -> AppResult<u32> {
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

#[derive(PartialEq)]
pub(crate) enum CipherMutation {
    SoftDelete,
    Restore,
    HardDelete,
    Move { folder_id: Option<String> },
    Archive,
    Unarchive,
}

const SNAPSHOT_GROUP_BYTES: usize = 1_900_000;
const SNAPSHOT_GROUP_ROWS: usize = 200;

struct SnapshotGroup {
    json: String,
    rows: usize,
}

impl SnapshotGroup {
    fn new() -> Self {
        Self {
            json: String::from("["),
            rows: 0,
        }
    }

    fn push(&mut self, row: &str) -> Option<String> {
        // Reserve the closing bracket and one separator for the incoming row.
        let completed = if self.rows >= SNAPSHOT_GROUP_ROWS
            || self.json.len() + row.len() + 2 > SNAPSHOT_GROUP_BYTES
        {
            self.take()
        } else {
            None
        };
        self.json.push_str(row);
        self.json.push(',');
        self.rows += 1;
        completed
    }

    fn take(&mut self) -> Option<String> {
        if self.rows == 0 {
            return None;
        }
        self.rows = 0;
        self.json.pop();
        self.json.push(']');
        Some(std::mem::replace(&mut self.json, String::from("[")))
    }
}

pub(crate) fn selected_snapshot_guards(
    db: &D1Database,
    user_id: &str,
    rows: &[CipherRow],
) -> AppResult<Vec<D1PreparedStatement>> {
    let mut guards = Vec::new();
    let mut group = SnapshotGroup::new();
    let group_guard = |encoded: &str| {
        guard(
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
            &db::d1_params![user_id, encoded],
        )
    };
    for row in rows {
        let encoded = serde_json::to_string(row).map_err(AppError::internal_error)?;
        if encoded.len() > SNAPSHOT_GROUP_BYTES {
            guards.push(cipher_snapshot_guard(db, row)?);
            continue;
        }
        if let Some(completed) = group.push(&encoded) {
            guards.push(group_guard(&completed)?);
        }
    }
    if let Some(last) = group.take() {
        guards.push(group_guard(&last)?);
    }
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
        values.push(folder_id.to_d1_param());
    }
    Ok(db.prepare(query).bind(&values)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_groups_respect_row_and_byte_limits() {
        let mut group = SnapshotGroup::new();
        for _ in 0..SNAPSHOT_GROUP_ROWS {
            assert!(group.push("0").is_none());
        }
        let group_json = group.push("1").expect("full row group");
        let group_rows: Vec<i32> = serde_json::from_str(&group_json).expect("valid snapshot array");
        assert_eq!(group_rows, vec![0; SNAPSHOT_GROUP_ROWS]);
        assert_eq!(group.take().as_deref(), Some("[1]"));

        let row = format!("\"{}\"", "x".repeat(SNAPSHOT_GROUP_BYTES - 7));
        assert!(group.push(&row).is_none());
        assert!(group.push("0").is_none());
        assert!(group.push("1").is_some());
        assert_eq!(group.take().as_deref(), Some("[1]"));
    }
}
