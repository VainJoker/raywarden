//! Persisted Send rows, SQL and the assertions used to commit their changes.
use serde::{Deserialize, Serialize};
use worker::{D1Database, D1PreparedStatement, query};

use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
    models::{
        mutation::{NEXT_USER_REVISION_SQL, RevisionRow},
        page::{Page, PageCursor, PageOrder, PageQuery},
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SendRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub notes: Option<String>,
    pub send_type: i32,
    pub data: String,
    pub encrypted_key: String,
    pub password_hash: Option<String>,
    pub password_salt: Option<String>,
    pub password_iterations: Option<i32>,
    pub max_access_count: Option<i64>,
    pub access_count: i64,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    pub deletes_at: String,
    pub is_disabled: i32,
    pub is_email_hidden: i32,
    pub access_stamp: String,
    pub file_id: Option<String>,
    pub file_size_bytes: i64,
    pub upload_state: i32,
    #[serde(default)]
    pub storage_key: Option<String>,
}

impl SendRow {
    pub(crate) async fn fetch_by_id(db: &D1Database, id: &str) -> AppResult<Self> {
        db::run_query(
            async {
                query!(db, "SELECT * FROM sends WHERE id = ?1", id)?
                    .first(None)
                    .await
            },
            "Failed to fetch Send",
        )
        .await?
        .ok_or_else(AppError::send_unavailable)
    }

    pub(crate) async fn fetch_for_user(db: &D1Database, id: &str, user: &str) -> AppResult<Self> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM sends WHERE id = ?1 AND user_id = ?2 AND \
                     upload_state = 0",
                    id,
                    user
                )?
                .first(None)
                .await
            },
            "Failed to fetch user Send",
        )
        .await?
        .ok_or_else(AppError::send_unavailable)
    }

    pub(crate) async fn list_page(
        db: &D1Database,
        user: &str,
        after: Option<&PageCursor>,
    ) -> AppResult<Page<Self>> {
        PageQuery {
            table: "sends",
            filter: "user_id=? AND upload_state=0",
            text_columns: &[
                "id",
                "user_id",
                "name",
                "notes",
                "data",
                "encrypted_key",
                "password_hash",
                "password_salt",
                "created_at",
                "updated_at",
                "expires_at",
                "deletes_at",
                "access_stamp",
                "file_id",
                "storage_key",
            ],
            order: PageOrder::CreatedFirst,
            related_bytes: None,
        }
        .fetch(db, &db::d1_params![user], after)
        .await
    }

    pub(crate) fn insert_statement(&self, db: &D1Database) -> AppResult<D1PreparedStatement> {
        Ok(query!(
            db,
            "INSERT INTO sends \
             (id,user_id,name,notes,send_type,data,encrypted_key,\
             password_hash,password_salt,password_iterations,max_access_count,\
             access_count,created_at,updated_at,expires_at,deletes_at,\
             is_disabled,is_email_hidden,access_stamp,file_id,file_size_bytes,\
             upload_state) VALUES \
             (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?\
             19,?20,?21,?22)",
            self.id,
            self.user_id,
            self.name,
            self.notes,
            self.send_type,
            self.data,
            self.encrypted_key,
            self.password_hash,
            self.password_salt,
            self.password_iterations,
            self.max_access_count,
            self.access_count,
            self.created_at,
            self.updated_at,
            self.expires_at,
            self.deletes_at,
            self.is_disabled,
            self.is_email_hidden,
            self.access_stamp,
            self.file_id,
            self.file_size_bytes,
            self.upload_state
        )?)
    }

    const fn snapshot_columns() -> &'static [&'static str; 23] {
        &[
            "id",
            "user_id",
            "name",
            "notes",
            "send_type",
            "data",
            "encrypted_key",
            "password_hash",
            "password_salt",
            "password_iterations",
            "max_access_count",
            "access_count",
            "created_at",
            "updated_at",
            "expires_at",
            "deletes_at",
            "is_disabled",
            "is_email_hidden",
            "access_stamp",
            "file_id",
            "file_size_bytes",
            "upload_state",
            "storage_key",
        ]
    }

    pub(crate) fn snapshot_predicate(&self) -> AppResult<(String, [wasm_bindgen::JsValue; 23])> {
        let predicate = Self::snapshot_columns()
            .iter()
            .enumerate()
            .map(|(index, column)| format!("s.{column} IS ?{}", index + 1))
            .collect::<Vec<_>>()
            .join(" AND ");
        // Each field is its own D1 value. Serializing the complete collection
        // (or quoting a large data field a second time) exceeds D1's 2 MB cap.
        let bindings = db::d1_params![
            self.id,
            self.user_id,
            self.name,
            self.notes,
            self.send_type,
            self.data,
            self.encrypted_key,
            self.password_hash,
            self.password_salt,
            self.password_iterations,
            self.max_access_count.map(db::safe_int).transpose()?,
            db::safe_int(self.access_count)?,
            self.created_at,
            self.updated_at,
            self.expires_at,
            self.deletes_at,
            self.is_disabled,
            self.is_email_hidden,
            self.access_stamp,
            self.file_id,
            db::safe_int(self.file_size_bytes)?,
            self.upload_state,
            self.storage_key,
        ];
        Ok((
            format!("EXISTS(SELECT 1 FROM sends s WHERE {predicate})"),
            bindings,
        ))
    }

    pub(crate) fn upload_predicate(&self) -> (&'static str, [wasm_bindgen::JsValue; 8]) {
        // Public access may change count and revision while bytes are in
        // flight. Only bind the encrypted file and pointer fields this upload
        // relies on.
        (
            "EXISTS(SELECT 1 FROM sends WHERE id=?1 AND user_id=?2 AND \
             send_type=1 AND data IS ?3 AND encrypted_key IS ?4 AND file_id \
             IS ?5 AND file_size_bytes IS ?6 AND storage_key IS ?7 AND \
             upload_state IS ?8)",
            db::d1_params![
                self.id,
                self.user_id,
                self.data,
                self.encrypted_key,
                self.file_id,
                self.file_size_bytes as f64,
                self.storage_key,
                self.upload_state,
            ],
        )
    }

    pub(crate) fn finalize_upload_statement(
        &self,
        db: &D1Database,
        size: i64,
        key: &str,
        now: &str,
    ) -> AppResult<D1PreparedStatement> {
        Ok(query!(
            db,
            "UPDATE sends SET \
             upload_state=0,file_size_bytes=?1,storage_key=?2,updated_at=?3 \
             WHERE id=?4 AND user_id=?5",
            size,
            key,
            now,
            self.id,
            self.user_id
        )?)
    }

    pub(crate) fn rotation_statement(
        &self,
        db: &D1Database,
        key: &str,
        now: &str,
        write_token: &str,
    ) -> AppResult<D1PreparedStatement> {
        Ok(query!(
            db,
            "UPDATE sends SET encrypted_key=?1,updated_at=?2,access_stamp=?6 \
             WHERE id=?3 AND user_id=?4 AND EXISTS(SELECT 1 FROM users WHERE \
             id=?4 AND account_write_token=?5)",
            key,
            now,
            self.id,
            self.user_id,
            write_token,
            uuid::Uuid::new_v4().to_string()
        )?)
    }

    pub(crate) fn update_statement(&self, db: &D1Database) -> AppResult<D1PreparedStatement> {
        Ok(query!(
            db,
            "UPDATE sends SET \
             name=?1,notes=?2,data=?3,encrypted_key=?4,password_hash=?5,\
             password_salt=?6,password_iterations=?7,max_access_count=?8,\
             updated_at=?9,expires_at=?10,deletes_at=?11,is_disabled=?12,\
             is_email_hidden=?13,access_stamp=?14 WHERE id=?15 AND \
             user_id=?16 AND upload_state=0",
            self.name,
            self.notes,
            self.data,
            self.encrypted_key,
            self.password_hash,
            self.password_salt,
            self.password_iterations,
            self.max_access_count,
            self.updated_at,
            self.expires_at,
            self.deletes_at,
            self.is_disabled,
            self.is_email_hidden,
            self.access_stamp,
            self.id,
            self.user_id
        )?)
    }

    /// The state predicate and increment execute together to enforce max count
    /// even when several anonymous requests arrive concurrently.
    pub(crate) fn access_count_guard(db: &D1Database) -> D1PreparedStatement {
        let abort = DbSentinel::SendAccessDenied.sql_abort_expr();
        db.prepare(format!(
            "SELECT CASE WHEN changes()=1 THEN 1 ELSE {abort} END"
        ))
    }

    pub(crate) fn revision_statement(
        db: &D1Database,
        user_id: &str,
        now: &str,
    ) -> AppResult<D1PreparedStatement> {
        Ok(query!(
            db,
            format!(
                "UPDATE users SET updated_at = {NEXT_USER_REVISION_SQL} WHERE \
                 id = ?2 RETURNING updated_at"
            ),
            now,
            user_id
        )?)
    }

    pub(crate) async fn advance_revision(&self, db: &D1Database) -> AppResult<String> {
        db::run_query(
            Self::revision_statement(db, &self.user_id, &crate::utils::time::now_rfc3339())?
                .first::<String>(Some("updated_at")),
            "Failed to update Send owner revision",
        )
        .await?
        .ok_or(AppError::Internal)
    }

    pub(crate) async fn consume_access(
        &mut self,
        db: &D1Database,
        file_id: Option<&str>,
    ) -> AppResult<String> {
        #[derive(Deserialize)]
        struct AccessCountRow {
            access_count: i64,
        }

        let now = crate::utils::time::now_rfc3339();
        let increment = query!(
            db,
            "UPDATE sends SET access_count=access_count+1,updated_at=?1 WHERE \
             id=?2 AND access_stamp=?3 AND upload_state=0 AND is_disabled=0 \
             AND julianday(deletes_at)>julianday(?1) AND (expires_at IS NULL \
             OR julianday(expires_at)>julianday(?1)) AND (max_access_count IS \
             NULL OR access_count<max_access_count) AND (?4 IS NULL OR \
             (send_type=1 AND file_id=?4)) RETURNING access_count",
            now,
            self.id,
            self.access_stamp,
            file_id
        )?;
        let results = db
            .batch(vec![
                increment,
                Self::access_count_guard(db),
                Self::revision_statement(db, &self.user_id, &now)?,
            ])
            .await
            .map_err(DatabaseError::send_access)?;
        let [increment, _, revision] = results.as_slice() else {
            return Err(AppError::Internal);
        };
        let count = increment
            .results::<AccessCountRow>()?
            .into_iter()
            .next()
            .ok_or(AppError::Internal)?;
        let revision = revision
            .results::<RevisionRow>()?
            .into_iter()
            .next()
            .ok_or(AppError::Internal)?;
        self.access_count = count.access_count;
        self.updated_at = now;
        Ok(revision.updated_at)
    }

    pub(crate) fn delete_statement(&self, db: &D1Database) -> AppResult<D1PreparedStatement> {
        Ok(query!(
            db,
            "DELETE FROM sends WHERE id=?1 AND user_id=?2",
            self.id,
            self.user_id
        )?)
    }

    pub(crate) async fn cleanup_candidates(
        db: &D1Database,
        now: &str,
        cutoff: &str,
    ) -> AppResult<Vec<Self>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM sends WHERE \
                     julianday(deletes_at)<=julianday(?1) OR (upload_state<>0 \
                     AND julianday(created_at)<=julianday(?2)) ORDER BY rowid \
                     LIMIT 16",
                    now,
                    cutoff
                )?
                .all()
                .await?
                .results()
            },
            "Failed to find expired Sends",
        )
        .await
    }

    pub(crate) async fn delete_expired(
        &self,
        db: &D1Database,
        now: &str,
        cutoff: &str,
    ) -> AppResult<()> {
        let expired = crate::models::mutation::guard(
            db,
            "EXISTS(SELECT 1 FROM sends WHERE id=?1 AND \
             (julianday(deletes_at)<=julianday(?2) OR (upload_state<>0 AND \
             julianday(created_at)<=julianday(?3))))",
            &db::d1_params![self.id, now, cutoff],
        )?;
        db.batch(vec![
            snapshot_guard(db, self)?,
            expired,
            self.delete_statement(db)?,
            Self::revision_statement(db, &self.user_id, now)?,
        ])
        .await?;
        Ok(())
    }

    pub(crate) async fn all_for_user(db: &D1Database, user: &str) -> AppResult<Vec<Self>> {
        PageQuery {
            table: "sends",
            filter: "user_id=?",
            text_columns: &[
                "id",
                "user_id",
                "name",
                "notes",
                "data",
                "encrypted_key",
                "password_hash",
                "password_salt",
                "created_at",
                "updated_at",
                "expires_at",
                "deletes_at",
                "access_stamp",
                "file_id",
                "storage_key",
            ],
            order: PageOrder::RowId,
            related_bytes: None,
        }
        .fetch_all(db, &db::d1_params![user])
        .await
    }

    pub(crate) async fn creator_email(&self, db: &D1Database) -> AppResult<Option<String>> {
        db::run_query(
            async {
                query!(db, "SELECT email FROM users WHERE id=?1", self.user_id)?
                    .first(Some("email"))
                    .await
            },
            "Failed to fetch Send creator",
        )
        .await
    }
}

pub(crate) fn snapshot_guard(db: &D1Database, send: &SendRow) -> AppResult<D1PreparedStatement> {
    let (predicate, bindings) = send.snapshot_predicate()?;
    crate::models::mutation::guard(db, &predicate, &bindings)
}

pub(crate) fn upload_guard(db: &D1Database, send: &SendRow) -> AppResult<D1PreparedStatement> {
    let (predicate, bindings) = send.upload_predicate();
    crate::models::mutation::guard(db, predicate, &bindings)
}

pub(crate) fn collection_guard(
    db: &D1Database,
    owner: &str,
    count: usize,
) -> AppResult<D1PreparedStatement> {
    crate::models::mutation::guard(
        db,
        "(SELECT COUNT(*) FROM sends WHERE user_id=?1)=?2",
        &db::d1_params![owner, count as f64],
    )
}

/// Count pending uploads as soon as their reservation is written.
pub(crate) fn quota_guard(
    db: &D1Database,
    send: &SendRow,
    quota: i64,
) -> AppResult<D1PreparedStatement> {
    crate::models::mutation::guard(
        db,
        "COALESCE((SELECT SUM(file_size_bytes) FROM sends WHERE \
         user_id=?2),0)+?3<=?1",
        &db::d1_params![quota as f64, send.user_id, send.file_size_bytes as f64],
    )
}
