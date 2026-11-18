//! Concrete Send SQL, row snapshots and atomic access-count updates.
use jiff::SignedDuration;
use serde::Serialize as _;
use serde_json::Value;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
};

use super::types::{
    SendDB,
    inaccessible,
    now_string,
};
use crate::{
    errors::AppError,
    infra::db,
};

impl SendDB {
    pub(super) async fn find_by_id(
        db: &D1Database,
        id: &str,
    ) -> Result<Self, AppError> {
        db::run_query(
            async {
                query!(db, "SELECT * FROM sends WHERE id = ?1", id)?
                    .first(None)
                    .await
            },
            "Failed to fetch Send",
        )
        .await?
        .ok_or_else(inaccessible)
    }

    pub(super) async fn get_for_user(
        db: &D1Database,
        id: &str,
        user: &str,
    ) -> Result<Self, AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM sends WHERE id = ?1 AND user_id = ?2 AND \
                     pending = 0",
                    id,
                    user
                )?
                .first(None)
                .await
            },
            "Failed to fetch user Send",
        )
        .await?
        .ok_or_else(inaccessible)
    }

    pub(super) async fn list_for_user(
        db: &D1Database,
        user: &str,
    ) -> Result<Vec<Self>, AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM sends WHERE user_id = ?1 AND pending = 0 \
                     ORDER BY created_at",
                    user
                )?
                .all()
                .await?
                .results()
            },
            "Failed to list Sends",
        )
        .await
    }

    /// A single INSERT reserves file quota, including all in-flight uploads.
    pub(super) fn insert_statement(
        &self,
        db: &D1Database,
        quota: Option<i64>,
    ) -> Result<D1PreparedStatement, AppError> {
        Ok(query!(
            db,
            "INSERT INTO sends \
             (id,user_id,name,notes,type,data,akey,password_hash,\
             password_salt,password_iter,max_access_count,access_count,\
             created_at,updated_at,expiration_date,deletion_date,disabled,\
             hide_email,access_stamp,file_id,file_size,pending)
                 SELECT \
             ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?\
             19,?20,?21,?22
                 WHERE ?23 IS NULL OR COALESCE((SELECT SUM(file_size) FROM \
             sends WHERE user_id = ?2),0) + ?21 <= ?23 RETURNING id",
            self.id,
            self.user_id,
            self.name,
            self.notes,
            self.send_type,
            self.data,
            self.akey,
            self.password_hash,
            self.password_salt,
            self.password_iter,
            self.max_access_count,
            self.access_count,
            self.created_at,
            self.updated_at,
            self.expiration_date,
            self.deletion_date,
            self.disabled,
            self.hide_email,
            self.access_stamp,
            self.file_id,
            self.file_size,
            self.pending,
            quota
        )?)
    }

    fn snapshot_columns() -> &'static [&'static str] {
        &[
            "id",
            "user_id",
            "name",
            "notes",
            "type",
            "data",
            "akey",
            "password_hash",
            "password_salt",
            "password_iter",
            "max_access_count",
            "access_count",
            "created_at",
            "updated_at",
            "expiration_date",
            "deletion_date",
            "disabled",
            "hide_email",
            "access_stamp",
            "file_id",
            "file_size",
            "pending",
            "storage_key",
        ]
    }

    pub(super) fn snapshot_predicate(
        &self,
    ) -> Result<(String, Vec<wasm_bindgen::JsValue>), AppError> {
        let predicate = Self::snapshot_columns()
            .iter()
            .enumerate()
            .map(|(index, column)| format!("s.{column} IS ?{}", index + 1))
            .collect::<Vec<_>>()
            .join(" AND ");
        // Each field is its own D1 value. Serializing the complete collection
        // (or quoting a large data field a second time) exceeds D1's 2 MB cap.
        let row = serde_json::to_value(self).map_err(|_| AppError::Internal)?;
        let serializer = worker::d1::serde_wasm_bindgen::Serializer::new()
            .serialize_missing_as_null(true);
        let bindings = Self::snapshot_columns()
            .iter()
            .map(|column| {
                row[*column]
                    .serialize(&serializer)
                    .map_err(|_| AppError::Internal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            format!("EXISTS(SELECT 1 FROM sends s WHERE {predicate})"),
            bindings,
        ))
    }

    pub(super) fn upload_predicate(
        &self,
    ) -> (&'static str, [wasm_bindgen::JsValue; 8]) {
        // Public access may change count and revision while bytes are in
        // flight. Only bind the encrypted file and pointer fields this upload
        // relies on.
        (
            "EXISTS(SELECT 1 FROM sends WHERE id=?1 AND user_id=?2 AND type=1 \
             AND data IS ?3 AND akey IS ?4 AND file_id IS ?5 AND file_size IS \
             ?6 AND storage_key IS ?7 AND pending IS ?8)",
            [
                self.id.clone().into(),
                self.user_id.clone().into(),
                self.data.clone().into(),
                self.akey.clone().into(),
                self.file_id
                    .clone()
                    .map(Into::into)
                    .unwrap_or(wasm_bindgen::JsValue::NULL),
                (self.file_size as f64).into(),
                self.storage_key
                    .clone()
                    .map(Into::into)
                    .unwrap_or(wasm_bindgen::JsValue::NULL),
                self.pending.into(),
            ],
        )
    }

    pub(super) fn finalize_upload_statement(
        &self,
        db: &D1Database,
        size: i64,
        key: &str,
        now: &str,
    ) -> Result<D1PreparedStatement, AppError> {
        Ok(query!(
            db,
            "UPDATE sends SET \
             pending=0,file_size=?1,storage_key=?2,updated_at=?3 WHERE id=?4 \
             AND user_id=?5",
            size,
            key,
            now,
            self.id,
            self.user_id
        )?)
    }

    pub(super) fn rotation_statement(
        &self,
        db: &D1Database,
        key: &str,
        now: &str,
        write_token: &str,
    ) -> Result<D1PreparedStatement, AppError> {
        Ok(query!(
            db,
            "UPDATE sends SET akey=?1,updated_at=?2,access_stamp=?6 WHERE \
             id=?3 AND user_id=?4 AND EXISTS(SELECT 1 FROM users WHERE id=?4 \
             AND account_write_token=?5)",
            key,
            now,
            self.id,
            self.user_id,
            write_token,
            uuid::Uuid::new_v4().to_string()
        )?)
    }

    pub(super) async fn delete_pending(
        &self,
        db: &D1Database,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM sends WHERE id=?1 AND user_id=?2 AND \
                     pending<>0",
                    self.id,
                    self.user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to remove pending Send",
        )
        .await
    }

    pub(super) fn update_statement(
        &self,
        db: &D1Database,
    ) -> Result<D1PreparedStatement, AppError> {
        Ok(query!(
            db,
            "UPDATE sends SET \
             name=?1,notes=?2,data=?3,akey=?4,password_hash=?5,password_salt=?\
             6,password_iter=?7,max_access_count=?8,updated_at=?9,\
             expiration_date=?10,deletion_date=?11,disabled=?12,hide_email=?\
             13,access_stamp=?14 WHERE id=?15 AND user_id=?16 AND pending=0",
            self.name,
            self.notes,
            self.data,
            self.akey,
            self.password_hash,
            self.password_salt,
            self.password_iter,
            self.max_access_count,
            self.updated_at,
            self.expiration_date,
            self.deletion_date,
            self.disabled,
            self.hide_email,
            self.access_stamp,
            self.id,
            self.user_id
        )?)
    }

    /// The state predicate and increment execute together to enforce max count
    /// even when several anonymous requests arrive concurrently.
    pub(super) fn access_count_guard(db: &D1Database) -> D1PreparedStatement {
        db.prepare(
            "SELECT CASE WHEN changes()=1 THEN 1 ELSE \
             json_extract('[]','RW_SEND_ACCESS_DENIED') END",
        )
    }

    pub(super) fn revision_statement(
        db: &D1Database,
        user_id: &str,
        now: &str,
    ) -> Result<D1PreparedStatement, AppError> {
        Ok(query!(
            db,
            "UPDATE users SET updated_at=CASE WHEN \
             julianday(updated_at)>=julianday(?1) THEN \
             strftime('%Y-%m-%dT%H:%M:%fZ',julianday(updated_at)+1.0/\
             86400000) ELSE ?1 END WHERE id=?2 RETURNING updated_at",
            now,
            user_id
        )?)
    }

    pub(super) async fn advance_revision(
        &self,
        db: &D1Database,
    ) -> Result<String, AppError> {
        db::run_query(
            Self::revision_statement(db, &self.user_id, &now_string())?
                .first::<String>(Some("updated_at")),
            "Failed to update Send owner revision",
        )
        .await?
        .ok_or(AppError::Internal)
    }

    pub(super) async fn consume_access(
        &mut self,
        db: &D1Database,
        file_id: Option<&str>,
    ) -> Result<(), AppError> {
        let now = now_string();
        let increment = query!(
            db,
            "UPDATE sends SET access_count=access_count+1,updated_at=?1 WHERE \
             id=?2 AND access_stamp=?3 AND pending=0 AND disabled=0 AND \
             julianday(deletion_date)>julianday(?1) AND (expiration_date IS \
             NULL OR julianday(expiration_date)>julianday(?1)) AND \
             (max_access_count IS NULL OR access_count<max_access_count) AND \
             (?4 IS NULL OR (type=1 AND file_id=?4)) RETURNING access_count",
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
            .map_err(|error| {
                if error.to_string().contains("RW_SEND_ACCESS_DENIED") {
                    inaccessible()
                } else {
                    AppError::from(error)
                }
            })?;
        self.access_count = results[0]
            .results::<Value>()?
            .first()
            .and_then(|row| row.get("access_count"))
            .and_then(Value::as_i64)
            .ok_or(AppError::Internal)?;
        self.updated_at = now;
        Ok(())
    }

    pub(super) fn delete_statement(
        &self,
        db: &D1Database,
    ) -> Result<D1PreparedStatement, AppError> {
        Ok(query!(
            db,
            "DELETE FROM sends WHERE id=?1 AND user_id=?2",
            self.id,
            self.user_id
        )?)
    }

    pub(super) async fn cleanup_candidates(
        db: &D1Database,
    ) -> Result<Vec<Self>, AppError> {
        let now = now_string();
        let cutoff = crate::infra::time::format_millis(
            crate::infra::time::now()
                .checked_sub(SignedDuration::from_secs(86_400))
                .map_err(|_| AppError::Internal)?,
        );
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM sends WHERE \
                     julianday(deletion_date)<=julianday(?1) OR (pending<>0 \
                     AND julianday(created_at)<=julianday(?2))",
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

    pub(super) async fn all_for_user(
        db: &D1Database,
        user: &str,
    ) -> Result<Vec<Self>, AppError> {
        db::run_query(
            async {
                query!(db, "SELECT * FROM sends WHERE user_id=?1", user)?
                    .all()
                    .await?
                    .results()
            },
            "Failed to list all user Sends",
        )
        .await
    }
}
