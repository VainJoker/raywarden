//! Persisted folder records and D1 ownership queries.
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
};

use crate::{
    errors::{
        AppResult,
        DatabaseError,
    },
    infra::db,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct FolderRow {
    pub id:         String,
    pub user_id:    String,
    // The name is encrypted client-side
    pub name:       String,
    pub created_at: String,
    pub updated_at: String,
}

impl FolderRow {
    pub async fn list_for_user(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<Vec<Self>> {
        let result = db
            .prepare("SELECT * FROM folders WHERE user_id = ?1")
            .bind(&[user_id.into()])?
            .all()
            .await?;
        db::decode_results(&result)
    }

    pub async fn fetch_for_user(
        db: &D1Database,
        folder_id: &str,
        user_id: &str,
    ) -> AppResult<Self> {
        query!(
            db,
            "SELECT * FROM folders WHERE id = ?1 AND user_id = ?2",
            folder_id,
            user_id
        )
        .map_err(|e| {
            DatabaseError::query(
                "Failed to bind query for getting folder",
                format_args!("{e:?}"),
            )
        })?
        .first(None)
        .await
        .map_err(|e| {
            DatabaseError::query(
                "Failed to execute query for getting folder",
                format_args!("{e:?}"),
            )
        })?
        .ok_or_else(DatabaseError::invalid_folder)
    }

    pub async fn ensure_for_user(
        db: &D1Database,
        folder_id: &str,
        user_id: &str,
    ) -> AppResult<()> {
        let exists: Option<Value> = db
            .prepare("SELECT 1 FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.into(), user_id.into()])
            .map_err(|e| {
                DatabaseError::query("Failed to bind folder ownership query", e)
            })?
            .first(None)
            .await
            .map_err(|e| {
                DatabaseError::query(
                    "Failed to execute folder ownership query",
                    e,
                )
            })?;

        if exists.is_none() {
            return Err(DatabaseError::invalid_folder());
        }

        Ok(())
    }

    pub fn snapshot_guard(
        &self,
        db: &D1Database,
    ) -> AppResult<D1PreparedStatement> {
        crate::models::mutation::guard(
            db,
            "EXISTS(SELECT 1 FROM folders WHERE id=?1 AND user_id=?2 AND name \
             IS ?3 AND created_at IS ?4 AND updated_at IS ?5)",
            &[
                self.id.clone().into(),
                self.user_id.clone().into(),
                self.name.clone().into(),
                self.created_at.clone().into(),
                self.updated_at.clone().into(),
            ],
        )
    }

    pub fn insert_statement(
        &self,
        db: &D1Database,
    ) -> AppResult<D1PreparedStatement> {
        Ok(db
            .prepare(
                "INSERT INTO folders(id,user_id,name,created_at,updated_at) \
                 VALUES(?1,?2,?3,?4,?4)",
            )
            .bind(&[
                self.id.clone().into(),
                self.user_id.clone().into(),
                self.name.clone().into(),
                self.created_at.clone().into(),
            ])?)
    }

    pub fn update_statement(
        &self,
        db: &D1Database,
    ) -> AppResult<D1PreparedStatement> {
        Ok(db
            .prepare(
                "UPDATE folders SET name=?1,updated_at=?2 WHERE id=?3 AND \
                 user_id=?4",
            )
            .bind(&[
                self.name.clone().into(),
                self.updated_at.clone().into(),
                self.id.clone().into(),
                self.user_id.clone().into(),
            ])?)
    }

    pub fn delete_statement(
        db: &D1Database,
        id: &str,
        user_id: &str,
    ) -> AppResult<D1PreparedStatement> {
        Ok(db
            .prepare("DELETE FROM folders WHERE id=?1 AND user_id=?2")
            .bind(&[id.into(), user_id.into()])?)
    }
}
