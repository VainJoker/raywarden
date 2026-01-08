use log::error;
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
        AppError,
        DatabaseError,
    },
    infra::DB,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct FolderDB {
    pub id:         String,
    pub user_id:    String,
    // The name is encrypted client-side
    pub name:       String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderResponse {
    pub id:            String,
    pub name:          String,
    pub revision_date: String,
    #[serde(default = "default_object")]
    pub object:        String,
}

fn default_object() -> String {
    "folder".to_string()
}

impl From<FolderDB> for FolderResponse {
    fn from(folder: FolderDB) -> Self {
        Self {
            id:            folder.id,
            name:          folder.name,
            revision_date: folder.updated_at,
            object:        default_object(),
        }
    }
}

impl FolderDB {
    pub async fn list_for_user(
        db: &D1Database,
        user_id: &str,
    ) -> Result<Vec<Self>, AppError> {
        db.prepare("SELECT * FROM folders WHERE user_id = ?1")
            .bind(&[user_id.into()])
            .map_err(|e| {
                error!("Failed to bind query for listing folders: {e:?}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to bind query for listing folders".to_string(),
                ))
            })?
            .all()
            .await
            .map_err(|e| {
                error!("Failed to execute query for listing folders: {e:?}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to execute query for listing folders".to_string(),
                ))
            })?
            .results()
            .map_err(|e| {
                error!(
                    "Failed to parse query results for listing folders: {e:?}"
                );
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to parse query results for listing folders"
                        .to_string(),
                ))
            })
    }

    pub async fn get_for_user(
        db: &D1Database,
        folder_id: &str,
        user_id: &str,
    ) -> Result<Self, AppError> {
        query!(
            db,
            "SELECT * FROM folders WHERE id = ?1 AND user_id = ?2",
            folder_id,
            user_id
        )
        .map_err(|e| {
            error!("Failed to bind query for getting folder: {e:?}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to bind query for getting folder".to_string(),
            ))
        })?
        .first(None)
        .await
        .map_err(|e| {
            error!("Failed to execute query for getting folder: {e:?}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to execute query for getting folder".to_string(),
            ))
        })?
        .ok_or_else(|| {
            AppError::Params(
                "Invalid folder: Folder does not exist or belongs to another \
                 user"
                    .to_string(),
            )
        })
    }

    pub async fn ensure_for_user(
        db: &D1Database,
        folder_id: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        let exists: Option<Value> = db
            .prepare("SELECT 1 FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.into(), user_id.into()])
            .map_err(|e| {
                error!("Failed to bind folder ownership query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to validate folder".to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| {
                error!("Failed to execute folder ownership query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to validate folder".to_string(),
                ))
            })?;

        if exists.is_none() {
            return Err(AppError::Params(
                "Invalid folder: Folder does not exist or belongs to another \
                 user"
                    .to_string(),
            ));
        }

        Ok(())
    }

    pub async fn ensure_json_folder_exists(
        db: &D1Database,
        raw_body: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        let folder_invalid: Option<Value> = db
            .prepare(
                "SELECT 1 WHERE json_extract(?1, '$.folderId') IS NOT NULL \
                 AND NOT EXISTS (
                     SELECT 1 FROM folders WHERE id = json_extract(?1, \
                 '$.folderId') AND user_id = ?2
                 )",
            )
            .bind(&[raw_body.to_string().into(), user_id.into()])?
            .first(None)
            .await
            .map_err(|e| {
                AppError::Database(DatabaseError::QueryFailed(e.to_string()))
            })?;

        if folder_invalid.is_some() {
            return Err(AppError::Params(
                "Invalid folder: Folder does not exist or belongs to another \
                 user"
                    .to_string(),
            ));
        }

        Ok(())
    }

    pub async fn insert(
        db: &D1Database,
        folder: &Self,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO folders (id, user_id, name, created_at, \
                     updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    folder.id,
                    folder.user_id,
                    folder.name,
                    folder.created_at,
                    folder.updated_at
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to create folder",
        )
        .await
    }

    pub async fn insert_batch(
        db: &D1Database,
        folders: &[Self],
        batch_size: usize,
    ) -> Result<(), AppError> {
        if folders.is_empty() {
            return Ok(());
        }

        let mut statements: Vec<D1PreparedStatement> =
            Vec::with_capacity(folders.len());

        for folder in folders {
            let stmt = query!(
                db,
                "INSERT INTO folders (id, user_id, name, created_at, \
                 updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                folder.id,
                folder.user_id,
                folder.name,
                folder.created_at,
                folder.updated_at
            )
            .map_err(|e| {
                error!("Failed to prepare folder insert: {e:?}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to create folder".to_string(),
                ))
            })?;

            statements.push(stmt);
        }

        if batch_size == 0 {
            DB::run_query(
                async { db.batch(statements).await.map(|_| ()) },
                "Failed to create folder batch",
            )
            .await
        } else {
            for chunk in statements.chunks(batch_size) {
                DB::run_query(
                    async { db.batch(chunk.to_vec()).await.map(|_| ()) },
                    "Failed to create folder batch",
                )
                .await?;
            }

            Ok(())
        }
    }

    pub async fn update_for_user(
        db: &D1Database,
        folder: &Self,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = \
                     ?3 AND user_id = ?4",
                    folder.name,
                    folder.updated_at,
                    folder.id,
                    folder.user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update folder",
        )
        .await
    }

    pub async fn delete_for_user(
        db: &D1Database,
        folder_id: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM folders WHERE id = ?1 AND user_id = ?2",
                    folder_id,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to delete folder",
        )
        .await
    }

    pub async fn purge_user_folders(
        db: &D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(db, "DELETE FROM folders WHERE user_id = ?1", user_id)?
                    .run()
                    .await
                    .map(|_| ())
            },
            "Failed to purge folders",
        )
        .await
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateFolderRequest {
    pub name: String,
}
