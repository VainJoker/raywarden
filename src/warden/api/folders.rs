use axum::{
    Json,
    extract::{
        Path,
        State,
    },
};
use chrono::Utc;
use serde_json::{
    Value,
    json,
};
use uuid::Uuid;
use worker::query;

use crate::{
    errors::AppError,
    models::folder::{
        CreateFolderRequest,
        Folder,
        FolderResponse,
    },
    warden::{
        AppState,
        service::claims::Claims,
    },
};

#[worker::send]
pub async fn list_folders(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();

    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .all()
        .await?
        .results()
        .map_err(|e| {
            log::error!("DB error (folders::list_folders): {e:?}");
            AppError::Database
        })?;

    let folders: Vec<FolderResponse> = folders_db
        .into_iter()
        .map(std::convert::Into::into)
        .collect();

    Ok(Json(json!({
        "data": folders,
        "object": "list",
        "continuationToken": null,
    })))
}

#[worker::send]
pub async fn get_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = state.get_db();

    let folder: Folder = query!(
        &db,
        "SELECT * FROM folders WHERE id = ?1 AND user_id = ?2",
        &id,
        &claims.sub
    )
    .map_err(|e| {
        log::error!("DB error (folders::list_folders): {e:?}");
        AppError::Database
    })?
    .first(None)
    .await?
    .ok_or_else(|| {
        AppError::BadRequest(
            "Invalid folder: Folder does not exist or belongs to another user"
                .to_string(),
        )
    })?;

    Ok(Json(folder.into()))
}

#[worker::send]
pub async fn create_folder(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = state.get_db();
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let folder = Folder {
        id:         Uuid::new_v4().to_string(),
        user_id:    claims.sub.clone(),
        name:       payload.name,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    query!(
        &db,
        "INSERT INTO folders (id, user_id, name, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        folder.id,
        folder.user_id,
        folder.name,
        folder.created_at,
        folder.updated_at
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    query!(
        &db,
        "UPDATE users SET updated_at = ?1 WHERE id = ?2",
        now,
        &claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let response = FolderResponse {
        id:            folder.id,
        name:          folder.name,
        revision_date: folder.updated_at,
        object:        "folder".to_string(),
    };

    Ok(Json(response))
}

#[worker::send]
pub async fn delete_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = state.get_db();

    query!(
        &db,
        "DELETE FROM folders WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    query!(
        &db,
        "UPDATE users SET updated_at = ?1 WHERE id = ?2",
        now,
        &claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(()))
}
#[worker::send]
pub async fn update_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = state.get_db();
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing_folder: Folder = query!(
        &db,
        "SELECT * FROM folders WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Folder not found".to_string()))?;

    let folder = Folder {
        id:         id.clone(),
        user_id:    existing_folder.user_id,
        name:       payload.name,
        created_at: existing_folder.created_at,
        updated_at: now.clone(),
    };

    query!(
        &db,
        "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 AND \
         user_id = ?4",
        folder.name,
        folder.updated_at,
        folder.id,
        folder.user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    query!(
        &db,
        "UPDATE users SET updated_at = ?1 WHERE id = ?2",
        now,
        &claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let response = FolderResponse {
        id:            folder.id,
        name:          folder.name,
        revision_date: folder.updated_at,
        object:        "folder".to_string(),
    };

    Ok(Json(response))
}
