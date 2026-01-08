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

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::AppError,
    models::{
        folder::{
            CreateFolderRequest,
            FolderDB,
            FolderResponse,
        },
        user::UserDB,
    },
};

#[worker::send]
pub async fn list_folders(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let folders_db = FolderDB::list_for_user(&db, &claims.sub).await?;

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
    let folder = FolderDB::get_for_user(&db, &id, &claims.sub).await?;
    Ok(Json(folder.into()))
}

#[worker::send]
pub async fn create_folder(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateFolderRequest>,
) -> Result<Json<FolderResponse>, AppError> {
    let db = state.get_db();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let folder = FolderDB {
        id:         Uuid::new_v4().to_string(),
        user_id:    claims.sub.clone(),
        name:       payload.name,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    FolderDB::insert(&db, &folder).await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

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

    FolderDB::delete_for_user(&db, &id, &claims.sub).await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

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
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing_folder = FolderDB::get_for_user(&db, &id, &claims.sub).await?;

    let folder = FolderDB {
        id:         id.clone(),
        user_id:    existing_folder.user_id,
        name:       payload.name,
        created_at: existing_folder.created_at,
        updated_at: now.clone(),
    };

    FolderDB::update_for_user(&db, &folder).await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    let response = FolderResponse {
        id:            folder.id,
        name:          folder.name,
        revision_date: folder.updated_at,
        object:        "folder".to_string(),
    };

    Ok(Json(response))
}
