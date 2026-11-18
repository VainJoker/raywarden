use axum::{
    Json,
    extract::{
        Path,
        State,
    },
};
use serde_json::{
    Value,
    json,
};
use uuid::Uuid;
use worker::{
    D1Database,
    D1PreparedStatement,
};

use crate::{
    api::{
        AppState,
        service::{
            cipher_mutation,
            claims::Claims,
            notifications::{
                self,
                UpdateType,
            },
        },
    },
    errors::AppResult,
    infra::admin_notify::{
        self,
        Event,
    },
    models::folder::{
        CreateFolderRequest,
        FolderDB,
        FolderResponse,
    },
};

fn snapshot_guard(
    db: &D1Database,
    row: &FolderDB,
) -> AppResult<D1PreparedStatement> {
    cipher_mutation::guard(
        db,
        "EXISTS(SELECT 1 FROM folders WHERE id=?1 AND user_id=?2 AND name IS \
         ?3 AND created_at IS ?4 AND updated_at IS ?5)",
        &[
            row.id.clone().into(),
            row.user_id.clone().into(),
            row.name.clone().into(),
            row.created_at.clone().into(),
            row.updated_at.clone().into(),
        ],
    )
}
#[worker::send]
pub async fn list_folders(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let rows: Vec<FolderResponse> =
        FolderDB::list_for_user(&state.get_db(), &claims.sub)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
    Ok(Json(
        json!({"data":rows,"object":"list","continuationToken":null}),
    ))
}
#[worker::send]
pub async fn get_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<FolderResponse>> {
    Ok(Json(
        FolderDB::get_for_user(&state.get_db(), &id, &claims.sub)
            .await?
            .into(),
    ))
}
#[worker::send]
pub async fn create_folder(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateFolderRequest>,
) -> AppResult<Json<FolderResponse>> {
    let db = state.get_db();
    let key_guard = cipher_mutation::account_key_guard(&db, &claims).await?;
    let now = crate::infra::time::now_rfc3339();
    let folder = FolderDB {
        id:         Uuid::new_v4().to_string(),
        user_id:    claims.sub.clone(),
        name:       payload.name,
        created_at: now.clone(),
        updated_at: now,
    };
    let write = db
        .prepare(
            "INSERT INTO folders(id,user_id,name,created_at,updated_at) \
             VALUES(?1,?2,?3,?4,?4)",
        )
        .bind(&[
            folder.id.clone().into(),
            folder.user_id.clone().into(),
            folder.name.clone().into(),
            folder.created_at.clone().into(),
        ])?;
    let revision =
        cipher_mutation::commit(&db, &claims, vec![key_guard], vec![write])
            .await?;
    notify(
        &state,
        &claims,
        UpdateType::SyncFolderCreate,
        &folder.id,
        &revision,
    )
    .await;
    Ok(Json(folder.into()))
}
#[worker::send]
pub async fn delete_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<()>> {
    let db = state.get_db();
    let old = FolderDB::get_for_user(&db, &id, &claims.sub).await?;
    let write = db
        .prepare("DELETE FROM folders WHERE id=?1 AND user_id=?2")
        .bind(&[id.clone().into(), claims.sub.clone().into()])?;
    let revision = cipher_mutation::commit(
        &db,
        &claims,
        vec![snapshot_guard(&db, &old)?],
        vec![write],
    )
    .await?;
    notify(
        &state,
        &claims,
        UpdateType::SyncFolderDelete,
        &id,
        &revision,
    )
    .await;
    Ok(Json(()))
}
#[worker::send]
pub async fn update_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateFolderRequest>,
) -> AppResult<Json<FolderResponse>> {
    let db = state.get_db();
    let key_guard = cipher_mutation::account_key_guard(&db, &claims).await?;
    let old = FolderDB::get_for_user(&db, &id, &claims.sub).await?;
    let guards = vec![key_guard, snapshot_guard(&db, &old)?];
    let now = crate::infra::time::now_rfc3339();
    let folder = FolderDB {
        id:         id.clone(),
        user_id:    claims.sub.clone(),
        name:       payload.name,
        created_at: old.created_at,
        updated_at: now.clone(),
    };
    let write = db
        .prepare(
            "UPDATE folders SET name=?1,updated_at=?2 WHERE id=?3 AND \
             user_id=?4",
        )
        .bind(&[
            folder.name.clone().into(),
            now.into(),
            id.into(),
            claims.sub.clone().into(),
        ])?;
    let revision =
        cipher_mutation::commit(&db, &claims, guards, vec![write]).await?;
    notify(
        &state,
        &claims,
        UpdateType::SyncFolderUpdate,
        &folder.id,
        &revision,
    )
    .await;
    Ok(Json(folder.into()))
}

async fn notify(
    state: &AppState,
    claims: &Claims,
    kind: UpdateType,
    id: &str,
    revision: &str,
) {
    notifications::publish_folder_update(
        &state.env,
        &claims.sub,
        kind,
        id,
        revision,
        claims.device(),
    )
    .await;
    admin_notify::emit(&state.env, Event::VaultChanged, &claims.sub).await;
}
