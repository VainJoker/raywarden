//! Folder request/response contracts and projections.
use serde::{
    Deserialize,
    Serialize,
};
use uuid::Uuid;

use crate::{
    app::AppContext,
    errors::AppResult,
    models::vault::folder::FolderRow,
    service::{
        identity::session::Claims,
        notifications::UpdateType,
        vault_write::VaultWrite,
    },
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderResponse {
    pub id:            String,
    pub name:          String,
    pub revision_date: String,
    object:            &'static str,
}

impl From<FolderRow> for FolderResponse {
    fn from(folder: FolderRow) -> Self {
        Self {
            id:            folder.id,
            name:          folder.name,
            revision_date: folder.updated_at,
            object:        "folder",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateFolderRequest {
    pub name: String,
}

pub async fn create_folder(
    state: &AppContext,
    claims: &Claims,
    payload: CreateFolderRequest,
) -> AppResult<FolderResponse> {
    let mut mutation = VaultWrite::new(state, claims);
    let db = mutation.database();
    mutation.guard_account_key().await?;
    let now = crate::utils::time::now_rfc3339();
    let folder = FolderRow {
        id:         Uuid::new_v4().to_string(),
        user_id:    mutation.user_id().to_owned(),
        name:       payload.name,
        created_at: now.clone(),
        updated_at: now,
    };
    let write = folder.insert_statement(db)?;
    let committed = mutation.commit(vec![write]).await?;
    committed
        .publish_folder(UpdateType::SyncFolderCreate, &folder.id)
        .await;
    Ok(folder.into())
}

pub async fn delete_folder(
    state: &AppContext,
    claims: &Claims,
    id: String,
) -> AppResult<()> {
    let mut mutation = VaultWrite::new(state, claims);
    let db = mutation.database();
    let old = FolderRow::fetch_for_user(db, &id, mutation.user_id()).await?;
    let write = FolderRow::delete_statement(db, &id, mutation.user_id())?;
    mutation.add_guard(old.snapshot_guard(db)?);
    let committed = mutation.commit(vec![write]).await?;
    committed
        .publish_folder(UpdateType::SyncFolderDelete, &id)
        .await;
    Ok(())
}

pub async fn update_folder(
    state: &AppContext,
    claims: &Claims,
    id: String,
    payload: CreateFolderRequest,
) -> AppResult<FolderResponse> {
    let mut mutation = VaultWrite::new(state, claims);
    let db = mutation.database();
    mutation.guard_account_key().await?;
    let old = FolderRow::fetch_for_user(db, &id, mutation.user_id()).await?;
    mutation.add_guard(old.snapshot_guard(db)?);
    let now = crate::utils::time::now_rfc3339();
    let folder = FolderRow {
        id,
        user_id: mutation.user_id().to_owned(),
        name: payload.name,
        created_at: old.created_at,
        updated_at: now,
    };
    let write = folder.update_statement(db)?;
    let committed = mutation.commit(vec![write]).await?;
    committed
        .publish_folder(UpdateType::SyncFolderUpdate, &folder.id)
        .await;
    Ok(folder.into())
}
