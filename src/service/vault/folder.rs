//! Folder request/response contracts and projections.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, Env};

use crate::{
    errors::AppResult,
    models::{page::Page, vault::folder::FolderRow},
    service::{identity::session::Claims, notifications::UpdateType, vault_write::VaultWrite},
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderResponse {
    pub id: String,
    pub name: String,
    pub revision_date: String,
    object: &'static str,
}

impl From<FolderRow> for FolderResponse {
    fn from(folder: FolderRow) -> Self {
        Self {
            id: folder.id,
            name: folder.name,
            revision_date: folder.updated_at,
            object: "folder",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateFolderRequest {
    pub name: String,
}

pub(crate) async fn visit_folder_responses(
    db: &D1Database,
    user_id: &str,
    mut visit: impl FnMut(FolderResponse) -> AppResult<()>,
) -> AppResult<()> {
    Page::visit(
        async |after| FolderRow::list_page(db, user_id, after).await,
        async |rows| rows.into_iter().try_for_each(|row| visit(row.into())),
    )
    .await
}

pub async fn delete_folder(db: &D1Database, env: &Env, claims: &Claims, id: &str) -> AppResult<()> {
    let mut mutation = VaultWrite::new(db, env, claims);
    let old = FolderRow::fetch_for_user(db, id, mutation.user_id()).await?;
    let write = FolderRow::delete_statement(db, id, mutation.user_id())?;
    mutation.add_guard(old.snapshot_guard(db)?);
    let committed = mutation.commit(vec![write]).await?;
    committed
        .publish_folder(UpdateType::SyncFolderDelete, id)
        .await;
    Ok(())
}

pub(crate) async fn save_folder(
    db: &D1Database,
    env: &Env,
    claims: &Claims,
    id: Option<String>,
    payload: CreateFolderRequest,
) -> AppResult<FolderResponse> {
    let mut mutation = VaultWrite::new(db, env, claims);
    mutation.guard_account_key().await?;
    let existing = if let Some(id) = id {
        let folder = FolderRow::fetch_for_user(db, &id, mutation.user_id()).await?;
        mutation.add_guard(folder.snapshot_guard(db)?);
        Some(folder)
    } else {
        None
    };
    let now = crate::utils::time::now_rfc3339();
    let (folder, write, update) = if let Some(mut folder) = existing {
        folder.name = payload.name;
        folder.updated_at = now;
        let write = folder.update_statement(db)?;
        (folder, write, UpdateType::SyncFolderUpdate)
    } else {
        let folder = FolderRow {
            id: Uuid::new_v4().to_string(),
            user_id: mutation.user_id().to_owned(),
            name: payload.name,
            created_at: now.clone(),
            updated_at: now,
        };
        let write = folder.insert_statement(db)?;
        (folder, write, UpdateType::SyncFolderCreate)
    };
    mutation
        .commit(vec![write])
        .await?
        .publish_folder(update, &folder.id)
        .await;
    Ok(folder.into())
}
