//! Personal vault import contracts and workflow.
use std::collections::HashSet;

use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use worker::{D1Database, Env};

use crate::{
    errors::{AppError, AppResult},
    models::vault::folder::FolderRow,
    service::{
        identity::session::Claims,
        notifications::{UpdateType, admin::Event},
        vault::cipher::{CipherRequest, normalize_optional_rfc3339},
        vault_write::VaultWrite,
    },
};

/// Folder data structure for import requests.
/// Aligned with vaultwarden's `FolderData`.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportFolder {
    /// Optional folder ID - if provided and exists, the existing folder is
    /// used
    pub id: Option<String>,
    pub name: String,
}

/// Relationship between cipher index and folder index in the import arrays.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FolderRelationship {
    /// Cipher index in the ciphers array
    pub key: usize,
    /// Folder index in the folders array
    pub value: usize,
}

/// Import request payload structure.
/// Aligned with vaultwarden's `ImportData` used in POST /ciphers/import.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub ciphers: Vec<CipherRequest>,
    pub folders: Vec<ImportFolder>,
    #[serde(default)]
    pub folder_relationships: Vec<FolderRelationship>,
}

struct ImportPlan {
    request: ImportRequest,
    maximum_rows: usize,
}

impl ImportPlan {
    fn prepare(
        mut request: ImportRequest,
        user_id: &str,
        key_id: Option<&str>,
        batch_limit: u32,
    ) -> AppResult<Self> {
        for cipher in &mut request.ciphers {
            // Source organization and folder IDs are discarded. The import
            // protocol supplies the folder relationships separately.
            cipher.organization_id = None;
            cipher.folder_id = None;
            cipher.validate_for_personal_vault(user_id)?;
            cipher.validate_encryption_context(user_id, key_id)?;
        }
        for link in &request.folder_relationships {
            if link.key >= request.ciphers.len() || link.value >= request.folders.len() {
                return Err(AppError::bad_request(
                    "Invalid cipher-folder import relationship",
                ));
            }
        }
        Ok(Self {
            request,
            maximum_rows: batch_limit.clamp(1, 200) as usize,
        })
    }

    fn resolve_folders(&mut self, existing: &HashSet<String>) -> Vec<serde_json::Value> {
        let mut resolved = Vec::with_capacity(self.request.folders.len());
        let mut folders = Vec::new();
        for folder in self.request.folders.drain(..) {
            let id = folder
                .id
                .filter(|id| existing.contains(id))
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            if !existing.contains(&id) {
                folders.push(json!([id, folder.name]));
            }
            resolved.push(id);
        }
        for link in &self.request.folder_relationships {
            self.request.ciphers[link.key].folder_id = Some(resolved[link.value].clone());
        }
        folders
    }

    async fn commit(mut self, mut mutation: VaultWrite<'_>) -> AppResult<()> {
        let db = mutation.database();
        let existing: HashSet<_> = FolderRow::list_for_user(db, mutation.user_id())
            .await?
            .into_iter()
            .map(|folder| folder.id)
            .collect();
        let folders = self.resolve_folders(&existing);
        let required = self
            .request
            .ciphers
            .iter()
            .filter_map(|cipher| cipher.folder_id.as_ref())
            .filter(|id| existing.contains(*id))
            .cloned()
            .collect();
        mutation.add_guard(crate::models::vault::import::required_folder_guard(
            db,
            mutation.user_id(),
            &required,
        )?);
        let now = crate::utils::time::now_rfc3339();
        let ciphers = self
            .request
            .ciphers
            .into_iter()
            .map(encode_cipher)
            .collect::<AppResult<_>>()?;
        let writes = crate::models::vault::import::collect_import_writes(
            db,
            mutation.user_id(),
            &now,
            folders,
            ciphers,
            self.maximum_rows,
        )?;
        let committed = mutation.commit(writes).await?;
        committed.publish_user(UpdateType::SyncVault).await;
        committed.emit_admin(Event::Import).await;
        Ok(())
    }
}

fn encode_cipher(mut cipher: CipherRequest) -> AppResult<serde_json::Value> {
    let cipher_type = cipher.cipher_type;
    let favorite = cipher.is_favorite.unwrap_or(false);
    let folder = cipher.folder_id.take();
    let archived = normalize_optional_rfc3339(cipher.archived_at.as_deref());
    let data = serde_json::to_string(&cipher.into_payload()).map_err(AppError::internal_error)?;
    Ok(json!([
        Uuid::new_v4().to_string(),
        cipher_type,
        data,
        favorite,
        folder,
        archived
    ]))
}

pub(crate) async fn import_data(
    db: &D1Database,
    env: &Env,
    import_batch_size: u32,
    claims: &Claims,
    payload: ImportRequest,
) -> AppResult<()> {
    let mut mutation = VaultWrite::new(db, env, claims);
    let account = mutation.guard_account_key().await?;
    let plan = ImportPlan::prepare(
        payload,
        mutation.user_id(),
        account.user_key_id.as_deref(),
        import_batch_size,
    )?;
    plan.commit(mutation).await
}
