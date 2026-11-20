//! Personal vault import contracts and workflow.
use std::collections::HashSet;

use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    app::AppContext,
    errors::{
        AppError,
        AppResult,
    },
    models::vault::folder::FolderRow,
    service::{
        identity::session::Claims,
        notifications::{
            UpdateType,
            admin::Event,
        },
        vault::cipher::{
            CipherPayload,
            CipherRequest,
            normalize_optional_rfc3339,
        },
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
    pub id:   Option<String>,
    pub name: String,
}

/// Relationship between cipher index and folder index in the import arrays.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FolderRelationship {
    /// Cipher index in the ciphers array
    pub key:   usize,
    /// Folder index in the folders array
    pub value: usize,
}

/// Import request payload structure.
/// Aligned with vaultwarden's `ImportData` used in POST /ciphers/import.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub ciphers:              Vec<CipherRequest>,
    pub folders:              Vec<ImportFolder>,
    #[serde(default)]
    pub folder_relationships: Vec<FolderRelationship>,
}

#[allow(
    clippy::too_many_lines,
    reason = "Resolve every imported relationship before committing one \
              guarded vault transaction"
)]
pub(crate) async fn import_data(
    claims: &Claims,
    state: &AppContext,
    mut payload: ImportRequest,
) -> AppResult<()> {
    let mut mutation = VaultWrite::new(state, claims);
    let db = mutation.database();
    let account = mutation.guard_account_key().await?;
    for cipher in &mut payload.ciphers {
        // Exported organization and folder identifiers belong to the source
        // vault. Relationships below are the import protocol's folder mapping.
        cipher.organization_id = None;
        cipher.folder_id = None;
        cipher.validate_for_personal_vault(mutation.user_id())?;
        cipher.validate_encryption_context(
            mutation.user_id(),
            account.user_key_id.as_deref(),
        )?;
    }
    for link in &payload.folder_relationships {
        if link.key >= payload.ciphers.len() ||
            link.value >= payload.folders.len()
        {
            return Err(AppError::bad_request(
                "Invalid cipher-folder import relationship",
            ));
        }
    }
    let existing: HashSet<String> =
        FolderRow::list_for_user(db, mutation.user_id())
            .await?
            .into_iter()
            .map(|folder| folder.id)
            .collect();
    let mut resolved = Vec::new();
    let mut folders = Vec::new();
    for folder in &payload.folders {
        let id = folder
            .id
            .as_ref()
            .filter(|id| existing.contains(*id))
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        if !existing.contains(&id) {
            folders.push(json!([id, folder.name]));
        }
        resolved.push(id);
    }
    for link in &payload.folder_relationships {
        payload.ciphers[link.key].folder_id =
            Some(resolved[link.value].clone());
    }
    let required: HashSet<String> = payload
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
    let mut ciphers = Vec::new();
    for cipher in payload.ciphers {
        let data = serde_json::to_string(&CipherPayload::from_request(&cipher))
            .map_err(AppError::internal_error)?;
        ciphers.push(json!([
            Uuid::new_v4().to_string(),
            cipher.cipher_type,
            data,
            cipher.is_favorite.unwrap_or(false),
            cipher.folder_id,
            normalize_optional_rfc3339(cipher.archived_at.as_deref())
        ]));
    }
    let maximum_rows = state.config.import_batch_size.clamp(1, 200) as usize;
    let writes = crate::models::vault::import::collect_import_writes(
        db,
        mutation.user_id(),
        &now,
        folders,
        ciphers,
        maximum_rows,
    )?;
    let committed = mutation.commit(writes).await?;
    committed.publish_user(UpdateType::SyncVault).await;
    committed.emit_admin(Event::Import).await;
    Ok(())
}
