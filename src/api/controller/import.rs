use std::collections::{
    HashMap,
    HashSet,
};

use axum::{
    Json,
    extract::State,
};
use chrono::Utc;
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::AppError,
    models::{
        cipher::{
            Cipher,
            CipherDB,
            CipherData,
        },
        folder::FolderDB,
        import::ImportRequest,
        user::UserDB,
    },
};

/// Import ciphers and folders.
/// Aligned with vaultwarden's POST /ciphers/import implementation.
#[worker::send]
pub async fn import_data(
    claims: Claims,
    State(state): State<AppState>,
    Json(data): Json<ImportRequest>,
) -> Result<Json<()>, AppError> {
    let db = state.get_db();
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let batch_size = state.config.import_batch_size as usize;

    // Get existing folders for this user
    let existing_folders: HashSet<String> =
        FolderDB::list_for_user(&db, &claims.sub)
            .await?
            .into_iter()
            .map(|folder| folder.id)
            .collect();

    // Process folders and build the folder_id list
    let mut folders_to_insert: Vec<FolderDB> = Vec::new();
    let mut folders: Vec<String> = Vec::with_capacity(data.folders.len());

    for import_folder in data.folders {
        let folder_id = if let Some(ref id) = import_folder.id {
            if existing_folders.contains(id) {
                // Folder already exists, use existing ID
                id.clone()
            } else {
                // Folder doesn't exist, create new one with provided ID
                let folder = FolderDB {
                    id:         id.clone(),
                    user_id:    claims.sub.clone(),
                    name:       import_folder.name.clone(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                };

                folders_to_insert.push(folder);
                id.clone()
            }
        } else {
            // No ID provided, create new folder with generated UUID
            let new_id = Uuid::new_v4().to_string();
            let folder = FolderDB {
                id:         new_id.clone(),
                user_id:    claims.sub.clone(),
                name:       import_folder.name.clone(),
                created_at: now.clone(),
                updated_at: now.clone(),
            };

            folders_to_insert.push(folder);
            new_id
        };

        folders.push(folder_id);
    }

    // Execute folder inserts in batches
    FolderDB::insert_batch(&db, &folders_to_insert, batch_size).await?;

    // Build the relations map: cipher_index -> folder_index
    // Each cipher can only be in one folder at a time
    let mut relations_map: HashMap<usize, usize> =
        HashMap::with_capacity(data.folder_relationships.len());
    for relation in data.folder_relationships {
        relations_map.insert(relation.key, relation.value);
    }

    // Prepare all cipher insert statements
    let mut cipher_batch: Vec<(Cipher, String)> =
        Vec::with_capacity(data.ciphers.len());

    for (index, import_cipher) in data.ciphers.into_iter().enumerate() {
        // Determine folder_id from folder_relationships
        let folder_id = relations_map
            .get(&index)
            .and_then(|folder_idx| folders.get(*folder_idx).cloned());

        let cipher_data = CipherData {
            name:        import_cipher.name,
            notes:       import_cipher.notes,
            type_fields: import_cipher.type_fields,
        };

        let data_value = serde_json::to_value(&cipher_data).map_err(|e| {
            log::error!("Failed to serialize cipher data for import: {e}");
            AppError::Internal
        })?;

        let cipher = Cipher {
            id: Uuid::new_v4().to_string(),
            user_id: Some(claims.sub.clone()),
            organization_id: import_cipher.organization_id,
            r#type: import_cipher.r#type,
            data: data_value,
            favorite: import_cipher.favorite.unwrap_or(false),
            folder_id,
            deleted_at: None,
            created_at: now.clone(),
            updated_at: now.clone(),
            object: "cipher".to_string(),
            organization_use_totp: false,
            edit: true,
            view_password: true,
            collection_ids: None,
            attachments: None,
        };

        let data = serde_json::to_string(&cipher.data).map_err(|e| {
            log::error!("Failed to serialize cipher data JSON for import: {e}");
            AppError::Internal
        })?;

        cipher_batch.push((cipher, data));
    }

    // Execute cipher inserts in batches
    CipherDB::insert_ciphers_batch(&db, &cipher_batch, batch_size).await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;
    Ok(Json(()))
}
