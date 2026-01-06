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
use worker::{
    D1PreparedStatement,
    query,
};

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::{
        AppError,
        DatabaseError,
    },
    models::{
        cipher::{
            Cipher,
            CipherData,
        },
        folder::Folder,
        import::ImportRequest,
        user::User,
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
    let existing_folder_rows = query!(
        &db,
        "SELECT id FROM folders WHERE user_id = ?1",
        &claims.sub
    )
    .map_err(|_| {
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to query existing folders".to_string(),
        ))
    })?
    .all()
    .await?
    .results::<FolderIdRow>()?;

    let existing_folders: HashSet<String> =
        existing_folder_rows.into_iter().map(|row| row.id).collect();

    // Process folders and build the folder_id list
    let mut folder_statements: Vec<D1PreparedStatement> = Vec::new();
    let mut folders: Vec<String> = Vec::with_capacity(data.folders.len());

    for import_folder in data.folders {
        let folder_id = if let Some(ref id) = import_folder.id {
            if existing_folders.contains(id) {
                // Folder already exists, use existing ID
                id.clone()
            } else {
                // Folder doesn't exist, create new one with provided ID
                let folder = Folder {
                    id:         id.clone(),
                    user_id:    claims.sub.clone(),
                    name:       import_folder.name.clone(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                };

                let stmt = query!(
                    &db,
                    "INSERT INTO folders (id, user_id, name, created_at, \
                     updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    folder.id,
                    folder.user_id,
                    folder.name,
                    folder.created_at,
                    folder.updated_at
                )
                .map_err(|_| {
                    AppError::Database(DatabaseError::QueryFailed(
                        "Failed to insert folder".to_string(),
                    ))
                })?;

                folder_statements.push(stmt);
                id.clone()
            }
        } else {
            // No ID provided, create new folder with generated UUID
            let new_id = Uuid::new_v4().to_string();
            let folder = Folder {
                id:         new_id.clone(),
                user_id:    claims.sub.clone(),
                name:       import_folder.name.clone(),
                created_at: now.clone(),
                updated_at: now.clone(),
            };

            let stmt = query!(
                &db,
                "INSERT INTO folders (id, user_id, name, created_at, \
                 updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                folder.id,
                folder.user_id,
                folder.name,
                folder.created_at,
                folder.updated_at
            )
            .map_err(|_| {
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to insert folder".to_string(),
                ))
            })?;

            folder_statements.push(stmt);
            new_id
        };

        folders.push(folder_id);
    }

    // Execute folder inserts in batches
    if !folder_statements.is_empty() {
        // db::execute_in_batches(&db, folder_statements, batch_size).await?;
        if batch_size == 0 {
            db.batch(folder_statements).await?;
        } else {
            for chunk in folder_statements.chunks(batch_size) {
                db.batch(chunk.to_vec()).await?;
            }
        }
    }

    // Build the relations map: cipher_index -> folder_index
    // Each cipher can only be in one folder at a time
    let mut relations_map: HashMap<usize, usize> =
        HashMap::with_capacity(data.folder_relationships.len());
    for relation in data.folder_relationships {
        relations_map.insert(relation.key, relation.value);
    }

    // Prepare all cipher insert statements
    let mut cipher_statements: Vec<D1PreparedStatement> =
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

        let stmt = query!(
            &db,
            "INSERT INTO ciphers (id, user_id, organization_id, type, data, \
             favorite, folder_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            cipher.id,
            cipher.user_id,
            cipher.organization_id,
            cipher.r#type,
            data,
            cipher.favorite,
            cipher.folder_id,
            cipher.created_at,
            cipher.updated_at,
        )
        .map_err(|_| {
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to insert cipher".to_string(),
            ))
        })?;

        cipher_statements.push(stmt);
    }

    // Execute cipher inserts in batches
    if !cipher_statements.is_empty() {
        // db::execute_in_batches(&db, cipher_statements, batch_size).await?;
        if batch_size == 0 {
            db.batch(cipher_statements).await?;
        } else {
            for chunk in cipher_statements.chunks(batch_size) {
                db.batch(chunk.to_vec()).await?;
            }
        }
    }
    User::touch_user_updated_at(&db, &claims.sub).await?;
    Ok(Json(()))
}

/// Helper struct for querying existing folder IDs
#[derive(serde::Deserialize)]
struct FolderIdRow {
    id: String,
}
