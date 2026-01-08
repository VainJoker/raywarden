use axum::{
    Json,
    extract::{
        Path,
        State,
    },
};
use chrono::{
    DateTime,
    Utc,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        controller::attachments,
        service::claims::Claims,
    },
    errors::{
        AppError,
        AuthError,
    },
    models::{
        attachment::AttachmentDB,
        cipher::{
            Cipher,
            CipherDB,
            CipherData,
            CipherRequestData,
            CreateCipherRequest,
            PartialCipherData,
        },
        folder::FolderDB,
        user::{
            PasswordOrOtpData,
            UserDB,
        },
    },
};

// A wrapper for raw JSON strings that implements `IntoResponse`.
// Use this to return pre-built JSON without re-parsing/re-serializing.
// pub struct RawJson(pub String);

// impl IntoResponse for RawJson {
//     fn into_response(self) -> Response {
//         ([(header::CONTENT_TYPE, "application/json")],
// self.0).into_response()     }
// }

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let db = state.get_db();
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let cipher_data_req = payload.cipher;

    let cipher_data = CipherData {
        name:        cipher_data_req.name,
        notes:       cipher_data_req.notes,
        type_fields: cipher_data_req.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|e| {
        log::error!("Failed to serialize cipher data: {e}");
        AppError::Internal
    })?;

    let mut cipher = Cipher {
        id:                    Uuid::new_v4().to_string(),
        user_id:               Some(claims.sub.clone()),
        organization_id:       cipher_data_req.organization_id.clone(),
        r#type:                cipher_data_req.r#type,
        data:                  data_value,
        favorite:              cipher_data_req.favorite.unwrap_or(false),
        folder_id:             cipher_data_req.folder_id.clone(),
        deleted_at:            None,
        created_at:            now.clone(),
        updated_at:            now.clone(),
        object:                "cipher".to_string(),
        organization_use_totp: false,
        edit:                  true,
        view_password:         true,
        collection_ids:        if payload.collection_ids.is_empty() {
            None
        } else {
            Some(payload.collection_ids)
        },
        attachments:           None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|e| {
        log::error!("Failed to serialize cipher data JSON: {e}");
        AppError::Internal
    })?;

    CipherDB::insert_cipher(&db, &cipher, &data).await?;

    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = state.get_db();
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing_cipher =
        CipherDB::fetch_for_user(&db, &id, &claims.sub).await?;

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        FolderDB::ensure_for_user(&db, folder_id, &claims.sub).await?;
    }

    // Reject updates based on stale client data when the last known revision is
    // provided
    if let Some(dt) = payload.last_known_revision_date.as_deref() {
        match DateTime::parse_from_rfc3339(dt) {
            Ok(client_dt) => {
                match DateTime::parse_from_rfc3339(&existing_cipher.updated_at)
                {
                    Ok(server_dt) => {
                        if server_dt
                            .signed_duration_since(client_dt)
                            .num_seconds() >
                            1
                        {
                            return Err(AppError::Params(
                                "The client copy of this cipher is out of \
                                 date. Resync the client and try again."
                                    .to_string(),
                            ));
                        }
                    }
                    Err(err) => log::warn!(
                        "Error parsing server revisionDate '{}' for cipher \
                         {}: {err}",
                        existing_cipher.updated_at,
                        existing_cipher.id,
                    ),
                }
            }
            Err(err) => {
                log::warn!("Error parsing lastKnownRevisionDate '{dt}': {err}");
            }
        }
    }

    let cipher_data_req = payload;

    let cipher_data = CipherData {
        name:        cipher_data_req.name,
        notes:       cipher_data_req.notes,
        type_fields: cipher_data_req.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|e| {
        log::error!("Failed to serialize cipher data: {e}");
        AppError::Internal
    })?;

    let mut cipher = Cipher {
        id:                    id.clone(),
        user_id:               Some(claims.sub.clone()),
        organization_id:       cipher_data_req.organization_id.clone(),
        r#type:                cipher_data_req.r#type,
        data:                  data_value,
        favorite:              cipher_data_req.favorite.unwrap_or(false),
        folder_id:             cipher_data_req.folder_id.clone(),
        deleted_at:            None,
        created_at:            existing_cipher.created_at,
        updated_at:            now.clone(),
        object:                "cipher".to_string(),
        organization_use_totp: false,
        edit:                  true,
        view_password:         true,
        collection_ids:        None,
        attachments:           None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|e| {
        log::error!("Failed to serialize cipher data JSON: {e}");
        AppError::Internal
    })?;

    CipherDB::update_cipher(&db, &cipher, &data, &id, &claims.sub).await?;

    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers - list all non-trashed ciphers for current user
#[worker::send]
pub async fn list_ciphers(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let include_attachments = AttachmentDB::attachments_enabled(&state.env);
    let ciphers_json = CipherDB::fetch_cipher_json_array_raw(
        &db,
        include_attachments,
        "WHERE c.user_id = ?1 AND c.deleted_at IS NULL",
        &[claims.sub.clone().into()],
        "ORDER BY c.updated_at DESC",
    )
    .await?;

    // Build response JSON via string concatenation (no parsing!)
    let response = format!(
        r#"{{"data":{ciphers_json},"object":"list","continuationToken":null}}"#
    );

    Ok(Json(serde_json::from_str(&response).map_err(|err| {
        log::error!("Failed to parse cipher list JSON: {err}");
        AppError::Internal
    })?))
}

/// GET /api/ciphers/{id}
#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = state.get_db();
    let cipher = CipherDB::fetch_for_user(&db, &id, &claims.sub).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers/{id}/details
#[worker::send]
pub async fn get_cipher_details(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    get_cipher(claims, State(state), Path(id)).await
}

/// PUT/POST /api/ciphers/{id}/partial
#[worker::send]
pub async fn update_cipher_partial(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    let db = state.get_db();
    let user_id = &claims.sub;

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        FolderDB::ensure_for_user(&db, folder_id, user_id).await?;
    }

    // Ensure cipher exists and belongs to user
    CipherDB::fetch_for_user(&db, &id, user_id).await?;

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    CipherDB::update_cipher_partial(
        &db,
        payload.folder_id,
        payload.favorite,
        &now,
        &id,
        user_id,
    )
    .await?;

    UserDB::touch_user_updated_at(&db, user_id).await?;

    let cipher = CipherDB::fetch_for_user(&db, &id, user_id).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;

    Ok(Json(cipher))
}

/// Soft delete a single cipher (PUT /api/ciphers/{id}/delete)
/// Sets `deleted_at` to current timestamp
#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = state.get_db();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    CipherDB::soft_delete_cipher(&db, &id, &claims.sub, &now).await?;

    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Soft delete multiple ciphers (PUT /api/ciphers/delete)
/// Accepts raw JSON body and uses `json_each` with path to extract ids
/// directly. Expected JSON:
/// ```json
/// {"ids": ["cipher_id1", "cipher_id2"]}
/// ```
#[worker::send]
pub async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = state.get_db();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    CipherDB::soft_delete_ciphers_bulk(&db, &claims.sub, &body, &now).await?;

    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Hard delete a single cipher (DELETE /api/ciphers/{id} or POST
/// /api/ciphers/{id}/delete) Permanently removes the cipher from database
#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = state.get_db();

    if AttachmentDB::attachments_enabled(&state.env) {
        let bucket = AttachmentDB::require_bucket(&state.env)?;
        let id_json = serde_json::to_string(&[&id]).map_err(|e| {
            log::error!("Failed to serialize cipher id list: {e}");
            AppError::Internal
        })?;
        let keys = AttachmentDB::list_attachment_keys_for_cipher_ids_json(
            &db,
            &id_json,
            "$",
            Some(&claims.sub),
        )
        .await?;
        AttachmentDB::delete_r2_objects(&bucket, &keys).await?;
    }

    CipherDB::hard_delete_cipher(&db, &id, &claims.sub).await?;

    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Hard delete multiple ciphers (DELETE /api/ciphers or POST
/// /api/ciphers/delete) Accepts raw JSON body and uses `json_each` with path to
/// extract ids directly. Expected JSON:
/// ```json
/// {"ids": ["cipher_id1", "cipher_id2"]}
/// ```
#[worker::send]
pub async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = state.get_db();

    if AttachmentDB::attachments_enabled(&state.env) {
        let bucket = AttachmentDB::require_bucket(&state.env)?;
        let keys = AttachmentDB::list_attachment_keys_for_cipher_ids_json(
            &db,
            &body,
            "$.ids",
            Some(&claims.sub),
        )
        .await?;
        AttachmentDB::delete_r2_objects(&bucket, &keys).await?;
    }

    CipherDB::hard_delete_ciphers_bulk(&db, &claims.sub, &body).await?;

    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Restore a single cipher (PUT /api/ciphers/{id}/restore)
/// Clears the `deleted_at` timestamp
#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = state.get_db();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let cipher_db =
        CipherDB::restore_cipher(&db, &id, &claims.sub, &now).await?;

    let mut cipher: Cipher = cipher_db.into();
    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;

    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// Restore multiple ciphers (PUT /api/ciphers/restore)
/// Accepts raw JSON body and uses `json_each` with path to extract ids
/// directly. Expected JSON:
/// ```json
/// {"ids": ["cipher_id1", "cipher_id2"]}
/// ```
#[worker::send]
pub async fn restore_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    CipherDB::restore_ciphers_bulk(&db, &claims.sub, &body, &now).await?;

    let include_attachments = AttachmentDB::attachments_enabled(&state.env);
    let ciphers_json = CipherDB::fetch_cipher_json_array_raw(
        &db,
        include_attachments,
        "WHERE c.user_id = ?1 AND c.id IN (SELECT value FROM json_each(?2, \
         '$.ids'))",
        &[claims.sub.clone().into(), body.clone().into()],
        "",
    )
    .await?;

    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    // Build response JSON via string concatenation (no parsing!)
    let response = format!(
        r#"{{"data":{ciphers_json},"object":"list","continuationToken":null}}"#
    );

    Ok(Json(serde_json::from_str(&response).map_err(|err| {
        log::error!("Failed to parse restored cipher list JSON: {err}");
        AppError::Internal
    })?))
}

/// Handler for POST /api/ciphers
/// Accepts flat JSON structure (camelCase) as sent by Bitwarden clients
/// when creating a cipher without collection assignments.
#[worker::send]
pub async fn create_cipher_simple(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = state.get_db();
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let cipher_data = CipherData {
        name:        payload.name,
        notes:       payload.notes,
        type_fields: payload.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|e| {
        log::error!("Failed to serialize cipher data: {e}");
        AppError::Internal
    })?;

    let mut cipher = Cipher {
        id:                    Uuid::new_v4().to_string(),
        user_id:               Some(claims.sub.clone()),
        organization_id:       payload.organization_id.clone(),
        r#type:                payload.r#type,
        data:                  data_value,
        favorite:              payload.favorite.unwrap_or(false),
        folder_id:             payload.folder_id.clone(),
        deleted_at:            None,
        created_at:            now.clone(),
        updated_at:            now.clone(),
        object:                "cipher".to_string(),
        organization_use_totp: false,
        edit:                  true,
        view_password:         true,
        collection_ids:        None,
        attachments:           None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|e| {
        log::error!("Failed to serialize cipher data JSON: {e}");
        AppError::Internal
    })?;

    CipherDB::insert_cipher(&db, &cipher, &data).await?;

    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// Move selected ciphers to a folder (POST/PUT /api/ciphers/move)
/// Accepts raw JSON body and uses `json_extract/json_each` to extract values
/// directly. Expected JSON: {"folderId": "optional-folder-id-or-null", "ids":
/// ["`cipher_id1`", ...]} The folderId is optional and treated as null if not
/// provided in vaultwarden. D1/SQLite's `json_extract` returns SQL NULL for
/// non-existent paths, which is identical to the behavior in vaultwarden.
#[worker::send]
pub async fn move_cipher_selected(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = state.get_db();
    let user_id = &claims.sub;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Validate folder exists and belongs to user (if folder_id is provided)
    // Uses json_extract to get folderId from request body
    FolderDB::ensure_json_folder_exists(&db, &body, user_id).await?;

    // Update folder_id for all ciphers that belong to the user and are in the
    // ids list Uses json_extract for folderId and json_each for ids array
    CipherDB::move_selected(&db, user_id, &body, &now).await?;

    // Update user's revision date
    UserDB::touch_user_updated_at(&db, user_id).await?;

    Ok(Json(()))
}

/// Purge the user's vault - delete all ciphers and folders
/// POST /api/ciphers/purge
///
/// This is a destructive operation that requires password verification.
/// In vaultwarden, this endpoint also supports purging organization vaults,
/// but this simplified version only supports personal vault purge.
#[worker::send]
pub async fn purge_vault(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<()>, AppError> {
    let db = state.get_db();
    let user_id = &claims.sub;

    // Get the user from the database
    let user = UserDB::fetch_by_id_with(
        &db,
        user_id,
        "Failed to fetch user for vault purge",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    // Validate password (OTP not supported in this simplified version)
    let provided_hash = payload.master_password_hash.ok_or_else(|| {
        AppError::Params("Missing master password hash".to_string())
    })?;

    let verification = user.verify_master_password(&provided_hash).await?;

    if !verification.is_valid() {
        return Err(AppError::Auth(AuthError::InvalidPassword));
    }

    if AttachmentDB::attachments_enabled(&state.env) {
        let bucket = AttachmentDB::require_bucket(&state.env)?;
        let keys =
            AttachmentDB::list_attachment_keys_for_user(&db, user_id).await?;
        AttachmentDB::delete_r2_objects(&bucket, &keys).await?;
    }

    // Delete all user's ciphers (both active and soft-deleted)
    CipherDB::purge_user_ciphers(&db, user_id).await?;
    FolderDB::purge_user_folders(&db, user_id).await?;

    // Update user's revision date to trigger client sync
    UserDB::touch_user_updated_at(&db, user_id).await?;

    Ok(Json(()))
}
