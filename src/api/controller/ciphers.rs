use axum::{
    Json,
    extract::{
        Path,
        State,
    },
    http::header,
    response::{
        IntoResponse,
        Response,
    },
};
use chrono::{
    DateTime,
    Utc,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;
use worker::{
    query,
    wasm_bindgen::JsValue,
};

use crate::{
    api::{
        AppState,
        controller::attachments,
        service::claims::Claims,
    },
    errors::{
        AppError,
        AuthError,
        DatabaseError,
    },
    models::{
        attachment::AttachmentDB,
        cipher::{
            Cipher,
            CipherDBModel,
            CipherData,
            CipherRequestData,
            CreateCipherRequest,
            PartialCipherData,
        },
        user::{
            PasswordOrOtpData,
            User,
        },
    },
};

/// A wrapper for raw JSON strings that implements `IntoResponse`.
/// Use this to return pre-built JSON without re-parsing/re-serializing.
pub struct RawJson(pub String);

impl IntoResponse for RawJson {
    fn into_response(self) -> Response {
        ([(header::CONTENT_TYPE, "application/json")], self.0).into_response()
    }
}

/// Helper to fetch a cipher by id for a user or return `NotFound`.
async fn fetch_cipher_for_user(
    db: &worker::D1Database,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherDBModel, AppError> {
    db.prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
        .bind(&[cipher_id.to_string().into(), user_id.to_string().into()])
        .map_err(|e| {
            log::error!("Failed to bind fetch cipher query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch cipher".to_string(),
            ))
        })?
        .first(None)
        .await
        .map_err(|e| {
            log::error!("Failed to execute fetch cipher query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch cipher".to_string(),
            ))
        })?
        .ok_or_else(|| AppError::not_found("Cipher not found"))
}

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

    query!(
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
    .map_err(|e| {
        log::error!("Failed to bind insert cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to insert cipher".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Failed to execute insert cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to insert cipher".to_string(),
        ))
    })?;

    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    User::touch_user_updated_at(&db, &claims.sub).await?;

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

    let existing_cipher: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|e| {
        log::error!("Failed to bind fetch cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to fetch cipher".to_string(),
        ))
    })?
    .first(None)
    .await
    .map_err(|e| {
        log::error!("Failed to execute fetch cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to fetch cipher".to_string(),
        ))
    })?
    .ok_or_else(|| AppError::not_found("Cipher not found"))?;

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), claims.sub.clone().into()])
            .map_err(|e| {
                log::error!("Failed to bind folder ownership query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to validate folder".to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to execute folder ownership query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to validate folder".to_string(),
                ))
            })?;

        if folder_exists.is_none() {
            return Err(AppError::Params(
                "Invalid folder: Folder does not exist or belongs to another \
                 user"
                    .to_string(),
            ));
        }
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

    query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, \
         favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7 AND \
         user_id = ?8",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
        claims.sub,
    )
    .map_err(|e| {
        log::error!("Failed to bind update cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update cipher".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Failed to execute update cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update cipher".to_string(),
        ))
    })?;

    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    User::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers - list all non-trashed ciphers for current user
#[worker::send]
pub async fn list_ciphers(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<RawJson, AppError> {
    let db = state.get_db();
    let include_attachments = AttachmentDB::attachments_enabled(&state.env);
    let ciphers_json = fetch_cipher_json_array_raw(
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

    Ok(RawJson(response))
}

/// GET /api/ciphers/{id}
#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = state.get_db();
    let cipher = fetch_cipher_for_user(&db, &id, &claims.sub).await?;
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
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), user_id.clone().into()])
            .map_err(|e| {
                log::error!("Failed to bind folder ownership query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to validate folder".to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to execute folder ownership query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to validate folder".to_string(),
                ))
            })?;

        if folder_exists.is_none() {
            return Err(AppError::Params(
                "Invalid folder: Folder does not exist or belongs to another \
                 user"
                    .to_string(),
            ));
        }
    }

    // Ensure cipher exists and belongs to user
    fetch_cipher_for_user(&db, &id, user_id).await?;

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    query!(
        &db,
        "UPDATE ciphers SET folder_id = ?1, favorite = ?2, updated_at = ?3 \
         WHERE id = ?4 AND user_id = ?5",
        payload.folder_id,
        payload.favorite,
        now,
        id,
        user_id,
    )
    .map_err(|e| {
        log::error!("Failed to bind update cipher partial query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update cipher".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Failed to execute update cipher partial query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to update cipher".to_string(),
        ))
    })?;

    User::touch_user_updated_at(&db, user_id).await?;

    let cipher = fetch_cipher_for_user(&db, &id, user_id).await?;
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

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2 \
         AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|e| {
        log::error!("Failed to bind soft-delete cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to soft-delete cipher".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Failed to execute soft-delete cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to soft-delete cipher".to_string(),
        ))
    })?;

    User::touch_user_updated_at(&db, &claims.sub).await?;

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

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE user_id = \
         ?2 AND id IN (SELECT value FROM json_each(?3, '$.ids'))",
        now,
        claims.sub,
        body
    )
    .map_err(|e| {
        log::error!("Failed to bind bulk soft-delete query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to soft-delete ciphers".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| map_d1_json_error(&e))?;

    User::touch_user_updated_at(&db, &claims.sub).await?;

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

    query!(
        &db,
        "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|e| {
        log::error!("Failed to bind hard-delete cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to delete cipher".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Failed to execute hard-delete cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to delete cipher".to_string(),
        ))
    })?;

    User::touch_user_updated_at(&db, &claims.sub).await?;

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

    query!(
        &db,
        "DELETE FROM ciphers WHERE user_id = ?1 AND id IN (SELECT value FROM \
         json_each(?2, '$.ids'))",
        claims.sub,
        body
    )
    .map_err(|e| {
        log::error!("Failed to bind bulk hard-delete query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to delete ciphers".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| map_d1_json_error(&e))?;

    User::touch_user_updated_at(&db, &claims.sub).await?;

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

    // Update the cipher to clear deleted_at
    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 \
         AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|e| {
        log::error!("Failed to bind restore cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to restore cipher".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Failed to execute restore cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to restore cipher".to_string(),
        ))
    })?;

    // Fetch and return the restored cipher
    let cipher_db: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|e| {
        log::error!("Failed to bind fetch restored cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to fetch cipher".to_string(),
        ))
    })?
    .first(None)
    .await
    .map_err(|e| {
        log::error!("Failed to execute fetch restored cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to fetch cipher".to_string(),
        ))
    })?
    .ok_or_else(|| AppError::not_found("Cipher not found"))?;

    let mut cipher: Cipher = cipher_db.into();
    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;

    User::touch_user_updated_at(&db, &claims.sub).await?;

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
) -> Result<RawJson, AppError> {
    let db = state.get_db();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Single bulk UPDATE using json_each() with path
    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE user_id \
         = ?2 AND id IN (SELECT value FROM json_each(?3, '$.ids'))",
        now,
        claims.sub,
        body
    )
    .map_err(|e| {
        log::error!("Failed to bind bulk restore query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to restore ciphers".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| map_d1_json_error(&e))?;

    let include_attachments = AttachmentDB::attachments_enabled(&state.env);
    let ciphers_json = fetch_cipher_json_array_raw(
        &db,
        include_attachments,
        "WHERE c.user_id = ?1 AND c.id IN (SELECT value FROM json_each(?2, \
         '$.ids'))",
        &[claims.sub.clone().into(), body.clone().into()],
        "",
    )
    .await?;

    User::touch_user_updated_at(&db, &claims.sub).await?;

    // Build response JSON via string concatenation (no parsing!)
    let response = format!(
        r#"{{"data":{ciphers_json},"object":"list","continuationToken":null}}"#
    );

    Ok(RawJson(response))
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

    query!(
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
    .map_err(|e| {
        log::error!("Failed to bind insert cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to insert cipher".to_string(),
        ))
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("Failed to execute insert cipher query: {e}");
        AppError::Database(DatabaseError::QueryFailed(
            "Failed to insert cipher".to_string(),
        ))
    })?;

    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    User::touch_user_updated_at(&db, &claims.sub).await?;

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
    let folder_invalid: Option<Value> = db
        .prepare(
            "SELECT 1 WHERE json_extract(?1, '$.folderId') IS NOT NULL 
             AND NOT EXISTS (
                 SELECT 1 FROM folders WHERE id = json_extract(?1, \
             '$.folderId') AND user_id = ?2
             )",
        )
        .bind(&[body.clone().into(), user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|e| map_d1_json_error(&e))?;

    if folder_invalid.is_some() {
        return Err(AppError::Params(
            "Invalid folder: Folder does not exist or belongs to another user"
                .to_string(),
        ));
    }

    // Update folder_id for all ciphers that belong to the user and are in the
    // ids list Uses json_extract for folderId and json_each for ids array
    db.prepare(
        "UPDATE ciphers SET folder_id = json_extract(?1, '$.folderId'), \
         updated_at = ?2 
         WHERE user_id = ?3 AND id IN (SELECT value FROM json_each(?1, \
         '$.ids'))",
    )
    .bind(&[body.into(), now.into(), user_id.clone().into()])?
    .run()
    .await
    .map_err(|e| map_d1_json_error(&e))?;

    // Update user's revision date
    User::touch_user_updated_at(&db, user_id).await?;

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
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])
        .map_err(|e| {
            log::error!("Failed to bind fetch user query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch user".to_string(),
            ))
        })?
        .first(None)
        .await
        .map_err(|e| {
            log::error!("Failed to execute fetch user query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch user".to_string(),
            ))
        })?
        .ok_or(AppError::Auth(AuthError::UserNotFound))?;
    let user: User = serde_json::from_value(user).map_err(|e| {
        log::error!("Failed to deserialize user row: {e}");
        AppError::Internal
    })?;

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
    query!(&db, "DELETE FROM ciphers WHERE user_id = ?1", user_id)
        .map_err(|e| {
            log::error!("Failed to bind purge ciphers query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to purge ciphers".to_string(),
            ))
        })?
        .run()
        .await
        .map_err(|e| {
            log::error!("Failed to execute purge ciphers query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to purge ciphers".to_string(),
            ))
        })?;

    // Delete all user's folders
    query!(&db, "DELETE FROM folders WHERE user_id = ?1", user_id)
        .map_err(|e| {
            log::error!("Failed to bind purge folders query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to purge folders".to_string(),
            ))
        })?
        .run()
        .await
        .map_err(|e| {
            log::error!("Failed to execute purge folders query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to purge folders".to_string(),
            ))
        })?;

    // Update user's revision date to trigger client sync
    User::touch_user_updated_at(&db, user_id).await?;

    Ok(Json(()))
}

#[derive(Deserialize)]
struct CipherJsonArrayRow {
    ciphers_json: String,
}

/// Build the SQL expression for a single cipher as JSON.
fn cipher_json_expr(attachments_enabled: bool) -> String {
    let attachments_expr = if attachments_enabled {
        "
            (
                SELECT CASE WHEN COUNT(1)=0 THEN NULL ELSE json_group_array(
                    json_object(
                        'id', a.id,
                        'url', NULL,
                        'fileName', a.file_name,
                        'size', CAST(a.file_size AS TEXT),
                        'sizeName',
                            CASE
                                WHEN a.file_size < 1024 THEN printf('%d B', \
         a.file_size)
                                WHEN a.file_size < 1048576 THEN printf('%.1f \
         KB', a.file_size / 1024.0)
                                WHEN a.file_size < 1073741824 THEN \
         printf('%.1f MB', a.file_size / 1048576.0)
                                WHEN a.file_size < 1099511627776 THEN \
         printf('%.1f GB', a.file_size / 1073741824.0)
                                ELSE printf('%.1f TB', a.file_size / \
         1099511627776.0)
                            END,
                        'key', a.akey,
                        'object', 'attachment'
                    )
                ) END
                FROM attachments a
                WHERE a.cipher_id = c.id
            )
        "
    } else {
        "NULL"
    };

    format!(
        "json_object(
            'object', 'cipherDetails',
            'id', c.id,
            'userId', c.user_id,
            'organizationId', c.organization_id,
            'folderId', c.folder_id,
            'type', c.type,
            'favorite', CASE WHEN c.favorite THEN json('true') ELSE \
         json('false') END,
            'edit', json('true'),
            'viewPassword', json('true'),
            'permissions', json_object('delete', json('true'), 'restore', \
         json('true')),
            'organizationUseTotp', json('false'),
            'collectionIds', NULL,
            'revisionDate', c.updated_at,
            'creationDate', c.created_at,
            'deletedDate', c.deleted_at,
            'attachments', {attachments_expr},
            'name', json_extract(c.data, '$.name'),
            'notes', json_extract(c.data, '$.notes'),
            'fields', json_extract(c.data, '$.fields'),
            'passwordHistory', json_extract(c.data, '$.passwordHistory'),
            'reprompt', COALESCE(json_extract(c.data, '$.reprompt'), 0),
            'login', CASE WHEN c.type = 1 THEN json_extract(c.data, '$.login') \
         ELSE NULL END,
            'secureNote', CASE WHEN c.type = 2 THEN json_extract(c.data, \
         '$.secureNote') ELSE NULL END,
            'card', CASE WHEN c.type = 3 THEN json_extract(c.data, '$.card') \
         ELSE NULL END,
            'identity', CASE WHEN c.type = 4 THEN json_extract(c.data, \
         '$.identity') ELSE NULL END,
            'sshKey', CASE WHEN c.type = 5 THEN json_extract(c.data, \
         '$.sshKey') ELSE NULL END
        )"
    )
}

/// Build SQL that returns ciphers as a JSON array string (using
/// `json_group_array`).
fn cipher_json_array_sql(
    attachments_enabled: bool,
    where_clause: &str,
    order_clause: &str,
) -> String {
    let cipher_expr = cipher_json_expr(attachments_enabled);
    // Use a subquery to ensure ORDER BY is applied before json_group_array
    format!(
        "SELECT COALESCE(json_group_array(json(sub.cipher_json)), '[]') AS \
         ciphers_json
        FROM (
            SELECT {cipher_expr} AS cipher_json
            FROM ciphers c
            {where_clause}
            {order_clause}
        ) sub",
    )
}

/// Execute a cipher JSON projection query and return the raw JSON array string.
/// This avoids JSON parsing in Rust, significantly reducing CPU time.
pub(crate) async fn fetch_cipher_json_array_raw(
    db: &worker::D1Database,
    attachments_enabled: bool,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
) -> Result<String, AppError> {
    let sql =
        cipher_json_array_sql(attachments_enabled, where_clause, order_clause);

    let row: Option<CipherJsonArrayRow> = db
        .prepare(&sql)
        .bind(params)
        .map_err(|e| {
            log::error!("Failed to bind cipher JSON projection query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to query ciphers".to_string(),
            ))
        })?
        .first(None)
        .await
        .map_err(|e| map_d1_json_error(&e))?;

    Ok(row.map_or_else(|| "[]".to_string(), |r| r.ciphers_json))
}

fn map_d1_json_error(err: &worker::Error) -> AppError {
    let msg = err.to_string();
    let is_invalid_json = msg.contains("malformed JSON") ||
        msg.contains("Invalid JSON") ||
        msg.contains("json_each") && msg.contains("JSON") ||
        msg.contains("json_extract") && msg.contains("JSON");

    if is_invalid_json {
        log::warn!("Invalid JSON body (D1): {msg}");
        AppError::Params("Invalid JSON body".to_string())
    } else {
        log::error!("D1 query failed: {msg}");
        AppError::Database(DatabaseError::QueryFailed(
            "Database query failed".to_string(),
        ))
    }
}
