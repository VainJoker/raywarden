use axum::{
    Json,
    body::Bytes,
    extract::{
        Multipart,
        Path,
        State,
    },
};
use chrono::Utc;
use log;
use serde::{
    Deserialize,
    Serialize,
};
use uuid::Uuid;
use worker::{
    Bucket,
    D1Database,
    Env,
    HttpMetadata,
};

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::AppError,
    infra::jwtor as jwt,
    models::{
        attachment::{
            AttachmentDB,
            AttachmentResponse,
        },
        cipher::{
            Cipher,
            CipherDB,
        },
        user::UserDB,
    },
};

const SIZE_LEEWAY_BYTES: i64 = 1024 * 1024; // 1 MiB
const DEFAULT_ATTACHMENT_TTL_SECS: i64 = 300; // 5 minutes

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentCreateRequest {
    pub key:           String,
    pub file_name:     String,
    pub file_size:     NumberOrString,
    #[serde(default)]
    #[allow(dead_code)] // We don't support org features and admin requests
    pub admin_request: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUploadResponse {
    pub object:           String,
    pub attachment_id:    String,
    pub url:              String,
    pub file_upload_type: i32,
    #[serde(rename = "cipherResponse")]
    pub cipher_response:  Cipher,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentDeleteResponse {
    pub cipher: Cipher,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct AttachmentDownloadClaims {
    pub sub:           String,
    pub cipher_id:     String,
    pub attachment_id: String,
    pub exp:           usize,
}

fn now_string() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// POST /`api/ciphers/{cipher_id}/attachment/v2`
#[worker::send]
pub async fn create_attachment(
    claims: Claims,
    State(state): State<AppState>,
    Path(cipher_id): Path<String>,
    Json(payload): Json<AttachmentCreateRequest>,
) -> Result<Json<AttachmentUploadResponse>, AppError> {
    // Require bucket; fail directly if missing
    let _bucket = AttachmentDB::require_bucket(&state.env)?;
    let db = state.get_db();
    let base_url = state.get_domain();

    let cipher =
        CipherDB::ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;

    let AttachmentCreateRequest {
        key,
        file_name,
        file_size,
        admin_request: _,
    } = payload;

    if let NumberOrString::String(s) = &file_size &&
        s.trim().is_empty()
    {
        return Err(AppError::Params(
            "Attachment size must be provided".to_string(),
        ));
    }
    let declared_size = match file_size {
        NumberOrString::Number(v) => v,
        NumberOrString::String(v) => v.parse::<i64>().map_err(|e| {
            log::warn!("Invalid attachment size '{v}': {e}");
            AppError::Params("Invalid attachment size".to_string())
        })?,
    };
    if declared_size <= 0 {
        return Err(AppError::Params(
            "Attachment size must be positive".to_string(),
        ));
    }

    enforce_limits(
        &db,
        &state.env,
        &claims.sub,
        declared_size,
        None, // exclude_attachment
    )
    .await?;

    let attachment_id = Uuid::new_v4().to_string();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let pending_attachment = AttachmentDB {
        id:              attachment_id.clone(),
        cipher_id:       cipher.id.clone(),
        file_name:       file_name.clone(),
        file_size:       declared_size,
        akey:            Some(key.clone()),
        created_at:      now.clone(),
        updated_at:      now.clone(),
        organization_id: cipher.organization_id.clone(),
    };

    AttachmentDB::insert_pending(&db, &pending_attachment).await?;

    // Return upload URL pointing to local upload endpoint
    let url = upload_url(
        &state.env,
        base_url,
        &cipher_id,
        &attachment_id,
        &claims.sub,
    )?;
    let mut cipher_response: Cipher = cipher.into();
    hydrate_cipher_attachments(&db, &state.env, &mut cipher_response).await?;

    // add pending attachment to response
    let pending_response = pending_attachment.to_response(None);
    match &mut cipher_response.attachments {
        Some(list) => list.push(pending_response),
        None => cipher_response.attachments = Some(vec![pending_response]),
    }

    // no need to touch cipher updated_at and user updated_at here
    // it will be touched in after upload

    Ok(Json(AttachmentUploadResponse {
        object: "attachment-fileUpload".to_string(),
        attachment_id,
        url,
        file_upload_type: 1, // Direct PUT with token
        cipher_response,
    }))
}

/// POST /`api/ciphers/{cipher_id}/attachment/{attachment_id}`
#[worker::send]
pub async fn upload_attachment_v2_data(
    claims: Claims,
    State(state): State<AppState>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<Json<()>, AppError> {
    let bucket = AttachmentDB::require_bucket(&state.env)?;
    let db = state.get_db();

    let _cipher =
        CipherDB::ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;

    let mut pending =
        AttachmentDB::fetch_pending_attachment(&db, &attachment_id).await?;
    if pending.cipher_id != cipher_id {
        return Err(AppError::Params(
            "Attachment does not belong to cipher".to_string(),
        ));
    }

    let (file_bytes, content_type, key_override, _file_name) =
        read_multipart(&mut multipart).await?;
    let actual_size = file_bytes.len() as i64;

    // Validate actual size against declared value deviation
    if let Err(e) = validate_size_within_declared(&pending, actual_size) {
        AttachmentDB::delete_pending(&db, &pending.id).await?;
        return Err(e);
    }

    // Validate capacity limits (replace with actual size)
    enforce_limits(
        &db,
        &state.env,
        &claims.sub,
        actual_size,
        Some(&pending.id),
    )
    .await?;

    // Need a key
    if pending.akey.is_none() && key_override.is_none() {
        return Err(AppError::Params("No attachment key provided".to_string()));
    }
    if let Some(k) = key_override {
        pending.akey = Some(k);
    }

    // Save to R2
    upload_to_r2(
        &bucket,
        &pending.r2_key(),
        content_type,
        file_bytes.to_vec(),
    )
    .await?;

    // Finalize: move pending -> attachments and touch timestamps
    let now = now_string();
    let finalized = AttachmentDB {
        file_size: actual_size,
        updated_at: now.clone(),
        ..pending.clone()
    };

    AttachmentDB::insert_finalized(&db, &finalized, &now).await?;
    AttachmentDB::delete_pending(&db, &finalized.id).await?;

    CipherDB::touch_cipher_updated_at(&db, &cipher_id).await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// POST /`api/ciphers/{cipher_id}/attachment`
/// Legacy API for creating an attachment associated with a cipher.
#[worker::send]
pub async fn upload_attachment_legacy(
    claims: Claims,
    State(state): State<AppState>,
    Path(cipher_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<Cipher>, AppError> {
    let bucket = AttachmentDB::require_bucket(&state.env)?;
    let db = state.get_db();

    let cipher =
        CipherDB::ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;

    let (file_bytes, content_type, key, file_name) =
        read_multipart(&mut multipart).await?;
    let key = key.ok_or_else(|| {
        AppError::Params("No attachment key provided".to_string())
    })?;
    let file_name = file_name
        .ok_or_else(|| AppError::Params("No filename provided".to_string()))?;

    let actual_size = file_bytes.len() as i64;
    if actual_size <= 0 {
        return Err(AppError::Params(
            "Attachment size must be positive".to_string(),
        ));
    }

    // Validate capacity limits
    enforce_limits(&db, &state.env, &claims.sub, actual_size, None).await?;

    let attachment_id = Uuid::new_v4().to_string();
    let now = now_string();
    let attachment = AttachmentDB {
        id:              attachment_id.clone(),
        cipher_id:       cipher.id.clone(),
        file_name:       file_name.clone(),
        file_size:       actual_size,
        akey:            Some(key.clone()),
        created_at:      now.clone(),
        updated_at:      now.clone(),
        organization_id: cipher.organization_id.clone(),
    };

    AttachmentDB::insert_finalized(&db, &attachment, &now).await?;

    // Save to R2
    upload_to_r2(
        &bucket,
        &format!("{cipher_id}/{attachment_id}"),
        content_type,
        file_bytes.to_vec(),
    )
    .await?;

    CipherDB::touch_cipher_updated_at(&db, &cipher_id).await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    // reload cipher to return fresh updated_at and attachments state
    let mut cipher_response: Cipher = cipher.into();
    hydrate_cipher_attachments(&db, &state.env, &mut cipher_response).await?;

    Ok(Json(cipher_response))
}

/// GET /`api/ciphers/{cipher_id}/attachment/{attachment_id}`
#[worker::send]
pub async fn get_attachment(
    claims: Claims,
    State(state): State<AppState>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<AttachmentResponse>, AppError> {
    let base_url = state.get_domain();
    let _bucket = AttachmentDB::require_bucket(&state.env)?;
    let db = state.get_db();

    let cipher =
        CipherDB::ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;
    let attachment =
        AttachmentDB::fetch_attachment(&db, &attachment_id).await?;

    if attachment.cipher_id != cipher.id {
        return Err(AppError::Params(
            "Attachment does not belong to cipher".to_string(),
        ));
    }

    let url = download_url(
        &state.env,
        base_url,
        &cipher_id,
        &attachment_id,
        &claims.sub,
    )?;
    Ok(Json(attachment.to_response(Some(url))))
}

/// DELETE /`api/ciphers/{cipher_id}/attachment/{attachment_id}`
#[worker::send]
pub async fn delete_attachment(
    claims: Claims,
    State(state): State<AppState>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<AttachmentDeleteResponse>, AppError> {
    let bucket = AttachmentDB::require_bucket(&state.env)?;
    let db = state.get_db();

    let cipher =
        CipherDB::ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;
    let attachment =
        AttachmentDB::fetch_attachment(&db, &attachment_id).await?;

    if attachment.cipher_id != cipher.id {
        return Err(AppError::Params(
            "Attachment does not belong to cipher".to_string(),
        ));
    }

    // Delete R2 object; ignore missing objects
    AttachmentDB::delete_r2_objects(&bucket, &[attachment.r2_key()]).await?;

    AttachmentDB::delete_attachment(&db, &attachment.id).await?;

    CipherDB::touch_cipher_updated_at(&db, &cipher_id).await?;
    UserDB::touch_user_updated_at(&db, &claims.sub).await?;

    // Reload cipher to return fresh updated_at and attachments state
    let mut cipher_response: Cipher =
        CipherDB::ensure_cipher_for_user(&db, &cipher_id, &claims.sub)
            .await?
            .into();
    hydrate_cipher_attachments(&db, &state.env, &mut cipher_response).await?;

    Ok(Json(AttachmentDeleteResponse {
        cipher: cipher_response,
    }))
}

/// POST /`api/ciphers/{cipher_id}/attachment/{attachment_id}/delete`
/// Legacy API for deleting an attachment associated with a cipher.
#[worker::send]
pub async fn delete_attachment_post(
    claims: Claims,
    State(state): State<AppState>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<AttachmentDeleteResponse>, AppError> {
    delete_attachment(claims, State(state), Path((cipher_id, attachment_id)))
        .await
}

/// Attach attachment information to Cipher (used by other handlers)
pub async fn hydrate_cipher_attachments(
    db: &D1Database,
    env: &Env,
    cipher: &mut Cipher,
) -> Result<(), AppError> {
    if !AttachmentDB::attachments_enabled(env) {
        cipher.attachments = None;
        return Ok(());
    }

    let ids_json = serde_json::to_string(&[&cipher.id]).map_err(|e| {
        log::error!("Failed to serialize cipher id list: {e}");
        AppError::Internal
    })?;
    let mut map =
        AttachmentDB::load_attachment_map_json(db, &ids_json, "$").await?;
    if let Some(list) = map.remove(&cipher.id) &&
        !list.is_empty()
    {
        cipher.attachments = Some(list);
    }
    Ok(())
}

fn download_url(
    env: &Env,
    base_url: &str,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
) -> Result<String, AppError> {
    let token = build_download_token(env, user_id, cipher_id, attachment_id)?;
    let normalized_base = base_url.trim_end_matches('/');
    Ok(format!(
        "{normalized_base}/api/ciphers/{cipher_id}/attachment/{attachment_id}/\
         download?token={token}"
    ))
}

async fn upload_to_r2(
    bucket: &Bucket,
    key: &str,
    content_type: Option<String>,
    data: Vec<u8>,
) -> Result<(), AppError> {
    let mut builder = bucket.put(key, data);

    if let Some(ct) = content_type {
        builder = builder.http_metadata(HttpMetadata {
            content_type: Some(ct),
            ..Default::default()
        });
    }

    builder.execute().await.map_err(AppError::Worker)?;
    Ok(())
}

async fn read_multipart(
    multipart: &mut Multipart,
) -> Result<(Bytes, Option<String>, Option<String>, Option<String>), AppError> {
    let mut file_bytes: Option<Bytes> = None;
    let mut content_type: Option<String> = None;
    let mut key: Option<String> = None;
    let mut file_name: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        log::warn!("Invalid multipart data: {e}");
        AppError::Params("Invalid multipart data".to_string())
    })? {
        match field.name() {
            Some("data") => {
                content_type = field.content_type().map(ToString::to_string);
                file_name = field.file_name().map(ToString::to_string);
                file_bytes = Some(field.bytes().await.map_err(|e| {
                    log::warn!("Failed to read attachment data bytes: {e}");
                    AppError::Params(
                        "Failed to read attachment data".to_string(),
                    )
                })?);
            }
            Some("key") => {
                key = Some(field.text().await.map_err(|e| {
                    log::warn!("Invalid attachment key field: {e}");
                    AppError::Params("Invalid key field".to_string())
                })?);
            }
            _ => {}
        }
    }

    let file_bytes = file_bytes.ok_or_else(|| {
        AppError::Params("No attachment data provided".to_string())
    })?;

    Ok((file_bytes, content_type, key, file_name))
}

fn validate_size_within_declared(
    attachment: &AttachmentDB,
    actual_size: i64,
) -> Result<(), AppError> {
    let max_size = attachment
        .file_size
        .checked_add(SIZE_LEEWAY_BYTES)
        .ok_or_else(|| {
            AppError::Params("Attachment size overflow".to_string())
        })?;
    let min_size = attachment
        .file_size
        .checked_sub(SIZE_LEEWAY_BYTES)
        .ok_or_else(|| {
            AppError::Params("Attachment size overflow".to_string())
        })?;

    if actual_size < min_size || actual_size > max_size {
        return Err(AppError::Params(format!(
            "Attachment size mismatch (expected within [{min_size}, \
             {max_size}], got {actual_size})"
        )));
    }

    Ok(())
}

fn build_download_token(
    env: &Env,
    user_id: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<String, AppError> {
    let ttl_secs = download_ttl_secs(env)?;
    let now = Utc::now().timestamp();
    let exp = now
        .checked_add(ttl_secs)
        .ok_or_else(|| AppError::Internal)?;

    if exp < 0 {
        log::error!(
            "Computed negative expiration for attachment token: \
             cipher={cipher_id}, attachment={attachment_id}"
        );
        return Err(AppError::Internal);
    }

    let claims = AttachmentDownloadClaims {
        sub:           user_id.to_string(),
        cipher_id:     cipher_id.to_string(),
        attachment_id: attachment_id.to_string(),
        exp:           exp as usize,
    };

    let secret = jwt_secret(env)?;
    jwt::encode(&claims, secret.as_bytes()).map_err(AppError::from)
}

fn upload_url(
    env: &Env,
    base_url: &str,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
) -> Result<String, AppError> {
    let token = build_download_token(env, user_id, cipher_id, attachment_id)?;
    let normalized_base = base_url.trim_end_matches('/');
    Ok(format!(
        "{normalized_base}/api/ciphers/{cipher_id}/attachment/{attachment_id}/\
         azure-upload?token={token}"
    ))
}

fn jwt_secret(env: &Env) -> Result<String, AppError> {
    Ok(env.secret("JWT_SECRET")?.to_string())
}

fn download_ttl_secs(env: &Env) -> Result<i64, AppError> {
    match env.var("ATTACHMENT_TTL_SECS") {
        Ok(v) => {
            let raw = v.to_string();
            let ttl = raw.parse::<i64>().map_err(|err| {
                log::error!("Invalid ATTACHMENT_TTL_SECS '{raw}': {err}");
                AppError::Internal
            })?;

            if ttl <= 0 {
                log::error!("ATTACHMENT_TTL_SECS '{raw}' must be positive");
                return Err(AppError::Internal);
            }

            Ok(ttl)
        }
        Err(_) => Ok(DEFAULT_ATTACHMENT_TTL_SECS),
    }
}

async fn enforce_limits(
    db: &D1Database,
    env: &Env,
    user_id: &str,
    new_size: i64,
    exclude_attachment: Option<&str>,
) -> Result<(), AppError> {
    if new_size < 0 {
        return Err(AppError::Params(
            "Attachment size cannot be negative".to_string(),
        ));
    }

    let max_bytes = attachment_max_bytes(env)?;
    if let Some(max_bytes) = max_bytes &&
        new_size as u64 > max_bytes
    {
        return Err(AppError::Params(
            "Attachment size exceeds limit".to_string(),
        ));
    }

    let limit_bytes = total_limit_bytes(env)?;
    if let Some(limit_bytes) = limit_bytes {
        let used = AttachmentDB::user_attachment_usage(
            db,
            user_id,
            exclude_attachment,
        )
        .await?;
        let limit = limit_bytes as i64;
        let new_total = used.checked_add(new_size).ok_or_else(|| {
            AppError::Params("Attachment size overflow".to_string())
        })?;

        if new_total > limit {
            return Err(AppError::Params(
                "Attachment storage limit reached".to_string(),
            ));
        }
    }

    Ok(())
}

fn attachment_max_bytes(env: &Env) -> Result<Option<u64>, AppError> {
    match env.var("ATTACHMENT_MAX_BYTES") {
        Ok(v) => {
            let raw = v.to_string();
            raw.parse::<u64>().map(Some).map_err(|err| {
                log::error!("Invalid ATTACHMENT_MAX_BYTES '{raw}': {err}");
                AppError::Internal
            })
        }
        Err(_) => Ok(None),
    }
}

fn total_limit_bytes(env: &Env) -> Result<Option<u64>, AppError> {
    match env.var("ATTACHMENT_TOTAL_LIMIT_KB") {
        Ok(v) => {
            let raw = v.to_string();
            let kb = raw.parse::<u64>().map_err(|err| {
                log::error!("Invalid ATTACHMENT_TOTAL_LIMIT_KB '{raw}': {err}");
                AppError::Internal
            })?;

            let bytes = kb.checked_mul(1024).ok_or_else(|| {
                log::error!(
                    "ATTACHMENT_TOTAL_LIMIT_KB '{raw}' overflowed when \
                     converting to bytes"
                );
                AppError::Internal
            })?;

            Ok(Some(bytes))
        }
        Err(_) => Ok(None),
    }
}
