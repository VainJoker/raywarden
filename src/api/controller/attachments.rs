use axum::{
    Json,
    body::Body,
    extract::{
        Multipart,
        Path,
        Query,
        State,
    },
    http::{
        HeaderMap,
        Method,
        StatusCode,
        header,
    },
    response::Response,
};
use log;
use serde::{
    Deserialize,
    Serialize,
};
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::{
    D1Database,
    D1PreparedStatement,
    Env,
};

use crate::{
    api::{
        AppState,
        service::{
            attachments::{
                hydrate_cipher_attachments,
                stable_url,
            },
            cipher_mutation,
            claims::Claims,
            notifications::{
                self,
                UpdateType,
            },
        },
    },
    errors::AppError,
    infra::{
        admin_notify::{
            self,
            Event,
        },
        jwt,
        storage::Storage,
    },
    models::{
        attachment::{
            AttachmentDB,
            AttachmentResponse,
        },
        cipher::{
            Cipher,
            CipherDB,
        },
    },
};

const SIZE_LEEWAY_BYTES: i64 = 1024 * 1024; // 1 MiB
const DEFAULT_ATTACHMENT_TTL_SECS: i64 = 60; // signed metadata URL
const MAX_MULTIPART_METADATA_BYTES: usize = 16 * 1024;

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
    pub exp:           i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device:        Option<String>,
}

#[derive(Deserialize)]
pub struct AttachmentTokenQuery {
    token: Option<String>,
}

struct UploadedMultipart {
    size:      u64,
    key:       Option<String>,
    file_name: Option<String>,
}

fn now_string() -> String {
    crate::infra::time::now_rfc3339()
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
    let _bucket = crate::infra::storage::Storage::from_env(&state.env)?;
    let db = state.get_db();
    let key_guard = cipher_mutation::account_key_guard(&db, &claims).await?;
    let base_url = state.get_domain();

    let cipher = ensure_mutable_cipher(&db, &cipher_id, &claims.sub).await?;

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
    let now = crate::infra::time::now_rfc3339();
    let pending_attachment = AttachmentDB {
        id:              attachment_id.clone(),
        cipher_id:       cipher.id.clone(),
        file_name:       file_name.clone(),
        file_size:       declared_size,
        akey:            Some(key.clone()),
        created_at:      now.clone(),
        updated_at:      now.clone(),
        organization_id: cipher.organization_id.clone(),
        storage_key:     None,
    };

    let guards = vec![
        key_guard,
        cipher_mutation::cipher_snapshot_guard(&db, &cipher)?,
    ];
    let pending_write = db
        .prepare(
            "INSERT INTO \
             attachments_pending(id,cipher_id,file_name,file_size,akey,\
             created_at,updated_at,organization_id) \
             VALUES(?1,?2,?3,?4,?5,?6,?6,?7)",
        )
        .bind(&[
            pending_attachment.id.clone().into(),
            pending_attachment.cipher_id.clone().into(),
            pending_attachment.file_name.clone().into(),
            JsValue::from_f64(pending_attachment.file_size as f64),
            pending_attachment
                .akey
                .clone()
                .map(Into::into)
                .unwrap_or(JsValue::NULL),
            pending_attachment.created_at.clone().into(),
            pending_attachment
                .organization_id
                .clone()
                .map(Into::into)
                .unwrap_or(JsValue::NULL),
        ])?;

    // Return upload URL pointing to local upload endpoint
    let url = upload_url(
        &state.env,
        base_url,
        &cipher_id,
        &attachment_id,
        &claims.sub,
        claims.device(),
    )
    .await?;
    let mut cipher_response: Cipher = cipher.into_api()?;
    hydrate_cipher_attachments(&db, &state.env, &mut cipher_response).await?;

    // add pending attachment to response
    let pending_response = pending_attachment.to_response(Some(stable_url(
        &state.env,
        &cipher_id,
        &attachment_id,
    )?));
    match &mut cipher_response.attachments {
        Some(list) => list.push(pending_response),
        None => cipher_response.attachments = Some(vec![pending_response]),
    }

    cipher_mutation::commit(&db, &claims, guards, vec![pending_write]).await?;

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
    let storage = Storage::from_env(&state.env)?;
    let db = state.get_db();
    let key_guard = cipher_mutation::account_key_guard(&db, &claims).await?;
    let cipher = ensure_mutable_cipher(&db, &cipher_id, &claims.sub).await?;
    let (mut pending, replacing) =
        match pending_for_cipher(&db, &cipher_id, &attachment_id).await {
            Ok(row) => (row, false),
            Err(AppError::NotFound { .. }) => {
                let row =
                    AttachmentDB::fetch_attachment(&db, &attachment_id).await?;
                if row.cipher_id != cipher_id {
                    return Err(AppError::bad_request(
                        "Attachment does not belong to cipher",
                    ));
                }
                (row, true)
            }
            Err(error) => return Err(error),
        };
    enforce_limits(
        &db,
        &state.env,
        &claims.sub,
        pending.file_size,
        Some(&pending.id),
    )
    .await?;
    let max_bytes =
        upload_limit(&db, &state.env, &claims.sub, Some(&pending)).await?;
    let guards = vec![
        key_guard,
        cipher_mutation::cipher_snapshot_guard(&db, &cipher)?,
        if replacing {
            attachment_snapshot_guard(&db, &pending)?
        } else {
            pending_snapshot_guard(&db, &pending)?
        },
    ];
    let object_key = staged_key(&cipher_id, &attachment_id);
    pending.storage_key = Some(object_key.clone());
    let result = async {
        let uploaded =
            read_multipart(&mut multipart, &storage, &object_key, max_bytes)
                .await?;
        let actual_size = size_as_i64(uploaded.size)?;
        validate_size_within_declared(&pending, actual_size)?;
        enforce_limits(
            &db,
            &state.env,
            &claims.sub,
            actual_size,
            Some(&pending.id),
        )
        .await?;
        if let Some(key) = uploaded.key {
            pending.akey = Some(key);
        }
        if pending.akey.is_none() {
            return Err(AppError::bad_request("No attachment key provided"));
        }
        pending.file_size = actual_size;
        let writes = if replacing {
            AttachmentDB::replace_upload(
                &db,
                &pending,
                &claims.sub,
                &now_string(),
            )?
        } else {
            AttachmentDB::finalize_upload(
                &db,
                &pending,
                &claims.sub,
                &now_string(),
            )?
        };
        cipher_mutation::commit(&db, &claims, guards, writes)
            .await
            .map(|_| ())
    }
    .await;
    if let Err(error) = result {
        cleanup_upload(&state.env, &db, &object_key).await;
        return Err(error);
    }
    publish_upload(&state.env, &claims.sub, &cipher_id, claims.device()).await;
    Ok(Json(()))
}

/// PUT capability URL returned by the v2 metadata endpoint.
#[worker::send]
pub async fn upload_attachment_azure(
    State(state): State<AppState>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    Query(query): Query<AttachmentTokenQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, AppError> {
    let claims = attachment_claims(
        query.token.as_deref(),
        &state.config.jwt_secret,
        &cipher_id,
        &attachment_id,
    )?;
    let storage = Storage::from_env(&state.env)?;
    let db = state.get_db();
    let key_guard =
        cipher_mutation::account_snapshot_guard(&db, &claims.sub).await?;
    let cipher = ensure_mutable_cipher(&db, &cipher_id, &claims.sub).await?;
    let mut pending =
        pending_for_cipher(&db, &cipher_id, &attachment_id).await?;
    let content_length = upload_content_length(&headers)?;
    let expected = content_length
        .map(size_as_i64)
        .transpose()?
        .unwrap_or(pending.file_size);
    enforce_limits(&db, &state.env, &claims.sub, expected, Some(&pending.id))
        .await?;
    let max_bytes =
        upload_limit(&db, &state.env, &claims.sub, Some(&pending)).await?;
    if content_length.is_some_and(|size| size > max_bytes) {
        return Err(AppError::bad_request("Attachment size exceeds limit"));
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let guards = vec![
        key_guard,
        cipher_mutation::cipher_snapshot_guard(&db, &cipher)?,
        pending_snapshot_guard(&db, &pending)?,
    ];
    let object_key = staged_key(&cipher_id, &attachment_id);
    pending.storage_key = Some(object_key.clone());
    let result = async {
        let size = storage
            .put_stream(
                &object_key,
                body.into_data_stream(),
                max_bytes,
                content_type,
            )
            .await?;
        if content_length.is_some_and(|expected| expected != size) {
            return Err(AppError::bad_request(
                "Content-Length does not match uploaded size",
            ));
        }
        let actual_size = size_as_i64(size)?;
        validate_size_within_declared(&pending, actual_size)?;
        enforce_limits(
            &db,
            &state.env,
            &claims.sub,
            actual_size,
            Some(&pending.id),
        )
        .await?;
        pending.file_size = actual_size;
        let writes = AttachmentDB::finalize_upload(
            &db,
            &pending,
            &claims.sub,
            &now_string(),
        )?;
        cipher_mutation::commit_capability(&db, &claims.sub, guards, writes)
            .await
            .map(|_| ())
    }
    .await;
    if let Err(error) = result {
        cleanup_upload(&state.env, &db, &object_key).await;
        return Err(error);
    }
    publish_upload(
        &state.env,
        &claims.sub,
        &cipher_id,
        claims.device.as_deref(),
    )
    .await;
    Ok(StatusCode::CREATED)
}

/// GET/HEAD capability URL. Authorization stays independent of any bearer.
#[worker::send]
pub async fn download_attachment(
    State(state): State<AppState>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    Query(query): Query<AttachmentTokenQuery>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let claims = attachment_claims(
        query.token.as_deref(),
        &state.config.jwt_secret,
        &cipher_id,
        &attachment_id,
    )?;
    let db = state.get_db();
    // Signed download URLs retain the previous read policy, including trash.
    CipherDB::fetch_for_user(&db, &cipher_id, &claims.sub).await?;
    let attachment =
        AttachmentDB::fetch_attachment(&db, &attachment_id).await?;
    if attachment.cipher_id != cipher_id {
        return Err(AppError::bad_request(
            "Attachment does not belong to cipher",
        ));
    }
    Storage::from_env(&state.env)?
        .download(&attachment.r2_key(), &headers, method == Method::HEAD)
        .await
}

/// POST /`api/ciphers/{cipher_id}/attachment` (legacy multipart upload).
#[worker::send]
pub async fn upload_attachment_legacy(
    claims: Claims,
    State(state): State<AppState>,
    Path(cipher_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<Cipher>, AppError> {
    let storage = Storage::from_env(&state.env)?;
    let db = state.get_db();
    let key_guard = cipher_mutation::account_key_guard(&db, &claims).await?;
    let cipher = ensure_mutable_cipher(&db, &cipher_id, &claims.sub).await?;
    let attachment_id = Uuid::new_v4().to_string();
    let object_key = staged_key(&cipher_id, &attachment_id);
    let guards = vec![
        key_guard,
        cipher_mutation::cipher_snapshot_guard(&db, &cipher)?,
    ];
    let mut cipher_response: Cipher = cipher.clone().into_api()?;
    hydrate_cipher_attachments(&db, &state.env, &mut cipher_response).await?;
    let max_bytes = upload_limit(&db, &state.env, &claims.sub, None).await?;
    let result = async {
        let uploaded =
            read_multipart(&mut multipart, &storage, &object_key, max_bytes)
                .await?;
        let key = uploaded.key.ok_or_else(|| {
            AppError::bad_request("No attachment key provided")
        })?;
        let file_name = uploaded
            .file_name
            .ok_or_else(|| AppError::bad_request("No filename provided"))?;
        let actual_size = size_as_i64(uploaded.size)?;
        if actual_size <= 0 {
            return Err(AppError::bad_request(
                "Attachment size must be positive",
            ));
        }
        enforce_limits(&db, &state.env, &claims.sub, actual_size, None).await?;
        let now = now_string();
        let attachment = AttachmentDB {
            id: attachment_id,
            cipher_id: cipher_id.clone(),
            file_name,
            file_size: actual_size,
            akey: Some(key),
            created_at: now.clone(),
            updated_at: now.clone(),
            organization_id: cipher.organization_id.clone(),
            storage_key: Some(object_key.clone()),
        };
        let response = attachment.to_response(Some(stable_url(
            &state.env,
            &cipher_id,
            &attachment.id,
        )?));
        cipher_response
            .attachments
            .get_or_insert_with(Vec::new)
            .push(response);
        cipher_response.updated_at = now.clone();
        let writes =
            AttachmentDB::finalize_upload(&db, &attachment, &claims.sub, &now)?;
        cipher_mutation::commit(&db, &claims, guards, writes)
            .await
            .map(|_| ())
    }
    .await;
    if let Err(error) = result {
        cleanup_upload(&state.env, &db, &object_key).await;
        return Err(error);
    }
    publish_upload(&state.env, &claims.sub, &cipher_id, claims.device()).await;
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
    let _bucket = crate::infra::storage::Storage::from_env(&state.env)?;
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
        claims.device(),
    )
    .await?;
    Ok(Json(attachment.to_response(Some(url))))
}

/// DELETE /`api/ciphers/{cipher_id}/attachment/{attachment_id}`
#[worker::send]
pub async fn delete_attachment(
    claims: Claims,
    State(state): State<AppState>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<AttachmentDeleteResponse>, AppError> {
    let db = state.get_db();
    let cipher =
        CipherDB::ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;
    let attachment =
        AttachmentDB::fetch_attachment(&db, &attachment_id).await?;
    if attachment.cipher_id != cipher_id {
        return Err(AppError::bad_request(
            "Attachment does not belong to cipher",
        ));
    }
    let guards = vec![
        cipher_mutation::cipher_snapshot_guard(&db, &cipher)?,
        cipher_mutation::guard(
            &db,
            "EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2 \
             AND file_name IS ?3 AND akey IS ?4 AND storage_key IS ?5 AND \
             updated_at IS ?6)",
            &[
                attachment.id.clone().into(),
                cipher_id.clone().into(),
                attachment.file_name.clone().into(),
                attachment
                    .akey
                    .clone()
                    .map(Into::into)
                    .unwrap_or(JsValue::NULL),
                attachment
                    .storage_key
                    .clone()
                    .map(Into::into)
                    .unwrap_or(JsValue::NULL),
                attachment.updated_at.clone().into(),
            ],
        )?,
    ];
    let now = now_string();
    let writes = vec![
        db.prepare("DELETE FROM attachments WHERE id=?1 AND cipher_id=?2")
            .bind(&[attachment_id.clone().into(), cipher_id.clone().into()])?,
        db.prepare(
            "UPDATE ciphers SET updated_at=?1 WHERE id=?2 AND user_id=?3",
        )
        .bind(&[
            now.clone().into(),
            cipher_id.clone().into(),
            claims.sub.clone().into(),
        ])?,
    ];
    let mut cipher_response: Cipher = cipher.into_api()?;
    hydrate_cipher_attachments(&db, &state.env, &mut cipher_response).await?;
    if let Some(list) = &mut cipher_response.attachments {
        list.retain(|item| item.id != attachment_id);
        if list.is_empty() {
            cipher_response.attachments = None;
        }
    }
    cipher_response.updated_at = now;
    let revision =
        cipher_mutation::commit(&db, &claims, guards, writes).await?;
    crate::api::service::ciphers::notify_cipher(
        &state,
        &claims,
        UpdateType::SyncCipherUpdate,
        &cipher_id,
        &revision,
    )
    .await;
    if let Err(error) =
        crate::infra::storage::cleanup::drain(&state.env, &db).await
    {
        log::warn!("Attachment cleanup deferred: {error}");
    }

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

async fn download_url(
    env: &Env,
    base_url: &str,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
    device: Option<&str>,
) -> Result<String, AppError> {
    let token =
        build_download_token(env, user_id, cipher_id, attachment_id, device)
            .await?;
    let normalized_base = base_url.trim_end_matches('/');
    Ok(format!(
        "{normalized_base}/attachments/{cipher_id}/{attachment_id}?\
         token={token}"
    ))
}

async fn read_multipart(
    multipart: &mut Multipart,
    storage: &Storage,
    object_key: &str,
    max_bytes: u64,
) -> Result<UploadedMultipart, AppError> {
    let mut size = None;
    let mut key = None;
    let mut file_name = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_error| AppError::bad_request("Invalid multipart data"))?
    {
        if field.name() == Some("data") {
            if size.is_some() {
                return Err(AppError::bad_request(
                    "Multiple attachment data fields",
                ));
            }
            file_name = field.file_name().map(ToString::to_string);
            if file_name
                .as_ref()
                .is_some_and(|name| name.len() > MAX_MULTIPART_METADATA_BYTES)
            {
                return Err(AppError::bad_request(
                    "Attachment filename is too long",
                ));
            }
            let content_type = field.content_type().map(ToString::to_string);
            size = Some(
                storage
                    .put_stream(
                        object_key,
                        field,
                        max_bytes,
                        content_type.as_deref(),
                    )
                    .await?,
            );
        } else {
            let is_key = field.name() == Some("key");
            let mut text = Vec::new();
            while let Some(chunk) = field.chunk().await.map_err(|_error| {
                AppError::bad_request("Invalid multipart field")
            })? {
                append_metadata(&mut text, &chunk)?;
            }
            if is_key {
                key = Some(String::from_utf8(text).map_err(|_error| {
                    AppError::bad_request("Invalid attachment key")
                })?);
            }
        }
    }
    Ok(UploadedMultipart {
        size: size.ok_or_else(|| {
            AppError::bad_request("No attachment data provided")
        })?,
        key,
        file_name,
    })
}

fn append_metadata(data: &mut Vec<u8>, chunk: &[u8]) -> Result<(), AppError> {
    if chunk.len() > MAX_MULTIPART_METADATA_BYTES.saturating_sub(data.len()) {
        return Err(AppError::bad_request("Multipart metadata is too large"));
    }
    data.extend_from_slice(chunk);
    Ok(())
}

async fn cleanup_upload(env: &Env, db: &D1Database, key: &str) {
    crate::infra::storage::cleanup::discard_staged_object(env, db, key).await;
}

async fn publish_upload(
    env: &Env,
    user_id: &str,
    cipher_id: &str,
    device: Option<&str>,
) {
    notifications::publish_cipher_update(
        env,
        user_id,
        UpdateType::SyncCipherUpdate,
        cipher_id,
        &now_string(),
        device,
    )
    .await;
    admin_notify::emit(env, Event::VaultChanged, user_id).await;
    if let Ok(db) = env.d1("warden-db") {
        if let Err(error) =
            crate::infra::storage::cleanup::drain(env, &db).await
        {
            log::warn!("Completed attachment object cleanup deferred: {error}");
        }
    }
}

fn staged_key(cipher_id: &str, attachment_id: &str) -> String {
    format!("attachments/{cipher_id}/{attachment_id}/{}", Uuid::new_v4())
}
fn pending_snapshot_guard(
    db: &D1Database,
    row: &AttachmentDB,
) -> Result<D1PreparedStatement, AppError> {
    cipher_mutation::guard(
        db,
        "EXISTS(SELECT 1 FROM attachments_pending WHERE id=?1 AND \
         cipher_id=?2 AND file_name IS ?3 AND file_size IS ?4 AND akey IS ?5 \
         AND created_at IS ?6 AND updated_at IS ?7 AND organization_id IS ?8)",
        &[
            row.id.clone().into(),
            row.cipher_id.clone().into(),
            row.file_name.clone().into(),
            JsValue::from_f64(row.file_size as f64),
            row.akey.clone().map(Into::into).unwrap_or(JsValue::NULL),
            row.created_at.clone().into(),
            row.updated_at.clone().into(),
            row.organization_id
                .clone()
                .map(Into::into)
                .unwrap_or(JsValue::NULL),
        ],
    )
}

fn attachment_snapshot_guard(
    db: &D1Database,
    row: &AttachmentDB,
) -> Result<D1PreparedStatement, AppError> {
    cipher_mutation::guard(
        db,
        "EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2 AND \
         file_name IS ?3 AND file_size IS ?4 AND akey IS ?5 AND created_at IS \
         ?6 AND updated_at IS ?7 AND organization_id IS ?8 AND storage_key IS \
         ?9) AND NOT EXISTS(SELECT 1 FROM attachments_pending WHERE id=?1)",
        &[
            row.id.clone().into(),
            row.cipher_id.clone().into(),
            row.file_name.clone().into(),
            JsValue::from_f64(row.file_size as f64),
            row.akey.clone().map(Into::into).unwrap_or(JsValue::NULL),
            row.created_at.clone().into(),
            row.updated_at.clone().into(),
            row.organization_id
                .clone()
                .map(Into::into)
                .unwrap_or(JsValue::NULL),
            row.storage_key
                .clone()
                .map(Into::into)
                .unwrap_or(JsValue::NULL),
        ],
    )
}

async fn ensure_mutable_cipher(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherDB, AppError> {
    let cipher = CipherDB::fetch_for_user(db, cipher_id, user_id).await?;
    if cipher.organization_id.is_some() {
        return Err(AppError::bad_request(
            "Organization attachments are not supported",
        ));
    }
    if cipher.deleted_at.is_some() {
        return Err(AppError::bad_request(
            "Cannot modify attachments for deleted cipher",
        ));
    }
    Ok(cipher)
}

async fn pending_for_cipher(
    db: &D1Database,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<AttachmentDB, AppError> {
    let pending =
        AttachmentDB::fetch_pending_attachment(db, attachment_id).await?;
    if pending.cipher_id != cipher_id {
        return Err(AppError::bad_request(
            "Attachment does not belong to cipher",
        ));
    }
    Ok(pending)
}

fn attachment_claims(
    token: Option<&str>,
    secret: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<AttachmentDownloadClaims, AppError> {
    let token = token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AppError::bad_request("Missing token"))?;
    let claims = jwt::decode::<AttachmentDownloadClaims>(
        token,
        secret.as_bytes(),
        &jwt::ValidationOptions::default(),
    )?
    .claims;
    if claims.sub.is_empty() ||
        claims.cipher_id != cipher_id ||
        claims.attachment_id != attachment_id
    {
        return Err(AppError::Unauthorized {
            message: "Invalid token".to_string(),
        });
    }
    Ok(claims)
}

fn upload_content_length(headers: &HeaderMap) -> Result<Option<u64>, AppError> {
    headers
        .get(header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|size| *size > 0)
                .ok_or_else(|| {
                    AppError::bad_request("Invalid Content-Length header")
                })
        })
        .transpose()
}

fn size_as_i64(size: u64) -> Result<i64, AppError> {
    i64::try_from(size)
        .map_err(|_error| AppError::bad_request("Attachment size overflow"))
}

/// Bound the stream before accepting bytes, then recheck the quota after
/// upload.
async fn upload_limit(
    db: &D1Database,
    env: &Env,
    user_id: &str,
    pending: Option<&AttachmentDB>,
) -> Result<u64, AppError> {
    let mut limit = i64::MAX as u64;
    if let Some(pending) = pending {
        let declared = u64::try_from(pending.file_size).map_err(|_error| {
            AppError::bad_request("Invalid attachment size")
        })?;
        limit = limit.min(
            declared.checked_add(SIZE_LEEWAY_BYTES as u64).ok_or_else(
                || AppError::bad_request("Attachment size overflow"),
            )?,
        );
    }
    if let Some(max) = Storage::max_bytes(env) {
        limit = limit.min(max as u64);
    }
    if let Some(max) = attachment_max_bytes(env)? {
        limit = limit.min(max);
    }
    if let Some(total) = total_limit_bytes(env)? {
        let used = AttachmentDB::user_attachment_usage(
            db,
            user_id,
            pending.map(|value| value.id.as_str()),
        )
        .await?;
        let used = u64::try_from(used).map_err(|_error| AppError::Internal)?;
        limit = limit.min(total.saturating_sub(used));
    }
    Ok(limit)
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

async fn build_download_token(
    env: &Env,
    user_id: &str,
    cipher_id: &str,
    attachment_id: &str,
    device: Option<&str>,
) -> Result<String, AppError> {
    let ttl_secs = download_ttl_secs(env)?;
    let now = crate::infra::time::now_seconds();
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
        sub: user_id.to_string(),
        cipher_id: cipher_id.to_string(),
        attachment_id: attachment_id.to_string(),
        exp,
        device: device.map(ToString::to_string),
    };

    let secret = crate::infra::jwt_keys::load(env).await?.access_secret;
    jwt::encode(&claims, secret.as_bytes()).map_err(AppError::from)
}

async fn upload_url(
    env: &Env,
    base_url: &str,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
    device: Option<&str>,
) -> Result<String, AppError> {
    let token =
        build_download_token(env, user_id, cipher_id, attachment_id, device)
            .await?;
    let normalized_base = base_url.trim_end_matches('/');
    Ok(format!(
        "{normalized_base}/api/ciphers/{cipher_id}/attachment/{attachment_id}/\
         azure-upload?token={token}"
    ))
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

    if crate::infra::storage::Storage::max_bytes(env)
        .is_some_and(|max| new_size as u64 > max as u64)
    {
        return Err(AppError::bad_request("File exceeds the 25 MiB KV limit"));
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
        let used = u64::try_from(used).map_err(|_error| AppError::Internal)?;
        let new_total = used.checked_add(new_size as u64).ok_or_else(|| {
            AppError::Params("Attachment size overflow".to_string())
        })?;

        if new_total > limit_bytes {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(size: i64) -> AttachmentDB {
        AttachmentDB {
            id:              "attachment".to_string(),
            cipher_id:       "cipher".to_string(),
            file_name:       "encrypted".to_string(),
            file_size:       size,
            akey:            Some("wrapped-key".to_string()),
            created_at:      String::new(),
            updated_at:      String::new(),
            organization_id: None,
            storage_key:     None,
        }
    }

    #[test]
    fn capability_is_bound_to_both_resources_and_a_subject() {
        let claims = AttachmentDownloadClaims {
            sub:           "owner".to_string(),
            cipher_id:     "cipher".to_string(),
            attachment_id: "attachment".to_string(),
            exp:           crate::infra::time::now_seconds() + 300,
            device:        Some("device".to_string()),
        };
        let token = jwt::encode(&claims, b"test-secret").unwrap();
        let decoded = attachment_claims(
            Some(&token),
            "test-secret",
            "cipher",
            "attachment",
        )
        .unwrap();
        assert_eq!(decoded.sub, "owner");
        assert_eq!(decoded.device.as_deref(), Some("device"));
        assert!(
            attachment_claims(
                Some(&token),
                "test-secret",
                "other",
                "attachment"
            )
            .is_err()
        );
        assert!(
            attachment_claims(Some(&token), "test-secret", "cipher", "other")
                .is_err()
        );
        assert!(
            attachment_claims(
                Some(&token),
                "wrong-secret",
                "cipher",
                "attachment"
            )
            .is_err()
        );
        assert!(
            attachment_claims(None, "test-secret", "cipher", "attachment")
                .is_err()
        );
        let no_subject = AttachmentDownloadClaims {
            sub: String::new(),
            ..claims
        };
        let token = jwt::encode(&no_subject, b"test-secret").unwrap();
        assert!(
            attachment_claims(
                Some(&token),
                "test-secret",
                "cipher",
                "attachment"
            )
            .is_err()
        );
    }

    #[test]
    fn capability_rejects_expiry_and_missing_required_claims() {
        let token = jwt::encode(&serde_json::json!({"sub":"owner","cipher_id":"cipher","attachment_id":"attachment","exp":crate::infra::time::now_seconds()-120}), b"secret").unwrap();
        assert!(
            attachment_claims(Some(&token), "secret", "cipher", "attachment")
                .is_err()
        );
        let token = jwt::encode(&serde_json::json!({"sub":"owner","cipher_id":"cipher","attachment_id":"attachment"}), b"secret").unwrap();
        assert!(
            attachment_claims(Some(&token), "secret", "cipher", "attachment")
                .is_err()
        );
    }

    #[test]
    fn legacy_exp_only_capabilities_keep_timestamps_beyond_the_wasm32_range() {
        let exp = i64::from(u32::MAX) + 300;
        let token = jwt::encode(
            &serde_json::json!({"sub":"owner","cipher_id":"cipher","attachment_id":"attachment","exp":exp}),
            b"secret",
        )
        .unwrap();
        let claims =
            attachment_claims(Some(&token), "secret", "cipher", "attachment")
                .unwrap();
        assert_eq!(claims.exp, exp);
        assert_eq!(claims.device, None);
    }

    #[test]
    fn declared_size_leeway_is_inclusive_and_detects_overflow() {
        let attachment = pending(2 * SIZE_LEEWAY_BYTES);
        assert!(
            validate_size_within_declared(&attachment, SIZE_LEEWAY_BYTES)
                .is_ok()
        );
        assert!(
            validate_size_within_declared(&attachment, 3 * SIZE_LEEWAY_BYTES)
                .is_ok()
        );
        assert!(
            validate_size_within_declared(&attachment, SIZE_LEEWAY_BYTES - 1)
                .is_err()
        );
        assert!(
            validate_size_within_declared(
                &attachment,
                3 * SIZE_LEEWAY_BYTES + 1
            )
            .is_err()
        );
        assert!(validate_size_within_declared(&pending(i64::MAX), 1).is_err());
        assert!(validate_size_within_declared(&pending(1), 0).is_ok());
    }

    #[test]
    fn content_length_is_optional_but_must_be_a_positive_integer() {
        let mut headers = HeaderMap::new();
        assert_eq!(upload_content_length(&headers).unwrap(), None);
        headers.insert(header::CONTENT_LENGTH, "123".parse().unwrap());
        assert_eq!(upload_content_length(&headers).unwrap(), Some(123));
        for invalid in ["0", "-1", "12oops", "18446744073709551616"] {
            headers.insert(header::CONTENT_LENGTH, invalid.parse().unwrap());
            assert!(upload_content_length(&headers).is_err());
        }
        assert!(size_as_i64(i64::MAX as u64).is_ok());
        assert!(size_as_i64(i64::MAX as u64 + 1).is_err());
    }

    #[test]
    fn multipart_metadata_is_bounded_before_appending_each_chunk() {
        let mut metadata = Vec::new();
        append_metadata(&mut metadata, &[1; MAX_MULTIPART_METADATA_BYTES - 1])
            .unwrap();
        append_metadata(&mut metadata, &[2]).unwrap();
        assert!(append_metadata(&mut metadata, &[3]).is_err());
        assert_eq!(metadata.len(), MAX_MULTIPART_METADATA_BYTES);
    }
}
