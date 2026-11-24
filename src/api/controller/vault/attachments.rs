//! Attachment capabilities and streaming handlers.
use std::{convert::Infallible, future::ready, sync::Arc};

use axum::{
    body::Body,
    extract::{FromRequestParts, Multipart, Path, Query, State},
    http::{HeaderMap, Method, StatusCode, header, request::Parts},
    response::Response,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        common::{json::Json, response::ApiResponse},
    },
    errors::{AppError, AppResult},
    infra::storage::Storage,
    models::{
        mutation::{account_snapshot_guard, cipher_snapshot_guard},
        vault::{
            attachment::{AttachmentRow, attachment_snapshot_guard, pending_snapshot_guard},
            cipher::CipherRow,
        },
    },
    service::{
        identity::session::Claims,
        notifications::UpdateType,
        vault::{
            attachment::{
                AttachmentResponse, AttachmentTokenScope, AttachmentTokenTarget,
                MAX_CIPHER_ATTACHMENT_BYTES, attachment_metadata_limit_error, attachment_response,
                attachment_response_metadata_bytes, attachment_row_metadata_bytes,
                attachment_storage_key, decode_attachment_claims, hydrate_cipher_attachments,
                hydrate_cipher_attachments_after_delete, include_metadata, require_owned_cipher,
                signed_download_url, signed_upload_url, unsigned_download_url,
                upload::{
                    AttachmentUpload, AttachmentUploadSpec, UploadAuthorization,
                    attachment_upload_limit_bytes, checked_attachment_size_bytes,
                    enforce_attachment_size_limits, ensure_mutable_cipher,
                },
            },
            cipher::CipherResponse,
        },
        vault_write::{self, VaultWrite},
    },
};

#[derive(Deserialize)]
pub(in crate::api) struct AttachmentTokenQuery {
    token: Option<String>,
}

/// POST /`api/ciphers/{cipher_id}/attachment/v2`
#[worker::send]
pub(in crate::api) async fn reserve_attachment_upload(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(cipher_id): Path<String>,
    Json(payload): Json<ReserveAttachmentUploadRequest>,
) -> AppResult<ApiResponse<AttachmentUploadResponse>> {
    Storage::from_env(&state.env)?;
    let db = state.database();
    let mut mutation = VaultWrite::new(db, &state.env, &claims);
    mutation.guard_account_key().await?;
    let base_url = state.domain();

    let cipher = ensure_mutable_cipher(db, &cipher_id, mutation.user_id()).await?;

    let ReserveAttachmentUploadRequest {
        encrypted_key,
        file_name,
        file_size_bytes,
    } = payload;

    if let IntegerInput::String(s) = &file_size_bytes
        && s.trim().is_empty()
    {
        return Err(AppError::Params("Attachment size must be provided".into()));
    }
    let declared_size_bytes = match file_size_bytes {
        IntegerInput::Number(v) => v,
        IntegerInput::String(size) => size.parse::<i64>().map_err(|error| {
            log::warn!("Invalid attachment size: {error}");
            AppError::Params("Invalid attachment size".into())
        })?,
    };
    if declared_size_bytes <= 0 {
        return Err(AppError::Params("Attachment size must be positive".into()));
    }

    let usage_limit = enforce_attachment_size_limits(
        db,
        &state.env,
        mutation.user_id(),
        declared_size_bytes,
        None, // exclude_attachment
    )
    .await?;

    let attachment_id = Uuid::new_v4().to_string();
    let now = crate::utils::time::now_rfc3339();
    let pending_attachment = AttachmentRow {
        id: attachment_id.clone(),
        cipher_id: cipher.id.clone(),
        file_name,
        file_size_bytes: declared_size_bytes,
        encrypted_key: Some(encrypted_key),
        created_at: now.clone(),
        updated_at: now.clone(),
        organization_id: cipher.organization_id.clone(),
        storage_key: None,
    };

    mutation.guard_cipher(&cipher)?;
    if let Some(usage_limit) = usage_limit {
        mutation.add_guard(AttachmentRow::quota_guard(
            db,
            mutation.user_id(),
            None,
            usage_limit,
        )?);
    }
    let pending_write = pending_attachment.reserve_upload(db)?;

    let url = signed_upload_url(
        &state.env,
        base_url,
        AttachmentTokenTarget::new(&cipher_id, &attachment_id),
        mutation.user_id(),
        claims.device(),
    )
    .await?;
    let mut cipher_response: CipherResponse = cipher.try_into()?;
    hydrate_cipher_attachments(
        db,
        base_url,
        include_metadata(&state.env),
        &mut cipher_response,
    )
    .await?;

    let existing_bytes: usize = cipher_response
        .attachments
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(attachment_response_metadata_bytes)
        .sum();
    let candidate_bytes = attachment_row_metadata_bytes(base_url, &pending_attachment);
    if existing_bytes.saturating_add(candidate_bytes) > MAX_CIPHER_ATTACHMENT_BYTES {
        return Err(attachment_metadata_limit_error());
    }

    let pending_response = attachment_response(
        &pending_attachment,
        Some(unsigned_download_url(base_url, &cipher_id, &attachment_id)),
    );
    match &mut cipher_response.attachments {
        Some(list) => list.push(pending_response),
        None => cipher_response.attachments = Some(vec![pending_response]),
    }

    mutation.commit(vec![pending_write]).await?;

    Ok(ApiResponse(AttachmentUploadResponse {
        object: "attachment-fileUpload".to_string(),
        attachment_id,
        url,
        file_upload_type: 1, // Direct PUT with token
        cipher_response,
    }))
}

/// POST /`api/ciphers/{cipher_id}/attachment/{attachment_id}`
#[worker::send]
pub(in crate::api) async fn upload_attachment_multipart(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> AppResult<ApiResponse<()>> {
    let storage = Storage::from_env(&state.env)?;
    let db = state.database();
    let (_, key_guard) = vault_write::account_key_guard(db, &claims).await?;
    let cipher = ensure_mutable_cipher(db, &cipher_id, &claims.sub).await?;
    let (attachment, is_replacement) =
        match AttachmentRow::fetch_pending_for_cipher(db, &cipher_id, &attachment_id).await {
            Ok(row) => (row, false),
            Err(AppError::NotFound { .. }) => {
                let row = AttachmentRow::fetch_for_cipher(db, &cipher_id, &attachment_id).await?;
                (row, true)
            }
            Err(error) => return Err(error),
        };
    let max_bytes = attachment_upload_limit_bytes(
        db,
        &state.env,
        &claims.sub,
        &attachment,
        attachment.file_size_bytes,
    )
    .await?;
    let guards = vec![
        key_guard,
        cipher_snapshot_guard(db, &cipher)?,
        if is_replacement {
            attachment_snapshot_guard(db, &attachment)?
        } else {
            pending_snapshot_guard(db, &attachment)?
        },
    ];
    let upload = AttachmentUpload::new(db, &state.env, storage, AttachmentUploadSpec {
        row: attachment,
        is_replacement,
        owner: UploadAuthorization::Session(&claims),
        max_bytes,
        guards,
    });
    upload_multipart(&mut multipart, upload).await?;
    Ok(ApiResponse(()))
}

/// PUT capability URL returned by the v2 metadata endpoint.
#[worker::send]
pub(in crate::api) async fn upload_attachment_with_token(
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    Query(query): Query<AttachmentTokenQuery>,
    content_length: ContentLengthHeader,
    headers: HeaderMap,
    body: Body,
) -> AppResult<StatusCode> {
    let claims = decode_attachment_claims(
        query.token.as_deref(),
        &state.jwt_keys.access_secret,
        AttachmentTokenTarget::new(&cipher_id, &attachment_id),
        AttachmentTokenScope::Upload,
    )?;
    let storage = Storage::from_env(&state.env)?;
    let db = state.database();
    let (_, key_guard) = account_snapshot_guard(db, &claims.sub).await?;
    let cipher = ensure_mutable_cipher(db, &cipher_id, &claims.sub).await?;
    let pending = AttachmentRow::fetch_pending_for_cipher(db, &cipher_id, &attachment_id).await?;
    let content_length = content_length.0?;
    let expected_size_bytes = content_length
        .map(checked_attachment_size_bytes)
        .transpose()?
        .unwrap_or(pending.file_size_bytes);
    let max_bytes =
        attachment_upload_limit_bytes(db, &state.env, &claims.sub, &pending, expected_size_bytes)
            .await?;
    if content_length.is_some_and(|size| size > max_bytes) {
        return Err(AppError::bad_request("Attachment size exceeds limit"));
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let guards = vec![
        key_guard,
        cipher_snapshot_guard(db, &cipher)?,
        pending_snapshot_guard(db, &pending)?,
    ];
    let mut upload = AttachmentUpload::new(db, &state.env, storage, AttachmentUploadSpec {
        row: pending,
        is_replacement: false,
        owner: UploadAuthorization::Capability {
            user_id: &claims.sub,
            device: claims.device.as_deref(),
        },
        max_bytes,
        guards,
    });
    if let Err(error) = upload.write(body.into_data_stream(), content_type).await {
        upload.abort().await;
        return Err(error);
    }
    upload.finish(None, content_length).await?;
    Ok(StatusCode::CREATED)
}

/// GET/HEAD capability URL. Authorization stays independent of any bearer.
#[worker::send]
pub(in crate::api) async fn download_attachment(
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    Query(query): Query<AttachmentTokenQuery>,
    method: Method,
    headers: HeaderMap,
) -> AppResult<Response> {
    let claims = decode_attachment_claims(
        query.token.as_deref(),
        &state.jwt_keys.access_secret,
        AttachmentTokenTarget::new(&cipher_id, &attachment_id),
        AttachmentTokenScope::Download,
    )?;
    let db = state.database();
    // Signed download URLs retain the previous read policy, including trash.
    CipherRow::fetch_for_user(db, &cipher_id, &claims.sub).await?;
    let attachment = AttachmentRow::fetch_for_cipher(db, &cipher_id, &attachment_id).await?;
    let storage = Storage::from_env(&state.env)?;
    crate::api::common::download::download(
        &storage,
        &attachment_storage_key(&attachment),
        &headers,
        method == Method::HEAD,
    )
    .await
}

/// GET /`api/ciphers/{cipher_id}/attachment/{attachment_id}`
#[worker::send]
pub(in crate::api) async fn get_attachment(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> AppResult<ApiResponse<AttachmentResponse>> {
    let base_url = state.domain();
    Storage::from_env(&state.env)?;
    let db = state.database();

    require_owned_cipher(db, &cipher_id, &claims.sub).await?;
    let attachment = AttachmentRow::fetch_for_cipher(db, &cipher_id, &attachment_id).await?;

    let url = signed_download_url(
        &state.env,
        base_url,
        AttachmentTokenTarget::new(&cipher_id, &attachment_id),
        &claims.sub,
        claims.device(),
    )
    .await?;
    Ok(ApiResponse(attachment_response(&attachment, Some(url))))
}

/// DELETE /`api/ciphers/{cipher_id}/attachment/{attachment_id}`
#[worker::send]
pub(in crate::api) async fn delete_attachment(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> AppResult<ApiResponse<AttachmentDeleteResponse>> {
    let db = state.database();
    let mut mutation = VaultWrite::new(db, &state.env, &claims);
    let cipher = require_owned_cipher(db, &cipher_id, mutation.user_id()).await?;
    let attachment = AttachmentRow::fetch_for_cipher(db, &cipher_id, &attachment_id).await?;
    mutation.guard_cipher(&cipher)?;
    mutation.add_guard(attachment.deletion_guard(db)?);
    let now = crate::utils::time::now_rfc3339();
    let writes = attachment.delete_statements(db, mutation.user_id(), &now)?;
    let mut cipher_response: CipherResponse = cipher.try_into()?;
    hydrate_cipher_attachments_after_delete(
        db,
        state.domain(),
        include_metadata(&state.env),
        &mut cipher_response,
        &attachment_id,
    )
    .await?;
    cipher_response.updated_at = now;
    let committed = mutation.commit(writes).await?;
    committed
        .publish_cipher(UpdateType::SyncCipherUpdate, &cipher_id)
        .await;
    if let Err(error) = crate::service::storage_cleanup::process_batch(&state.env, db).await {
        log::warn!("Attachment cleanup deferred: {error}");
    }

    Ok(ApiResponse(AttachmentDeleteResponse {
        cipher: cipher_response,
    }))
}

const MAX_MULTIPART_METADATA_SIZE_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct ReserveAttachmentUploadRequest {
    #[serde(rename = "key")]
    encrypted_key: String,
    file_name: String,
    #[serde(rename = "fileSize")]
    file_size_bytes: IntegerInput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct AttachmentUploadResponse {
    object: String,
    attachment_id: String,
    url: String,
    file_upload_type: i32,
    #[serde(rename = "cipherResponse")]
    cipher_response: CipherResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct AttachmentDeleteResponse {
    cipher: CipherResponse,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IntegerInput {
    Number(i64),
    String(String),
}

async fn upload_multipart(
    multipart: &mut Multipart,
    mut upload: AttachmentUpload<'_>,
) -> AppResult<()> {
    let encrypted_key = scan_multipart(multipart, &mut upload).await;
    match encrypted_key {
        Ok(encrypted_key) => upload.finish(encrypted_key, None).await,
        Err(error) => {
            upload.abort().await;
            Err(error)
        }
    }
}

async fn scan_multipart(
    multipart: &mut Multipart,
    upload: &mut AttachmentUpload<'_>,
) -> AppResult<Option<String>> {
    let mut has_data = false;
    let mut encrypted_key = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_error| AppError::bad_request("Invalid multipart data"))?
    {
        if field.name() == Some("data") {
            if has_data {
                return Err(AppError::bad_request("Multiple attachment data fields"));
            }
            if field
                .file_name()
                .is_some_and(|name| name.len() > MAX_MULTIPART_METADATA_SIZE_BYTES)
            {
                return Err(AppError::bad_request("Attachment filename is too long"));
            }
            let content_type = field.content_type().map(ToString::to_string);
            upload.write(field, content_type.as_deref()).await?;
            has_data = true;
        } else {
            let is_key = field.name() == Some("key");
            let mut text = Vec::new();
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|_error| AppError::bad_request("Invalid multipart field"))?
            {
                append_metadata(&mut text, &chunk)?;
            }
            if is_key {
                encrypted_key = Some(
                    String::from_utf8(text)
                        .map_err(|_error| AppError::bad_request("Invalid attachment key"))?,
                );
            }
        }
    }
    if !has_data {
        return Err(AppError::bad_request("No attachment data provided"));
    }
    Ok(encrypted_key)
}

fn append_metadata(data: &mut Vec<u8>, chunk: &[u8]) -> AppResult<()> {
    if chunk.len() > MAX_MULTIPART_METADATA_SIZE_BYTES.saturating_sub(data.len()) {
        return Err(AppError::bad_request("Multipart metadata is too large"));
    }
    data.extend_from_slice(chunk);
    Ok(())
}

// Parse the header at extraction, but propagate errors after capability
// and attachment checks to preserve the existing response precedence.
pub(in crate::api) struct ContentLengthHeader(AppResult<Option<u64>>);

impl ContentLengthHeader {
    fn from_headers(headers: &HeaderMap) -> Self {
        Self(
            headers
                .get(header::CONTENT_LENGTH)
                .map(|value| {
                    value
                        .to_str()
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok())
                        .filter(|size| *size > 0)
                        .ok_or_else(|| AppError::bad_request("Invalid Content-Length header"))
                })
                .transpose(),
        )
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ContentLengthHeader {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        ready(Ok(Self::from_headers(&parts.headers)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_is_optional_but_must_be_a_positive_integer() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            ContentLengthHeader::from_headers(&headers)
                .0
                .expect("valid test fixture"),
            None
        );
        headers.insert(
            header::CONTENT_LENGTH,
            "123".parse().expect("valid test fixture"),
        );
        assert_eq!(
            ContentLengthHeader::from_headers(&headers)
                .0
                .expect("valid test fixture"),
            Some(123)
        );
        for invalid in ["0", "-1", "12oops", "18446744073709551616"] {
            headers.insert(
                header::CONTENT_LENGTH,
                invalid.parse().expect("valid test fixture"),
            );
            assert!(ContentLengthHeader::from_headers(&headers).0.is_err());
        }
        assert!(checked_attachment_size_bytes(i64::MAX as u64).is_ok());
        assert!(checked_attachment_size_bytes(i64::MAX as u64 + 1).is_err());
    }

    #[test]
    fn multipart_metadata_is_bounded_before_appending_each_chunk() {
        let mut metadata = Vec::new();
        append_metadata(&mut metadata, &[1; MAX_MULTIPART_METADATA_SIZE_BYTES - 1])
            .expect("valid test fixture");
        append_metadata(&mut metadata, &[2]).expect("valid test fixture");
        assert!(append_metadata(&mut metadata, &[3]).is_err());
        assert_eq!(metadata.len(), MAX_MULTIPART_METADATA_SIZE_BYTES);
    }
}
