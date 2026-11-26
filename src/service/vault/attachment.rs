//! Attachment capabilities, object keys and protocol response projections.
pub(crate) mod upload;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use worker::{D1Database, Env};

use crate::{
    errors::{AppError, AppResult},
    infra::{config::attachment_token_ttl_seconds, jwt},
    models::{
        page::Page,
        vault::{attachment::AttachmentRow, cipher::CipherRow},
    },
    service::{identity::session::Claims, vault::cipher::CipherResponse},
};

// Keep one oversized cipher's decoded metadata within the budget left
// alongside the encoded snapshot, D1 page, and Worker runtime.
pub(crate) const MAX_CIPHER_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn attachment_row_metadata_bytes(domain: &str, row: &AttachmentRow) -> usize {
    row_metadata_bytes(row, &unsigned_download_url(domain, &row.cipher_id, &row.id))
}

fn row_metadata_bytes(row: &AttachmentRow, url: &str) -> usize {
    row.file_name.len()
        + row.encrypted_key.as_ref().map_or(0, String::len)
        + row.id.len()
        + url.len()
}

pub(crate) fn attachment_response_metadata_bytes(item: &AttachmentResponse) -> usize {
    item.file_name.len()
        + item.encrypted_key.as_ref().map_or(0, String::len)
        + item.id.len()
        + item.url.as_ref().map_or(0, String::len)
}

pub(crate) async fn enforce_cipher_attachment_metadata_budget(
    db: &D1Database,
    domain: &str,
    candidate: &AttachmentRow,
    exclude_attachment_id: Option<&str>,
) -> AppResult<()> {
    let mut total = attachment_row_metadata_bytes(domain, candidate);
    if total > MAX_CIPHER_ATTACHMENT_BYTES {
        return Err(attachment_metadata_limit_error());
    }
    visit_attachments(db, &[&candidate.cipher_id], |row| {
        if exclude_attachment_id != Some(row.id.as_str()) {
            total = total.saturating_add(attachment_row_metadata_bytes(domain, &row));
            if total > MAX_CIPHER_ATTACHMENT_BYTES {
                return Err(attachment_metadata_limit_error());
            }
        }
        Ok(())
    })
    .await
}

pub(crate) fn attachment_metadata_limit_error() -> AppError {
    AppError::PayloadTooLarge {
        message: "Cipher attachment metadata exceeds the server size limit".into(),
    }
}

pub(crate) async fn hydrate_cipher_attachments(
    db: &D1Database,
    domain: &str,
    include_attachments: bool,
    cipher: &mut CipherResponse,
) -> AppResult<()> {
    hydrate_ciphers_attachments(
        db,
        domain,
        include_attachments,
        std::slice::from_mut(cipher),
    )
    .await
}

/// Hydrate remaining attachments for a delete response without letting an
/// already-oversized cipher deadlock attachment removal.
pub(crate) async fn hydrate_cipher_attachments_after_delete(
    db: &D1Database,
    domain: &str,
    include_attachments: bool,
    cipher: &mut CipherResponse,
    deleted_attachment_id: &str,
) -> AppResult<()> {
    match project_attachments(
        db,
        domain,
        include_attachments,
        std::slice::from_mut(cipher),
        Some(deleted_attachment_id),
    )
    .await
    {
        Err(AppError::PayloadTooLarge { .. }) => {
            cipher.attachments = None;
            Ok(())
        }
        result => result,
    }
}

pub(crate) async fn hydrate_ciphers_attachments(
    db: &D1Database,
    domain: &str,
    include_attachments: bool,
    ciphers: &mut [CipherResponse],
) -> AppResult<()> {
    project_attachments(db, domain, include_attachments, ciphers, None).await
}

async fn project_attachments(
    db: &D1Database,
    domain: &str,
    include_attachments: bool,
    ciphers: &mut [CipherResponse],
    exclude_attachment_id: Option<&str>,
) -> AppResult<()> {
    let mut map: HashMap<String, (usize, Vec<AttachmentResponse>)> = HashMap::new();
    if include_attachments && !ciphers.is_empty() {
        let ids: Vec<_> = ciphers.iter().map(|cipher| cipher.id.as_str()).collect();
        visit_attachments(db, &ids, |row| {
            if exclude_attachment_id == Some(row.id.as_str()) {
                return Ok(());
            }
            let url = unsigned_download_url(domain, &row.cipher_id, &row.id);
            let item_bytes = row_metadata_bytes(&row, &url);
            let (cipher_id, response) = AttachmentResponse::into_cipher_item(row, Some(url));
            let (bytes, attachments) = map.entry(cipher_id).or_default();
            *bytes = bytes.saturating_add(item_bytes);
            if *bytes > MAX_CIPHER_ATTACHMENT_BYTES {
                return Err(attachment_metadata_limit_error());
            }
            attachments.push(response);
            Ok(())
        })
        .await?;
    }
    for cipher in ciphers {
        cipher.attachments = map
            .remove(&cipher.id)
            .map(|(_bytes, attachments)| attachments);
    }
    Ok(())
}

async fn visit_attachments(
    db: &D1Database,
    cipher_ids: &[&str],
    mut visit: impl FnMut(AttachmentRow) -> AppResult<()>,
) -> AppResult<()> {
    let json = serde_json::to_string(cipher_ids).map_err(AppError::internal_json(
        "Failed to serialize attachment cipher IDs",
    ))?;
    Page::visit(
        async |after| AttachmentRow::list_page(db, &json, after).await,
        async |rows| rows.into_iter().try_for_each(&mut visit),
    )
    .await
}

pub(crate) fn unsigned_download_url(domain: &str, cipher_id: &str, attachment_id: &str) -> String {
    format!(
        "{}/attachments/{cipher_id}/{attachment_id}",
        domain.trim_end_matches('/')
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentResponse {
    pub file_name: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "key")]
    pub encrypted_key: Option<String>,
    pub object: &'static str,
    #[serde(rename = "size")]
    pub size_bytes: String,
    #[serde(rename = "sizeName")]
    pub formatted_size: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl AttachmentResponse {
    fn into_cipher_item(attachment: AttachmentRow, url: Option<String>) -> (String, Self) {
        let AttachmentRow {
            id,
            cipher_id,
            file_name,
            file_size_bytes,
            encrypted_key,
            ..
        } = attachment;
        (cipher_id, Self {
            id,
            url,
            file_name,
            size_bytes: file_size_bytes.to_string(),
            formatted_size: format_file_size(file_size_bytes),
            encrypted_key,
            object: "attachment",
        })
    }
}

pub(crate) fn attachment_storage_key(attachment: &AttachmentRow) -> std::borrow::Cow<'_, str> {
    attachment.storage_key.as_deref().map_or_else(
        || std::borrow::Cow::Owned(format!("{}/{}", attachment.cipher_id, attachment.id)),
        std::borrow::Cow::Borrowed,
    )
}

pub(crate) fn attachment_response(
    attachment: &AttachmentRow,
    url: Option<String>,
) -> AttachmentResponse {
    AttachmentResponse {
        id: attachment.id.clone(),
        url,
        file_name: attachment.file_name.clone(),
        size_bytes: attachment.file_size_bytes.to_string(),
        formatted_size: format_file_size(attachment.file_size_bytes),
        encrypted_key: attachment.encrypted_key.clone(),
        object: "attachment",
    }
}

fn format_file_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    if bytes < 0 {
        return "0 B".to_string();
    }
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}

/// Attachment metadata is stored in D1, including when its backend is invalid.
pub(crate) fn include_metadata(env: &Env) -> bool {
    crate::infra::storage::Storage::is_configured(env)
}

/// Require an owned personal cipher for attachment metadata operations.
pub(crate) async fn require_owned_cipher(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    deleted_message: &'static str,
) -> AppResult<CipherRow> {
    let cipher = CipherRow::fetch_for_user(db, cipher_id, user_id).await?;
    if cipher.organization_id.is_some() {
        return Err(AppError::bad_request(
            "Organization attachments are not supported",
        ));
    }
    if cipher.deleted_at.is_some() {
        return Err(AppError::bad_request(deleted_message));
    }
    Ok(cipher)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum AttachmentTokenScope {
    #[serde(rename = "attachment.upload")]
    Upload,
    #[serde(rename = "attachment.download")]
    Download,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttachmentTokenPurpose {
    Upload,
    Download,
}

impl From<AttachmentTokenPurpose> for AttachmentTokenScope {
    fn from(purpose: AttachmentTokenPurpose) -> Self {
        match purpose {
            AttachmentTokenPurpose::Upload => Self::Upload,
            AttachmentTokenPurpose::Download => Self::Download,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AttachmentClaims {
    pub sub: String,
    pub cipher_id: String,
    pub attachment_id: String,
    pub exp: i64,
    pub scope: AttachmentTokenScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

#[derive(Serialize)]
struct AttachmentClaimsRef<'a> {
    sub: &'a str,
    cipher_id: &'a str,
    attachment_id: &'a str,
    exp: i64,
    scope: AttachmentTokenScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<&'a str>,
}

#[derive(Clone, Copy)]
pub(crate) struct AttachmentTokenTarget<'a> {
    cipher_id: &'a str,
    attachment_id: &'a str,
}

impl<'a> AttachmentTokenTarget<'a> {
    pub(crate) const fn new(cipher_id: &'a str, attachment_id: &'a str) -> Self {
        Self {
            cipher_id,
            attachment_id,
        }
    }
}

pub(crate) fn decode_attachment_claims(
    token: Option<&str>,
    secret: &str,
    target: AttachmentTokenTarget<'_>,
    expected_scope: AttachmentTokenScope,
) -> AppResult<AttachmentClaims> {
    let token = token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AppError::bad_request("Missing token"))?;
    let claims =
        jwt::decode::<AttachmentClaims>(token, secret.as_bytes(), &jwt::ValidationOptions {
            leeway_seconds: 0,
            ..Default::default()
        })?;
    if claims.sub.is_empty()
        || claims.cipher_id != target.cipher_id
        || claims.attachment_id != target.attachment_id
        || claims.scope != expected_scope
    {
        return Err(AppError::Unauthorized {
            message: "Invalid token".into(),
        });
    }
    Ok(claims)
}

pub(crate) fn signed_attachment_url(
    env: &Env,
    secret: &str,
    base_url: &str,
    target: AttachmentTokenTarget<'_>,
    owner: &Claims,
    purpose: AttachmentTokenPurpose,
) -> AppResult<String> {
    let AttachmentTokenTarget {
        cipher_id,
        attachment_id,
    } = target;
    let ttl_seconds = attachment_token_ttl_seconds(env)?;
    let exp = crate::utils::time::now_seconds()
        .checked_add(ttl_seconds)
        .ok_or_else(|| AppError::internal("Attachment token expiration overflowed"))?;
    let token = jwt::encode(
        &AttachmentClaimsRef {
            sub: &owner.sub,
            cipher_id,
            attachment_id,
            exp,
            scope: AttachmentTokenScope::from(purpose),
            device: owner.device(),
        },
        secret.as_bytes(),
    )?;

    let url = match purpose {
        AttachmentTokenPurpose::Upload => {
            let base = base_url.trim_end_matches('/');
            format!("{base}/api/ciphers/{cipher_id}/attachment/{attachment_id}/azure-upload")
        }
        AttachmentTokenPurpose::Download => {
            unsigned_download_url(base_url, cipher_id, attachment_id)
        }
    };
    Ok(format!("{url}?token={token}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_binds_subject_resources_scope_and_expiry() {
        let now = crate::utils::time::now_seconds();
        let claims = AttachmentClaims {
            sub: "owner".into(),
            cipher_id: "cipher".into(),
            attachment_id: "attachment".into(),
            exp: now + 300,
            scope: AttachmentTokenScope::Download,
            device: Some("device".into()),
        };
        let token = jwt::encode(&claims, b"secret").expect("token");
        let target = AttachmentTokenTarget::new("cipher", "attachment");
        assert!(
            decode_attachment_claims(
                Some(&token),
                "secret",
                target,
                AttachmentTokenScope::Download
            )
            .is_ok()
        );
        assert!(
            decode_attachment_claims(Some(&token), "secret", target, AttachmentTokenScope::Upload)
                .is_err()
        );
        assert!(
            decode_attachment_claims(
                Some(&token),
                "secret",
                AttachmentTokenTarget::new("other", "attachment"),
                AttachmentTokenScope::Download
            )
            .is_err()
        );
        let expired = jwt::encode(
            &AttachmentClaims {
                exp: now - 1,
                ..claims
            },
            b"secret",
        )
        .expect("expired");
        assert!(
            decode_attachment_claims(
                Some(&expired),
                "secret",
                target,
                AttachmentTokenScope::Download
            )
            .is_err()
        );
    }
}
