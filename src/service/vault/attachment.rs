//! Attachment capabilities, object keys and protocol response projections.
pub(crate) mod upload;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use worker::{D1Database, Env};

use crate::{
    errors::{AppError, AppResult},
    infra::{config::attachment_token_ttl_seconds, db, jwt},
    models::vault::{attachment::AttachmentRow, cipher::CipherRow},
    service::vault::cipher::CipherResponse,
};

// Keep one oversized cipher's decoded metadata within the budget left
// alongside the encoded snapshot, D1 page, and Worker runtime.
pub(crate) const MAX_CIPHER_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn attachment_row_metadata_bytes(domain: &str, row: &AttachmentRow) -> usize {
    let url = unsigned_download_url(domain, &row.cipher_id, &row.id);
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
    let json =
        serde_json::to_string(&[candidate.cipher_id.as_str()]).map_err(AppError::internal_error)?;
    let mut after = None;
    loop {
        let page = AttachmentRow::list_page(db, &json, after.as_ref()).await?;
        for row in page.rows {
            if exclude_attachment_id != Some(row.id.as_str()) {
                total = total.saturating_add(attachment_row_metadata_bytes(domain, &row));
                if total > MAX_CIPHER_ATTACHMENT_BYTES {
                    return Err(attachment_metadata_limit_error());
                }
            }
        }
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    Ok(())
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
    if !include_attachments {
        cipher.attachments = None;
        return Ok(());
    }
    let json = serde_json::to_string(&[cipher.id.as_str()]).map_err(AppError::internal_error)?;
    let mut bytes = 0usize;
    let mut attachments = Vec::new();
    let mut after = None;
    loop {
        let page = AttachmentRow::list_page(db, &json, after.as_ref()).await?;
        for row in page.rows {
            if row.id == deleted_attachment_id {
                continue;
            }
            bytes = bytes.saturating_add(attachment_row_metadata_bytes(domain, &row));
            if bytes > MAX_CIPHER_ATTACHMENT_BYTES {
                cipher.attachments = None;
                return Ok(());
            }
            let url = unsigned_download_url(domain, &row.cipher_id, &row.id);
            attachments.push(attachment_response(&row, Some(url)));
        }
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    cipher.attachments = (!attachments.is_empty()).then_some(attachments);
    Ok(())
}

pub(crate) async fn hydrate_ciphers_attachments(
    db: &D1Database,
    domain: &str,
    include_attachments: bool,
    ciphers: &mut [CipherResponse],
) -> AppResult<()> {
    if !include_attachments {
        for cipher in ciphers {
            cipher.attachments = None;
        }
        return Ok(());
    }
    let ids: Vec<&str> = ciphers.iter().map(|cipher| cipher.id.as_str()).collect();
    if ids.is_empty() {
        return Ok(());
    }
    let json = serde_json::to_string(&ids).map_err(AppError::internal_error)?;
    let mut map: HashMap<String, (usize, Vec<AttachmentResponse>)> = HashMap::new();
    let mut after = None;
    loop {
        let page = AttachmentRow::list_page(db, &json, after.as_ref()).await?;
        for row in page.rows {
            let (bytes, attachments) = map.entry(row.cipher_id.clone()).or_default();
            *bytes = bytes.saturating_add(attachment_row_metadata_bytes(domain, &row));
            if *bytes > MAX_CIPHER_ATTACHMENT_BYTES {
                return Err(attachment_metadata_limit_error());
            }
            let url = unsigned_download_url(domain, &row.cipher_id, &row.id);
            attachments.push(attachment_response(&row, Some(url)));
        }
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    for cipher in ciphers {
        cipher.attachments = map
            .remove(&cipher.id)
            .map(|(_bytes, attachments)| attachments);
    }
    Ok(())
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
    pub object: String,
    #[serde(rename = "size")]
    pub size_bytes: String,
    #[serde(rename = "sizeName")]
    pub formatted_size: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

pub(crate) fn attachment_storage_key(attachment: &AttachmentRow) -> String {
    attachment
        .storage_key
        .clone()
        .unwrap_or_else(|| format!("{}/{}", attachment.cipher_id, attachment.id))
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
        object: "attachment".to_string(),
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
) -> AppResult<CipherRow> {
    let cipher = CipherRow::fetch_for_user(db, cipher_id, user_id).await?;
    if cipher.organization_id.is_some() {
        return Err(AppError::bad_request(
            "Organization attachments are not supported",
        ));
    }
    if cipher.deleted_at.is_some() {
        return Err(AppError::bad_request("Cipher is deleted"));
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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AttachmentClaims {
    pub sub: String,
    pub cipher_id: String,
    pub attachment_id: String,
    pub exp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<AttachmentTokenScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
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

pub(crate) async fn signed_download_url(
    env: &Env,
    base_url: &str,
    target: AttachmentTokenTarget<'_>,
    user_id: &str,
    device: Option<&str>,
) -> AppResult<String> {
    let token =
        sign_attachment_token(env, user_id, target, AttachmentTokenScope::Download, device).await?;
    let url = unsigned_download_url(base_url, target.cipher_id, target.attachment_id);
    Ok(format!("{url}?token={token}"))
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
        || claims.scope.is_some_and(|scope| scope != expected_scope)
    {
        return Err(AppError::Unauthorized {
            message: "Invalid token".into(),
        });
    }
    Ok(claims)
}

async fn sign_attachment_token(
    env: &Env,
    user_id: &str,
    target: AttachmentTokenTarget<'_>,
    scope: AttachmentTokenScope,
    device: Option<&str>,
) -> AppResult<String> {
    let AttachmentTokenTarget {
        cipher_id,
        attachment_id,
    } = target;
    let ttl_seconds = attachment_token_ttl_seconds(env)?;
    let now = crate::utils::time::now_seconds();
    let exp = now
        .checked_add(ttl_seconds)
        .ok_or_else(|| AppError::Internal)?;

    let claims = AttachmentClaims {
        sub: user_id.to_string(),
        cipher_id: cipher_id.to_string(),
        attachment_id: attachment_id.to_string(),
        exp,
        scope: Some(scope),
        device: device.map(ToString::to_string),
    };

    let secret = crate::service::identity::jwt_keys::load(env, &db::binding(env)?)
        .await?
        .access_secret;
    jwt::encode(&claims, secret.as_bytes())
}

pub(crate) async fn signed_upload_url(
    env: &Env,
    base_url: &str,
    target: AttachmentTokenTarget<'_>,
    user_id: &str,
    device: Option<&str>,
) -> AppResult<String> {
    let token =
        sign_attachment_token(env, user_id, target, AttachmentTokenScope::Upload, device).await?;
    let AttachmentTokenTarget {
        cipher_id,
        attachment_id,
    } = target;
    let normalized_base = base_url.trim_end_matches('/');
    Ok(format!(
        "{normalized_base}/api/ciphers/{cipher_id}/attachment/{attachment_id}/\
         azure-upload?token={token}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_is_bound_to_both_resources_and_a_subject() {
        let claims = AttachmentClaims {
            sub: "owner".to_string(),
            cipher_id: "cipher".to_string(),
            attachment_id: "attachment".to_string(),
            exp: crate::utils::time::now_seconds() + 300,
            scope: Some(AttachmentTokenScope::Download),
            device: Some("device".to_string()),
        };
        let token = jwt::encode(&claims, b"test-secret").expect("valid test fixture");
        let decoded = decode_attachment_claims(
            Some(&token),
            "test-secret",
            AttachmentTokenTarget::new("cipher", "attachment"),
            AttachmentTokenScope::Download,
        )
        .expect("valid test fixture");
        assert_eq!(decoded.sub, "owner");
        assert_eq!(decoded.device.as_deref(), Some("device"));
        assert!(
            decode_attachment_claims(
                Some(&token),
                "test-secret",
                AttachmentTokenTarget::new("cipher", "attachment"),
                AttachmentTokenScope::Upload,
            )
            .is_err()
        );
        assert!(
            decode_attachment_claims(
                Some(&token),
                "test-secret",
                AttachmentTokenTarget::new("other", "attachment"),
                AttachmentTokenScope::Download,
            )
            .is_err()
        );
        assert!(
            decode_attachment_claims(
                Some(&token),
                "test-secret",
                AttachmentTokenTarget::new("cipher", "other"),
                AttachmentTokenScope::Download,
            )
            .is_err()
        );
        assert!(
            decode_attachment_claims(
                Some(&token),
                "wrong-secret",
                AttachmentTokenTarget::new("cipher", "attachment"),
                AttachmentTokenScope::Download,
            )
            .is_err()
        );
        assert!(
            decode_attachment_claims(
                None,
                "test-secret",
                AttachmentTokenTarget::new("cipher", "attachment"),
                AttachmentTokenScope::Download,
            )
            .is_err()
        );
        let no_subject = AttachmentClaims {
            sub: String::new(),
            ..claims
        };
        let token = jwt::encode(&no_subject, b"test-secret").expect("valid test fixture");
        assert!(
            decode_attachment_claims(
                Some(&token),
                "test-secret",
                AttachmentTokenTarget::new("cipher", "attachment"),
                AttachmentTokenScope::Download,
            )
            .is_err()
        );
    }

    #[test]
    fn capability_rejects_expiry_and_missing_required_claims() {
        let token = jwt::encode(&serde_json::json!({"sub":"owner","cipher_id":"cipher","attachment_id":"attachment","exp":crate::utils::time::now_seconds()-1}), b"secret").expect("valid test fixture");
        assert!(
            decode_attachment_claims(
                Some(&token),
                "secret",
                AttachmentTokenTarget::new("cipher", "attachment"),
                AttachmentTokenScope::Download,
            )
            .is_err()
        );
        let token = jwt::encode(
            &serde_json::json!({"sub":"owner","cipher_id":"cipher","attachment_id":"attachment"}),
            b"secret",
        )
        .expect("valid test fixture");
        assert!(
            decode_attachment_claims(
                Some(&token),
                "secret",
                AttachmentTokenTarget::new("cipher", "attachment"),
                AttachmentTokenScope::Download,
            )
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
        .expect("valid test fixture");
        let claims = decode_attachment_claims(
            Some(&token),
            "secret",
            AttachmentTokenTarget::new("cipher", "attachment"),
            AttachmentTokenScope::Download,
        )
        .expect("valid test fixture");
        assert_eq!(claims.exp, exp);
        assert_eq!(claims.device, None);
    }
}
