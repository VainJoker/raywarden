//! Attachment capabilities, object keys and protocol response projections.
pub(crate) mod upload;

use std::collections::HashMap;

use serde::{
    Deserialize,
    Serialize,
};
use worker::{
    D1Database,
    Env,
};

use crate::{
    app::AppContext,
    config::files::attachment_token_ttl_seconds,
    errors::{
        AppError,
        AppResult,
        DatabaseError,
    },
    infra::{
        db,
        jwt,
    },
    models::vault::{
        attachment::AttachmentRow,
        cipher::CipherRow,
    },
    service::vault::cipher::CipherResponse,
};

pub(crate) async fn hydrate_cipher_attachments(
    state: &AppContext,
    cipher: &mut CipherResponse,
) -> AppResult<()> {
    hydrate_ciphers_attachments(state, std::slice::from_mut(cipher)).await
}

pub(crate) async fn hydrate_ciphers_attachments(
    state: &AppContext,
    ciphers: &mut [CipherResponse],
) -> AppResult<()> {
    if !is_enabled(&state.env) {
        for cipher in ciphers {
            cipher.attachments = None;
        }
        return Ok(());
    }
    let ids: Vec<&str> =
        ciphers.iter().map(|cipher| cipher.id.as_str()).collect();
    if ids.is_empty() {
        return Ok(());
    }
    let json = serde_json::to_string(&ids).map_err(AppError::internal_error)?;
    let rows =
        AttachmentRow::list_for_ciphers_json(state.database(), &json, "$")
            .await?;
    let mut map: HashMap<String, Vec<AttachmentResponse>> = HashMap::new();
    for row in rows {
        let url =
            unsigned_download_url(state.domain(), &row.cipher_id, &row.id);
        map.entry(row.cipher_id.clone())
            .or_default()
            .push(attachment_response(&row, Some(url)));
    }
    for cipher in ciphers {
        cipher.attachments =
            map.remove(&cipher.id).filter(|list| !list.is_empty());
    }
    Ok(())
}

pub(crate) fn unsigned_download_url(
    domain: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> String {
    format!(
        "{}/attachments/{cipher_id}/{attachment_id}",
        domain.trim_end_matches('/')
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentResponse {
    pub id:             String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url:            Option<String>,
    pub file_name:      String,
    #[serde(rename = "size")]
    pub size_bytes:     String,
    #[serde(rename = "sizeName")]
    pub formatted_size: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "key")]
    pub encrypted_key:  Option<String>,
    pub object:         String,
}

pub(crate) fn attachment_storage_key(attachment: &AttachmentRow) -> String {
    attachment.storage_key.clone().unwrap_or_else(|| {
        format!("{}/{}", attachment.cipher_id, attachment.id)
    })
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

pub(crate) fn is_enabled(env: &Env) -> bool {
    crate::infra::storage::Storage::enabled(env)
}

/// Preserve the attachment endpoints' ownership and lifecycle checks.
pub(crate) async fn require_owned_cipher(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
) -> AppResult<CipherRow> {
    let cipher =
        CipherRow::fetch_for_attachment_owner(db, cipher_id, user_id).await?;
    if cipher.organization_id.is_some() {
        return Err(DatabaseError::query_failed(
            "Organization attachments are not supported",
        ));
    }
    if cipher.deleted_at.is_some() {
        return Err(DatabaseError::query_failed("Cipher is deleted"));
    }
    Ok(cipher)
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AttachmentClaims {
    pub sub:           String,
    pub cipher_id:     String,
    pub attachment_id: String,
    pub exp:           i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device:        Option<String>,
}

pub(crate) async fn signed_download_url(
    env: &Env,
    base_url: &str,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
    device: Option<&str>,
) -> AppResult<String> {
    let token =
        sign_attachment_token(env, user_id, cipher_id, attachment_id, device)
            .await?;
    let url = unsigned_download_url(base_url, cipher_id, attachment_id);
    Ok(format!("{url}?token={token}"))
}

pub(crate) fn decode_attachment_claims(
    token: Option<&str>,
    secret: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> AppResult<AttachmentClaims> {
    let token = token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AppError::bad_request("Missing token"))?;
    let claims = jwt::decode::<AttachmentClaims>(
        token,
        secret.as_bytes(),
        &jwt::ValidationOptions::default(),
    )?;
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

pub(crate) async fn sign_attachment_token(
    env: &Env,
    user_id: &str,
    cipher_id: &str,
    attachment_id: &str,
    device: Option<&str>,
) -> AppResult<String> {
    let ttl_seconds = attachment_token_ttl_seconds(env)?;
    let now = crate::utils::time::now_seconds();
    let exp = now
        .checked_add(ttl_seconds)
        .ok_or_else(|| AppError::Internal)?;

    if exp < 0 {
        log::error!(
            "Computed negative expiration for attachment token: \
             cipher={cipher_id}, attachment={attachment_id}"
        );
        return Err(AppError::Internal);
    }

    let claims = AttachmentClaims {
        sub: user_id.to_string(),
        cipher_id: cipher_id.to_string(),
        attachment_id: attachment_id.to_string(),
        exp,
        device: device.map(ToString::to_string),
    };

    let secret =
        crate::service::identity::jwt_keys::load(env, &db::binding(env)?)
            .await?
            .access_secret;
    jwt::encode(&claims, secret.as_bytes()).map_err(AppError::from)
}

pub(crate) async fn signed_upload_url(
    env: &Env,
    base_url: &str,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
    device: Option<&str>,
) -> AppResult<String> {
    let token =
        sign_attachment_token(env, user_id, cipher_id, attachment_id, device)
            .await?;
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
            sub:           "owner".to_string(),
            cipher_id:     "cipher".to_string(),
            attachment_id: "attachment".to_string(),
            exp:           crate::utils::time::now_seconds() + 300,
            device:        Some("device".to_string()),
        };
        let token =
            jwt::encode(&claims, b"test-secret").expect("valid test fixture");
        let decoded = decode_attachment_claims(
            Some(&token),
            "test-secret",
            "cipher",
            "attachment",
        )
        .expect("valid test fixture");
        assert_eq!(decoded.sub, "owner");
        assert_eq!(decoded.device.as_deref(), Some("device"));
        assert!(
            decode_attachment_claims(
                Some(&token),
                "test-secret",
                "other",
                "attachment"
            )
            .is_err()
        );
        assert!(
            decode_attachment_claims(
                Some(&token),
                "test-secret",
                "cipher",
                "other"
            )
            .is_err()
        );
        assert!(
            decode_attachment_claims(
                Some(&token),
                "wrong-secret",
                "cipher",
                "attachment"
            )
            .is_err()
        );
        assert!(
            decode_attachment_claims(
                None,
                "test-secret",
                "cipher",
                "attachment"
            )
            .is_err()
        );
        let no_subject = AttachmentClaims {
            sub: String::new(),
            ..claims
        };
        let token = jwt::encode(&no_subject, b"test-secret")
            .expect("valid test fixture");
        assert!(
            decode_attachment_claims(
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
        let token = jwt::encode(&serde_json::json!({"sub":"owner","cipher_id":"cipher","attachment_id":"attachment","exp":crate::utils::time::now_seconds()-120}), b"secret").expect("valid test fixture");
        assert!(
            decode_attachment_claims(
                Some(&token),
                "secret",
                "cipher",
                "attachment"
            )
            .is_err()
        );
        let token = jwt::encode(&serde_json::json!({"sub":"owner","cipher_id":"cipher","attachment_id":"attachment"}), b"secret").expect("valid test fixture");
        assert!(
            decode_attachment_claims(
                Some(&token),
                "secret",
                "cipher",
                "attachment"
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
            "cipher",
            "attachment",
        )
        .expect("valid test fixture");
        assert_eq!(claims.exp, exp);
        assert_eq!(claims.device, None);
    }
}
