//! Attachment response projection shared by vault and attachment handlers.
use worker::{
    D1Database,
    Env,
};

use crate::{
    errors::AppError,
    models::{
        attachment::AttachmentDB,
        cipher::Cipher,
    },
};

pub(crate) async fn hydrate_cipher_attachments(
    db: &D1Database,
    env: &Env,
    cipher: &mut Cipher,
) -> Result<(), AppError> {
    hydrate_ciphers_attachments(db, env, std::slice::from_mut(cipher)).await
}

pub(crate) async fn hydrate_ciphers_attachments(
    db: &D1Database,
    env: &Env,
    ciphers: &mut [Cipher],
) -> Result<(), AppError> {
    if !AttachmentDB::attachments_enabled(env) {
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
    let json = serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;
    let mut map =
        AttachmentDB::load_attachment_map_json(db, &json, "$").await?;
    for cipher in ciphers {
        cipher.attachments =
            map.remove(&cipher.id).filter(|list| !list.is_empty());
        if let Some(list) = &mut cipher.attachments {
            for attachment in list {
                attachment.url =
                    Some(stable_url(env, &cipher.id, &attachment.id)?);
            }
        }
    }
    Ok(())
}

pub(crate) fn stable_url(
    env: &Env,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<String, AppError> {
    let domain = env.var("DOMAIN")?.to_string();
    let domain = if domain.contains("://") {
        domain
    } else {
        format!("https://{domain}")
    };
    Ok(format!(
        "{}/attachments/{cipher_id}/{attachment_id}",
        domain.trim_end_matches('/')
    ))
}
