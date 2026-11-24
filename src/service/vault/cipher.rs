//! Personal-vault cipher workflows and protocol contracts.
mod request;
mod response;

use std::collections::HashMap;

use request::RotateAttachmentRequest;
pub use request::{
    CipherRequest, CreateCipherWithCollectionsRequest, UpdateCipherPartialRequest,
    client_revision_is_stale, normalize_optional_rfc3339,
};
pub use response::CipherResponse;
use serde_json::Value;
use uuid::Uuid;
use worker::{D1Database, D1PreparedStatement, Env};

use super::attachment;
use crate::{
    errors::{AppError, AppResult},
    models::vault::{
        attachment::AttachmentRow,
        cipher::{CipherMutation, CipherRow},
        folder::FolderRow,
    },
    service::{
        identity::{session::Claims, user::AccountVerificationRequest},
        notifications::{UpdateType, admin::Event},
        vault_write::VaultWrite,
    },
};

async fn collect_attachment_key_updates(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    updates: Option<&HashMap<String, RotateAttachmentRequest>>,
    now: &str,
) -> AppResult<(Vec<D1PreparedStatement>, Vec<String>)> {
    let Some(updates) = updates.filter(|updates| !updates.is_empty()) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let ids = serde_json::to_string(&updates.keys().collect::<Vec<_>>())
        .map_err(AppError::internal_error)?;
    let mut writes = Vec::new();
    let mut applied = Vec::new();
    let mut after = None;
    loop {
        let page =
            AttachmentRow::list_key_update_page(db, cipher_id, user_id, &ids, after.as_ref())
                .await?;
        for row in page.rows {
            let update = updates.get(&row.id).ok_or(AppError::Internal)?;
            writes.extend(AttachmentRow::rotate_key_statements(
                db,
                &row,
                &update.file_name,
                &update.key,
                now,
            )?);
            applied.push(row.id);
        }
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    Ok((writes, applied))
}

/// Single mutations publish an item update; bulk mutations publish a vault
/// update even when the selection is empty.
pub(crate) enum CipherSelection {
    Single(String),
    Bulk(Vec<String>),
}

/// Bind a sorted selection and arm snapshot guards before projecting or writing.
struct SelectionPlan {
    ids: Vec<String>,
    ids_json: String,
    rows: Vec<CipherRow>,
    bulk: bool,
    kind: CipherMutation,
}

impl SelectionPlan {
    async fn load(
        selection: CipherSelection,
        kind: CipherMutation,
        mutation: &mut VaultWrite<'_>,
    ) -> AppResult<Self> {
        let (mut ids, bulk) = match selection {
            CipherSelection::Single(id) => (vec![id], false),
            CipherSelection::Bulk(ids) => (ids, true),
        };
        ids.sort();
        ids.dedup();
        // JSON selections and snapshots avoid a bind for every row. Long
        // individual ciphertexts still use separate column binds.
        let ids_json = serde_json::to_string(&ids).map_err(AppError::internal_error)?;
        if ids_json.len() > 1_900_000 {
            return Err(AppError::PayloadTooLarge {
                message: "Cipher selection is too large".into(),
            });
        }
        let db = mutation.database();
        if let CipherMutation::Move {
            folder_id: Some(folder),
        } = &kind
        {
            FolderRow::ensure_for_user(db, folder, mutation.user_id()).await?;
        }
        let rows = CipherRow::fetch_selected(db, mutation.user_id(), &ids_json).await?;
        if rows.len() != ids.len() {
            return Err(AppError::bad_request(
                "Not all selected ciphers exist in the personal vault",
            ));
        }
        mutation.add_guards(crate::models::vault::cipher::selected_snapshot_guards(
            db,
            mutation.user_id(),
            &rows,
        )?);
        if let CipherMutation::Move { folder_id } = &kind {
            mutation.guard_folder(folder_id.as_deref())?;
        }
        Ok(Self {
            ids,
            ids_json,
            rows,
            bulk,
            kind,
        })
    }

    async fn execute_mutation(
        self,
        mutation: VaultWrite<'_>,
        env: &Env,
        domain: &str,
    ) -> AppResult<Vec<CipherResponse>> {
        let Self {
            ids,
            ids_json,
            rows,
            bulk,
            kind,
        } = self;
        let db = mutation.database();
        let now = crate::utils::time::now_rfc3339();
        let hard_delete = kind == CipherMutation::HardDelete;
        let response = if matches!(
            kind,
            CipherMutation::Restore | CipherMutation::Archive | CipherMutation::Unarchive
        ) {
            let mut response: Vec<_> = rows
                .into_iter()
                .map(CipherResponse::try_from)
                .collect::<AppResult<_>>()?;
            for cipher in &mut response {
                cipher.updated_at.clone_from(&now);
                match &kind {
                    CipherMutation::Restore => cipher.deleted_at = None,
                    CipherMutation::Archive => {
                        cipher.archived_at = Some(now.clone());
                    }
                    CipherMutation::Unarchive => cipher.archived_at = None,
                    _ => {}
                }
            }
            attachment::hydrate_ciphers_attachments(
                db,
                domain,
                attachment::include_metadata(env),
                &mut response,
            )
            .await?;
            response
        } else {
            Vec::new()
        };
        let write = crate::models::vault::cipher::selected_mutation(
            db,
            mutation.user_id(),
            &ids_json,
            &kind,
            &now,
        )?;
        let committed = mutation.commit(vec![write]).await?;
        if bulk {
            committed.publish_user(UpdateType::SyncCiphers).await;
        }
        if !bulk && let Some(id) = ids.first() {
            let update = if hard_delete {
                UpdateType::SyncLoginDelete
            } else {
                UpdateType::SyncCipherUpdate
            };
            committed.publish_cipher(update, id).await;
        }
        if !ids.is_empty() {
            let event = if matches!(
                kind,
                CipherMutation::SoftDelete | CipherMutation::HardDelete
            ) {
                Event::CipherDelete
            } else {
                Event::CipherUpdate
            };
            committed.emit_admin(event).await;
        }
        if hard_delete
            && let Err(error) = crate::service::storage_cleanup::process_batch(env, db).await
        {
            log::warn!("File cleanup deferred: {error}");
        }
        Ok(response)
    }
}

pub(crate) async fn mutate_selected(
    db: &D1Database,
    env: &Env,
    domain: &str,
    claims: &Claims,
    selection: CipherSelection,
    kind: CipherMutation,
) -> AppResult<Vec<CipherResponse>> {
    let mut mutation = VaultWrite::new(db, env, claims);
    SelectionPlan::load(selection, kind, &mut mutation)
        .await?
        .execute_mutation(mutation, env, domain)
        .await
}

/// Read and project each bounded page before loading the next one.
pub(crate) async fn visit_cipher_responses(
    db: &D1Database,
    user_id: &str,
    include_attachments: bool,
    include_ssh_keys: bool,
    newest_first: bool,
    domain: &str,
    mut visit: impl FnMut(CipherResponse) -> AppResult<()>,
) -> AppResult<()> {
    let mut after = None;
    loop {
        let page = CipherRow::list_page(
            db,
            user_id,
            include_attachments,
            include_ssh_keys,
            newest_first,
            after.as_ref(),
        )
        .await?;
        let mut ciphers = page
            .rows
            .into_iter()
            .map(CipherResponse::try_from)
            .collect::<AppResult<Vec<_>>>()?;
        attachment::hydrate_ciphers_attachments(db, domain, include_attachments, &mut ciphers)
            .await?;
        for cipher in ciphers {
            visit(cipher)?;
        }
        let Some(next) = page.next else { return Ok(()) };
        after = Some(next);
    }
}

async fn guard_cipher_write(
    request: &CipherRequest,
    mutation: &mut VaultWrite<'_>,
) -> AppResult<()> {
    let db = mutation.database();
    let account = mutation.guard_account_key().await?;
    request.validate_for_personal_vault(mutation.user_id())?;
    request.validate_encryption_context(mutation.user_id(), account.user_key_id.as_deref())?;
    if let Some(folder) = &request.folder_id {
        FolderRow::ensure_for_user(db, folder, mutation.user_id()).await?;
    }
    mutation.guard_folder(request.folder_id.as_deref())
}

pub(crate) async fn save_cipher(
    db: &D1Database,
    env: &Env,
    domain: &str,
    claims: &Claims,
    id: Option<String>,
    payload: CipherRequest,
) -> AppResult<CipherResponse> {
    let mut mutation = VaultWrite::new(db, env, claims);
    guard_cipher_write(&payload, &mut mutation).await?;
    let existing = if let Some(id) = &id {
        Some(CipherRow::fetch_for_user(db, id, mutation.user_id()).await?)
    } else {
        None
    };
    if let Some(existing) = &existing {
        if client_revision_is_stale(
            &existing.updated_at,
            payload.last_known_revision_at.as_deref(),
        ) {
            return Err(AppError::bad_request(
                "The client copy of this cipher is out of date. Resync the \
                 client and try again.",
            ));
        }
        mutation.guard_cipher(existing)?;
    }
    let now = crate::utils::time::now_rfc3339();
    let mut payload = payload;
    let updates = payload.attachment_key_updates.take();
    let (row, data) = prepare_cipher_row(id, payload, existing.as_ref(), mutation.user_id(), &now)?;
    let mut writes = vec![CipherRow::save_statement(db, &row, existing.is_some())?];
    let mut cipher = CipherResponse::from_row_and_data(row, data);
    let applied = if existing.is_some() {
        let (attachment_writes, applied) = collect_attachment_key_updates(
            db,
            &cipher.id,
            mutation.user_id(),
            updates.as_ref(),
            &now,
        )
        .await?;
        writes.extend(attachment_writes);
        applied
    } else {
        Vec::new()
    };
    attachment::hydrate_cipher_attachments(
        db,
        domain,
        attachment::include_metadata(env),
        &mut cipher,
    )
    .await?;
    if let (Some(list), Some(updates)) = (&mut cipher.attachments, &updates) {
        for attachment in list {
            if applied.contains(&attachment.id)
                && let Some(update) = updates.get(&attachment.id)
            {
                attachment.file_name.clone_from(&update.file_name);
                attachment.encrypted_key = Some(update.key.clone());
            }
        }
    }
    let committed = mutation.commit(writes).await?;
    let (update, event) = if existing.is_some() {
        (UpdateType::SyncCipherUpdate, Event::CipherUpdate)
    } else {
        (UpdateType::SyncCipherCreate, Event::CipherCreate)
    };
    committed.publish_cipher(update, &cipher.id).await;
    committed.emit_admin(event).await;
    Ok(cipher)
}

fn prepare_cipher_row(
    id: Option<String>,
    mut request: CipherRequest,
    existing: Option<&CipherRow>,
    user_id: &str,
    now: &str,
) -> AppResult<(CipherRow, Value)> {
    let cipher_type = request.cipher_type.into();
    let is_favorite = request
        .is_favorite
        .unwrap_or_else(|| existing.is_some_and(|row| row.is_favorite != 0));
    let folder_id = request.folder_id.take();
    let archived_at = request.archived_at.as_deref().and_then(|value| {
        normalize_optional_rfc3339(Some(value))
            .or_else(|| existing.and_then(|row| row.archived_at.clone()))
    });
    let data = serde_json::to_value(request.into_payload()).map_err(AppError::internal_error)?;
    let encoded = serde_json::to_string(&data).map_err(AppError::internal_error)?;
    if encoded.len() > 2_000_000 {
        return Err(AppError::PayloadTooLarge {
            message: "Cipher data exceeds the D1 size limit".into(),
        });
    }
    let row = CipherRow {
        id: id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        user_id: user_id.to_owned(),
        organization_id: None,
        cipher_type,
        data: encoded,
        is_favorite: i32::from(is_favorite),
        folder_id,
        deleted_at: existing.and_then(|row| row.deleted_at.clone()),
        archived_at,
        created_at: existing.map_or_else(|| now.to_owned(), |row| row.created_at.clone()),
        updated_at: now.to_owned(),
    };
    Ok((row, data))
}

pub(crate) async fn update_cipher_partial(
    db: &D1Database,
    env: &Env,
    domain: &str,
    claims: &Claims,
    id: String,
    payload: UpdateCipherPartialRequest,
) -> AppResult<CipherResponse> {
    let mut mutation = VaultWrite::new(db, env, claims);
    let old = CipherRow::fetch_for_user(db, &id, mutation.user_id()).await?;
    if let Some(folder) = &payload.folder_id {
        FolderRow::ensure_for_user(db, folder, mutation.user_id()).await?;
    }
    let now = crate::utils::time::now_rfc3339();
    mutation.guard_cipher(&old)?;
    mutation.guard_folder(payload.folder_id.as_deref())?;
    let write = CipherRow::partial_statement(
        db,
        mutation.user_id(),
        &id,
        payload.folder_id.as_deref(),
        payload.is_favorite,
        &now,
    )?;
    let mut cipher: CipherResponse = old.try_into()?;
    cipher.folder_id = payload.folder_id;
    cipher.is_favorite = payload.is_favorite;
    cipher.updated_at = now;
    attachment::hydrate_cipher_attachments(
        db,
        domain,
        attachment::include_metadata(env),
        &mut cipher,
    )
    .await?;
    let committed = mutation.commit(vec![write]).await?;
    committed
        .publish_cipher(UpdateType::SyncCipherUpdate, &cipher.id)
        .await;
    committed.emit_admin(Event::CipherUpdate).await;
    Ok(cipher)
}

pub(crate) async fn purge_vault(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    claims: &Claims,
    query: Option<&str>,
    payload: AccountVerificationRequest,
) -> AppResult<()> {
    ensure_personal_purge(query)?;
    crate::service::identity::email::verify_password_or_otp(
        db,
        env,
        access_secret,
        claims,
        &payload,
    )
    .await?;
    let mut mutation = VaultWrite::new(db, env, claims);
    let (guard, writes) = CipherRow::purge_statements(db, mutation.user_id()).await?;
    mutation.add_guard(guard);
    let committed = mutation.commit(writes).await?;
    committed.publish_user(UpdateType::SyncVault).await;
    committed.emit_admin(Event::CipherDelete).await;
    if let Err(error) = crate::service::storage_cleanup::process_batch(env, db).await {
        log::warn!("File cleanup deferred: {error}");
    }
    Ok(())
}

fn ensure_personal_purge(query: Option<&str>) -> AppResult<()> {
    if query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, value)| {
            matches!(name.as_ref(), "organizationId" | "organizationID") && !value.is_empty()
        })
    }) {
        return Err(AppError::bad_request(
            "Organization vaults are not supported",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod compatibility_tests {
    use super::ensure_personal_purge;

    #[test]
    fn purge_never_turns_an_organization_selector_into_personal_deletion() {
        for query in [
            "organizationId=organization",
            "organizationID=organization",
            "organizationId=&organizationID=other",
            "organizationId=other&organizationId=",
            "organization%49d=%20",
        ] {
            assert!(ensure_personal_purge(Some(query)).is_err(), "{query}");
        }
        for query in [
            None,
            Some(""),
            Some("organizationId="),
            Some("organizationId=&organizationID="),
        ] {
            assert!(ensure_personal_purge(query).is_ok());
        }
    }
}
