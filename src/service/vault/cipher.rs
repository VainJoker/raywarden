//! Personal-vault cipher workflows and protocol contracts.
mod request;
mod response;

pub use request::{
    CipherPayload,
    CipherRequest,
    CreateCipherWithCollectionsRequest,
    UpdateCipherPartialRequest,
    client_revision_is_stale,
    normalize_optional_rfc3339,
};
pub use response::CipherResponse;
use serde::Deserialize;
use uuid::Uuid;
use worker::{
    D1Database,
    D1PreparedStatement,
};

use super::attachment;
use crate::{
    app::AppContext,
    errors::{
        AppError,
        AppResult,
    },
    models::vault::{
        attachment::AttachmentRow,
        cipher::{
            CipherMutation,
            CipherRow,
            CipherWithAttachmentsRow,
        },
        folder::FolderRow,
    },
    service::{
        identity::{
            session::Claims,
            user::AccountVerificationRequest,
        },
        notifications::{
            UpdateType,
            admin::Event,
        },
        vault_write::VaultWrite,
    },
};

async fn collect_attachment_key_updates(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    payload: &CipherRequest,
    now: &str,
) -> AppResult<(Vec<D1PreparedStatement>, Vec<String>)> {
    let mut writes = Vec::new();
    let mut applied = Vec::new();
    for (id, data) in payload.attachment_key_updates.iter().flatten() {
        let row = AttachmentRow::find_for_user(db, id, user_id).await?;
        let Some(row) = row.filter(|row| row.cipher_id == cipher_id) else {
            continue;
        };
        writes.extend(AttachmentRow::rotate_key_statements(
            db,
            &row,
            &data.file_name,
            &data.key,
            now,
        )?);
        applied.push(id.clone());
    }
    Ok((writes, applied))
}

/// Single mutations publish an item update; bulk mutations publish a vault
/// update even when the selection is empty.
pub(crate) enum CipherSelection {
    Single(String),
    Bulk(Vec<String>),
}

// Use JSON selections/snapshots instead of a bind for every row. Long
// individual ciphertexts retain separate column binds, avoiding a second
// JSON-escape limit.
#[allow(
    clippy::too_many_lines,
    reason = "Keep selection checks, the atomic mutation and its post-commit \
              notifications together"
)]
pub(crate) async fn mutate_selected(
    claims: &Claims,
    state: &AppContext,
    selection: CipherSelection,
    kind: CipherMutation,
) -> AppResult<Vec<CipherResponse>> {
    let (mut ids, bulk) = match selection {
        CipherSelection::Single(id) => (vec![id], false),
        CipherSelection::Bulk(ids) => (ids, true),
    };
    ids.sort();
    ids.dedup();
    let mut mutation = VaultWrite::new(state, claims);
    let db = mutation.database();
    let ids_json =
        serde_json::to_string(&ids).map_err(AppError::internal_error)?;
    if ids_json.len() > 1_900_000 {
        return Err(AppError::PayloadTooLarge {
            message: "Cipher selection is too large".into(),
        });
    }
    if let CipherMutation::Move {
        folder_id: Some(folder),
    } = &kind
    {
        FolderRow::ensure_for_user(db, folder, mutation.user_id()).await?;
    }
    let rows =
        CipherRow::fetch_selected(db, mutation.user_id(), &ids_json).await?;
    if rows.len() != ids.len() {
        return Err(AppError::bad_request(
            "Not all selected ciphers exist in the personal vault",
        ));
    }
    mutation.add_guards(
        crate::models::vault::cipher::selected_snapshot_guards(
            db,
            mutation.user_id(),
            &rows,
        )?,
    );
    if let CipherMutation::Move { folder_id } = &kind {
        mutation.guard_folder(folder_id.as_deref())?;
    }
    let now = crate::utils::time::now_rfc3339();
    let hard_delete = kind == CipherMutation::HardDelete;
    let response = if matches!(
        kind,
        CipherMutation::Restore |
            CipherMutation::Archive |
            CipherMutation::Unarchive
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
        attachment::hydrate_ciphers_attachments(state, &mut response).await?;
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
    if hard_delete &&
        let Err(error) =
            crate::service::storage_cleanup::process_batch(&state.env, db)
                .await
    {
        log::warn!("File cleanup deferred: {error}");
    }
    Ok(response)
}

/// Read one coherent set of persisted rows, then project the client protocol.
pub(crate) async fn list_cipher_responses_json(
    db: &D1Database,
    user_id: &str,
    include_attachments: bool,
    include_ssh_keys: bool,
    newest_first: bool,
    domain: &str,
) -> AppResult<String> {
    let rows = CipherRow::fetch_with_attachments(
        db,
        user_id,
        include_attachments,
        include_ssh_keys,
        newest_first,
    )
    .await?;
    let ciphers = rows
        .into_iter()
        .map(|row| project_cipher(row, domain))
        .collect::<AppResult<Vec<_>>>()?;
    serde_json::to_string(&ciphers).map_err(AppError::internal_error)
}

fn project_cipher(
    row: CipherWithAttachmentsRow,
    domain: &str,
) -> AppResult<CipherResponse> {
    let mut cipher = CipherResponse::try_from(row.cipher)?;
    if let Some(raw) = row.attachments_json {
        let records: Vec<AttachmentRow> =
            serde_json::from_str(&raw).map_err(AppError::internal_error)?;
        let responses = records
            .iter()
            .map(|record| {
                let url = attachment::unsigned_download_url(
                    domain, &cipher.id, &record.id,
                );
                attachment::attachment_response(record, Some(url))
            })
            .collect::<Vec<_>>();
        cipher.attachments = (!responses.is_empty()).then_some(responses);
    }
    Ok(cipher)
}

async fn guard_cipher_write(
    request: &CipherRequest,
    mutation: &mut VaultWrite<'_>,
) -> AppResult<()> {
    let db = mutation.database();
    let account = mutation.guard_account_key().await?;
    request.validate_for_personal_vault(mutation.user_id())?;
    request.validate_encryption_context(
        mutation.user_id(),
        account.user_key_id.as_deref(),
    )?;
    if let Some(folder) = &request.folder_id {
        FolderRow::ensure_for_user(db, folder, mutation.user_id()).await?;
    }
    mutation.guard_folder(request.folder_id.as_deref())
}

pub(crate) async fn save_cipher(
    claims: &Claims,
    state: &AppContext,
    id: Option<String>,
    payload: CipherRequest,
) -> AppResult<CipherResponse> {
    let mut mutation = VaultWrite::new(state, claims);
    let db = mutation.database();
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
    let data = serde_json::to_value(CipherPayload::from_request(&payload))
        .map_err(AppError::internal_error)?;
    let encoded =
        serde_json::to_string(&data).map_err(AppError::internal_error)?;
    if encoded.len() > 2_000_000 {
        return Err(AppError::PayloadTooLarge {
            message: "Cipher data exceeds the D1 size limit".into(),
        });
    }
    let archived_at = match payload.archived_at.as_deref() {
        None => None,
        Some(value) => normalize_optional_rfc3339(Some(value)).or_else(|| {
            existing.as_ref().and_then(|row| row.archived_at.clone())
        }),
    };
    let row = CipherRow {
        id: id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        user_id: mutation.user_id().to_owned(),
        organization_id: None,
        cipher_type: payload.cipher_type,
        data: encoded,
        is_favorite: i32::from(payload.is_favorite.unwrap_or_else(|| {
            existing.as_ref().is_some_and(|row| row.is_favorite != 0)
        })),
        folder_id: payload.folder_id.clone(),
        deleted_at: existing.as_ref().and_then(|row| row.deleted_at.clone()),
        archived_at,
        created_at: existing
            .as_ref()
            .map_or_else(|| now.clone(), |row| row.created_at.clone()),
        updated_at: now.clone(),
    };
    let write = CipherRow::save_statement(db, &row, existing.is_some())?;
    let mut cipher = CipherResponse::from_row_and_data(row, data);
    let mut writes = vec![write];
    let mut applied_attachments = Vec::new();
    if existing.is_some() {
        let (attachment_writes, applied) = collect_attachment_key_updates(
            db,
            &cipher.id,
            mutation.user_id(),
            &payload,
            &now,
        )
        .await?;
        writes.extend(attachment_writes);
        applied_attachments = applied;
    }
    attachment::hydrate_cipher_attachments(state, &mut cipher).await?;
    if let Some(list) = &mut cipher.attachments {
        for attachment in list {
            if !applied_attachments.contains(&attachment.id) {
                continue;
            }
            if let Some(update) = payload
                .attachment_key_updates
                .as_ref()
                .and_then(|m| m.get(&attachment.id))
            {
                attachment.file_name = update.file_name.clone();
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

pub(crate) async fn update_cipher_partial(
    claims: &Claims,
    state: &AppContext,
    id: String,
    payload: UpdateCipherPartialRequest,
) -> AppResult<CipherResponse> {
    let mut mutation = VaultWrite::new(state, claims);
    let db = mutation.database();
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
    attachment::hydrate_cipher_attachments(state, &mut cipher).await?;
    let committed = mutation.commit(vec![write]).await?;
    committed
        .publish_cipher(UpdateType::SyncCipherUpdate, &cipher.id)
        .await;
    committed.emit_admin(Event::CipherUpdate).await;
    Ok(cipher)
}

pub(crate) async fn purge_vault(
    claims: &Claims,
    state: &AppContext,
    query: Option<&str>,
    payload: AccountVerificationRequest,
) -> AppResult<()> {
    ensure_personal_purge(query)?;
    crate::service::identity::email::verify_password_or_otp(
        state, claims, &payload,
    )
    .await?;
    let mut mutation = VaultWrite::new(state, claims);
    let db = mutation.database();
    let (guard, writes) =
        CipherRow::purge_statements(db, mutation.user_id()).await?;
    mutation.add_guard(guard);
    let committed = mutation.commit(writes).await?;
    committed.publish_user(UpdateType::SyncVault).await;
    committed.emit_admin(Event::CipherDelete).await;
    if let Err(error) =
        crate::service::storage_cleanup::process_batch(&state.env, db).await
    {
        log::warn!("File cleanup deferred: {error}");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CipherSelectionRequest {
    pub ids:       Vec<String>,
    pub folder_id: Option<String>,
}
pub(crate) fn parse_cipher_selection(
    body: &str,
) -> AppResult<CipherSelectionRequest> {
    let mut selection: CipherSelectionRequest = serde_json::from_str(body)
        .map_err(|_error| AppError::bad_request("Invalid cipher selection"))?;
    selection.folder_id = selection.folder_id.filter(|id| !id.is_empty());
    Ok(selection)
}

fn ensure_personal_purge(query: Option<&str>) -> AppResult<()> {
    if query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, value)| {
            matches!(name.as_ref(), "organizationId" | "organizationID") &&
                !value.is_empty()
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
    use super::{
        ensure_personal_purge,
        parse_cipher_selection,
    };

    #[test]
    fn attachment_projection_preserves_client_fields_and_hides_storage_metadata()
     {
        use serde_json::json;

        use crate::models::vault::cipher::CipherWithAttachmentsRow;
        let row: CipherWithAttachmentsRow = serde_json::from_value(json!({
            "id": "cipher", "user_id": "owner", "organization_id": null,
            "cipher_type": 1, "data": "{\"name\":\"encrypted\",\"login\":{}}", "is_favorite": 0,
            "folder_id": null, "deleted_at": null, "created_at": "created", "updated_at": "updated",
            "attachments_json": serde_json::to_string(&json!([{
                "id": "attachment", "cipher_id": "cipher", "file_name": "encrypted-name",
                "file_size_bytes": 1536, "encrypted_key": "wrapped-key", "created_at": "created", "updated_at": "updated",
                "organization_id": null, "storage_key": "private/storage/key"
            }])).expect("valid vault workflow fixture")
        })).expect("valid vault workflow fixture");
        let response = serde_json::to_value(
            super::project_cipher(row, "https://vault.example/")
                .expect("valid vault workflow fixture"),
        )
        .expect("valid vault workflow fixture");
        assert_eq!(
            response["attachments"],
            json!([{
                "id": "attachment", "url": "https://vault.example/attachments/cipher/attachment",
                "fileName": "encrypted-name", "size": "1536", "sizeName": "1.5 KB", "key": "wrapped-key", "object": "attachment"
            }])
        );
        assert!(!response.to_string().contains("private/storage/key"));
    }

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

    #[test]
    fn an_empty_move_folder_clears_the_relationship_without_normalizing_other_ids()
     {
        for body in [
            r#"{"ids":[],"folderId":""}"#,
            r#"{"ids":[],"folderId":null}"#,
            r#"{"ids":[]}"#,
        ] {
            assert!(
                parse_cipher_selection(body)
                    .expect("valid vault workflow fixture")
                    .folder_id
                    .is_none()
            );
        }
        assert_eq!(
            parse_cipher_selection(r#"{"ids":["cipher"],"folderId":"folder"}"#)
                .expect("valid vault workflow fixture")
                .folder_id
                .as_deref(),
            Some("folder")
        );
        assert_eq!(
            parse_cipher_selection(r#"{"ids":[],"folderId":" "}"#)
                .expect("valid vault workflow fixture")
                .folder_id
                .as_deref(),
            Some(" ")
        );
    }
}
