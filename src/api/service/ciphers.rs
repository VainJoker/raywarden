//! Shared personal-vault mutation workflows used by cipher and archive routes.
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{
    D1Database,
    D1PreparedStatement,
};

use crate::{
    api::{
        AppState,
        service::{
            attachments,
            cipher_mutation::{
                self,
                cipher_snapshot_guard,
                folder_guard,
            },
            claims::Claims,
            notifications::{
                self,
                UpdateType,
            },
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    infra::admin_notify::{
        self,
        Event,
    },
    models::{
        attachment::AttachmentDB,
        cipher::{
            Cipher,
            CipherDB,
            CipherRequestData,
        },
        folder::FolderDB,
    },
};

fn optional(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}

pub(crate) async fn collect_attachment_key_updates(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    payload: &CipherRequestData,
    now: &str,
) -> AppResult<(Vec<D1PreparedStatement>, Vec<String>)> {
    let mut writes = Vec::new();
    let mut applied = Vec::new();
    for (id, data) in payload.attachments2.iter().flatten() {
        let row: Option<AttachmentDB> = db
            .prepare(
                "SELECT a.* FROM attachments a JOIN ciphers c ON \
                 c.id=a.cipher_id WHERE a.id=?1 AND c.user_id=?2",
            )
            .bind(&[id.clone().into(), user_id.into()])?
            .first(None)
            .await?;
        let Some(row) = row else {
            continue;
        };
        if row.cipher_id != cipher_id {
            break;
        }
        writes.push(cipher_mutation::guard(
            db,
            "EXISTS(SELECT 1 FROM attachments WHERE id=?1 AND cipher_id=?2 \
             AND file_name IS ?3 AND akey IS ?4 AND updated_at IS ?5 AND \
             storage_key IS ?6 AND file_size IS ?7)",
            &[
                id.clone().into(),
                cipher_id.into(),
                row.file_name.into(),
                optional(row.akey.as_deref()),
                row.updated_at.into(),
                optional(row.storage_key.as_deref()),
                JsValue::from_f64(row.file_size as f64),
            ],
        )?);
        writes.push(
            db.prepare(
                "UPDATE attachments SET file_name=?1,akey=?2,updated_at=?3 \
                 WHERE id=?4 AND cipher_id=?5",
            )
            .bind(&[
                data.file_name.clone().into(),
                data.key.clone().into(),
                now.into(),
                id.clone().into(),
                cipher_id.into(),
            ])?,
        );
        applied.push(id.clone());
    }
    Ok((writes, applied))
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Mutation {
    SoftDelete,
    Restore,
    HardDelete,
    Move,
    Archive,
    Unarchive,
}

// Use JSON selections/snapshots instead of a bind for every row. Long
// individual ciphertexts retain separate column binds, avoiding a second
// JSON-escape limit.
pub(crate) async fn mutate_selected(
    claims: &Claims,
    state: &AppState,
    mut ids: Vec<String>,
    kind: Mutation,
    folder: Option<String>,
    bulk: bool,
) -> AppResult<Vec<Cipher>> {
    ids.sort();
    ids.dedup();
    let db = state.get_db();
    let ids_json =
        serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;
    if ids_json.len() > 1_900_000 {
        return Err(AppError::PayloadTooLarge {
            message: "Cipher selection is too large".into(),
        });
    }
    if let Some(folder) = &folder {
        FolderDB::ensure_for_user(&db, folder, &claims.sub).await?;
    }
    let result = db
        .prepare(
            "SELECT * FROM ciphers WHERE user_id=?1 AND id IN(SELECT value \
             FROM json_each(?2))",
        )
        .bind(&[claims.sub.clone().into(), ids_json.clone().into()])?
        .all()
        .await?;
    let rows: Vec<CipherDB> = crate::infra::db::decode_results(&result)?;
    if rows.len() != ids.len() {
        return Err(AppError::bad_request(
            "Not all selected ciphers exist in the personal vault",
        ));
    }
    let mut guards = Vec::new();
    let mut snapshots = Vec::new();
    let mut bytes = 2;
    let flush = |snapshots: &mut Vec<Value>,
                 guards: &mut Vec<D1PreparedStatement>|
     -> AppResult<()> {
        if snapshots.is_empty() {
            return Ok(());
        }
        let encoded =
            serde_json::to_string(snapshots).map_err(|_| AppError::Internal)?;
        guards.push(cipher_mutation::guard(
            &db,
            "(SELECT COUNT(*) FROM ciphers c JOIN json_each(?2) s ON \
             c.id=json_extract(s.value,'$.id') WHERE c.user_id=?1 AND \
             c.organization_id IS json_extract(s.value,'$.organization_id') \
             AND c.type IS json_extract(s.value,'$.type') AND c.data IS \
             json_extract(s.value,'$.data') AND c.favorite IS \
             json_extract(s.value,'$.favorite') AND c.folder_id IS \
             json_extract(s.value,'$.folder_id') AND c.deleted_at IS \
             json_extract(s.value,'$.deleted_at') AND c.archived_at IS \
             json_extract(s.value,'$.archived_at') AND c.created_at IS \
             json_extract(s.value,'$.created_at') AND c.updated_at IS \
             json_extract(s.value,'$.updated_at'))=json_array_length(?2)",
            &[claims.sub.clone().into(), encoded.into()],
        )?);
        snapshots.clear();
        Ok(())
    };
    for row in &rows {
        let value =
            serde_json::to_value(row).map_err(|_| AppError::Internal)?;
        let size = serde_json::to_string(&value)
            .map_err(|_| AppError::Internal)?
            .len();
        if size > 1_900_000 {
            guards.push(cipher_snapshot_guard(&db, row)?);
            continue;
        }
        if snapshots.len() >= 200 || bytes + size + 1 > 1_900_000 {
            flush(&mut snapshots, &mut guards)?;
            bytes = 2;
        }
        snapshots.push(value);
        bytes += size + 1;
    }
    flush(&mut snapshots, &mut guards)?;
    if kind == Mutation::Move {
        guards.push(folder_guard(&db, &claims.sub, folder.as_deref())?);
    }
    let now = crate::infra::time::now_rfc3339();
    let mut response: Vec<Cipher> = rows
        .into_iter()
        .map(CipherDB::into_api)
        .collect::<AppResult<_>>()?;
    for cipher in &mut response {
        cipher.updated_at.clone_from(&now);
        match kind {
            Mutation::SoftDelete => cipher.deleted_at = Some(now.clone()),
            Mutation::Restore => cipher.deleted_at = None,
            Mutation::Archive => cipher.archived_at = Some(now.clone()),
            Mutation::Unarchive => cipher.archived_at = None,
            Mutation::Move => cipher.folder_id.clone_from(&folder),
            Mutation::HardDelete => {}
        }
    }
    attachments::hydrate_ciphers_attachments(&db, &state.env, &mut response)
        .await?;
    let suffix = " WHERE user_id=?1 AND id IN(SELECT value FROM json_each(?2))";
    let query = match kind {
        Mutation::SoftDelete => {
            format!("UPDATE ciphers SET deleted_at=?3,updated_at=?3{suffix}")
        }
        Mutation::Restore => {
            format!("UPDATE ciphers SET deleted_at=NULL,updated_at=?3{suffix}")
        }
        Mutation::Archive => {
            format!("UPDATE ciphers SET archived_at=?3,updated_at=?3{suffix}")
        }
        Mutation::Unarchive => {
            format!("UPDATE ciphers SET archived_at=NULL,updated_at=?3{suffix}")
        }
        Mutation::Move => {
            format!("UPDATE ciphers SET folder_id=?4,updated_at=?3{suffix}")
        }
        Mutation::HardDelete => format!("DELETE FROM ciphers{suffix}"),
    };
    let mut values = vec![claims.sub.clone().into(), ids_json.into()];
    if kind != Mutation::HardDelete {
        values.push(now.into());
    }
    if kind == Mutation::Move {
        values.push(optional(folder.as_deref()));
    }
    let revision = cipher_mutation::commit(&db, claims, guards, vec![
        db.prepare(query).bind(&values)?,
    ])
    .await?;
    if bulk {
        notifications::publish_user_update(
            &state.env,
            &claims.sub,
            UpdateType::SyncCiphers,
            &revision,
            claims.device(),
        )
        .await;
    } else if let Some(cipher) = response.first() {
        notify_cipher(
            state,
            claims,
            if kind == Mutation::HardDelete {
                UpdateType::SyncLoginDelete
            } else {
                UpdateType::SyncCipherUpdate
            },
            &cipher.id,
            &revision,
        )
        .await;
    }
    if !response.is_empty() {
        admin_notify::emit(
            &state.env,
            if matches!(kind, Mutation::SoftDelete | Mutation::HardDelete) {
                Event::CipherDelete
            } else {
                Event::CipherUpdate
            },
            &claims.sub,
        )
        .await;
    }
    if kind == Mutation::HardDelete {
        if let Err(error) =
            crate::infra::storage::cleanup::drain(&state.env, &db).await
        {
            log::warn!("File cleanup deferred: {error}");
        }
    }
    Ok(response)
}

pub(crate) async fn notify_cipher(
    state: &AppState,
    claims: &Claims,
    kind: UpdateType,
    id: &str,
    revision: &str,
) {
    notifications::publish_cipher_update(
        &state.env,
        &claims.sub,
        kind,
        id,
        revision,
        claims.device(),
    )
    .await;
}
