use axum::{
    Json,
    extract::{
        Path,
        State,
    },
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::{
    D1Database,
    D1PreparedStatement,
};

use crate::{
    api::{
        AppState,
        RawJson,
        service::{
            attachments,
            cipher_mutation::{
                self,
                cipher_snapshot_guard,
                folder_guard,
            },
            ciphers::{
                Mutation,
                collect_attachment_key_updates,
                mutate_selected,
                notify_cipher,
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
            CipherData,
            CipherRequestData,
            CreateCipherRequest,
            PartialCipherData,
            client_revision_is_stale,
            normalize_optional_rfc3339,
        },
        folder::FolderDB,
        user::PasswordOrOtpData,
    },
};

fn optional(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}

async fn payload_guards(
    db: &D1Database,
    claims: &Claims,
    payload: &CipherRequestData,
) -> AppResult<Vec<D1PreparedStatement>> {
    let key_guard = cipher_mutation::account_key_guard(db, claims).await?;
    payload.validate_for_personal_vault(&claims.sub)?;
    let key_id: Option<String> = if payload.encrypted_by_key_id.is_some() {
        db.prepare("SELECT user_key_id FROM users WHERE id=?1")
            .bind(&[claims.sub.clone().into()])?
            .first(Some("user_key_id"))
            .await?
    } else {
        None
    };
    payload.validate_encryption_context(&claims.sub, key_id.as_deref())?;
    if let Some(folder) = &payload.folder_id {
        FolderDB::ensure_for_user(db, folder, &claims.sub).await?;
    }
    Ok(vec![
        key_guard,
        folder_guard(db, &claims.sub, payload.folder_id.as_deref())?,
        cipher_mutation::guard(
            db,
            "?2 IS NULL OR EXISTS(SELECT 1 FROM users WHERE id=?1 AND \
             (user_key_id IS NULL OR user_key_id=?2))",
            &[
                claims.sub.clone().into(),
                optional(payload.encrypted_by_key_id.as_deref()),
            ],
        )?,
    ])
}

async fn save_cipher(
    claims: Claims,
    state: AppState,
    id: Option<String>,
    payload: CipherRequestData,
) -> AppResult<Json<Cipher>> {
    let db = state.get_db();
    let mut guards = payload_guards(&db, &claims, &payload).await?;
    let existing = if let Some(id) = &id {
        Some(CipherDB::fetch_for_user(&db, id, &claims.sub).await?)
    } else {
        None
    };
    if let Some(existing) = &existing {
        if client_revision_is_stale(
            &existing.updated_at,
            payload.last_known_revision_date.as_deref(),
        ) {
            return Err(AppError::bad_request(
                "The client copy of this cipher is out of date. Resync the \
                 client and try again.",
            ));
        }
        guards.push(cipher_snapshot_guard(&db, existing)?);
    }
    let now = crate::infra::time::now_rfc3339();
    let data = serde_json::to_value(CipherData::from_request(&payload))
        .map_err(|_| AppError::Internal)?;
    let encoded =
        serde_json::to_string(&data).map_err(|_| AppError::Internal)?;
    if encoded.len() > 2_000_000 {
        return Err(AppError::PayloadTooLarge {
            message: "Cipher data exceeds the D1 size limit".into(),
        });
    }
    let archived_at = match payload.archived_date.as_deref() {
        None => None,
        Some(value) => normalize_optional_rfc3339(Some(value)).or_else(|| {
            existing.as_ref().and_then(|row| row.archived_at.clone())
        }),
    };
    let mut cipher = Cipher {
        id: id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        user_id: Some(claims.sub.clone()),
        organization_id: None,
        r#type: payload.r#type,
        data,
        favorite: payload.favorite.unwrap_or_else(|| {
            existing.as_ref().is_some_and(|row| row.favorite != 0)
        }),
        folder_id: payload.folder_id.clone(),
        deleted_at: existing.as_ref().and_then(|row| row.deleted_at.clone()),
        archived_at,
        created_at: existing
            .as_ref()
            .map_or_else(|| now.clone(), |row| row.created_at.clone()),
        updated_at: now.clone(),
        object: "cipherDetails".into(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
        attachments: None,
    };
    let write = if existing.is_some() {
        db.prepare(
            "UPDATE ciphers SET \
             type=?1,data=?2,favorite=?3,folder_id=?4,archived_at=?5,\
             updated_at=?6 WHERE id=?7 AND user_id=?8",
        )
        .bind(&[
            cipher.r#type.into(),
            encoded.into(),
            cipher.favorite.into(),
            optional(cipher.folder_id.as_deref()),
            optional(cipher.archived_at.as_deref()),
            now.clone().into(),
            cipher.id.clone().into(),
            claims.sub.clone().into(),
        ])?
    } else {
        db.prepare(
            "INSERT INTO \
             ciphers(id,user_id,organization_id,type,data,favorite,folder_id,\
             archived_at,created_at,updated_at) \
             VALUES(?1,?2,NULL,?3,?4,?5,?6,?7,?8,?8)",
        )
        .bind(&[
            cipher.id.clone().into(),
            claims.sub.clone().into(),
            cipher.r#type.into(),
            encoded.into(),
            cipher.favorite.into(),
            optional(cipher.folder_id.as_deref()),
            optional(cipher.archived_at.as_deref()),
            now.clone().into(),
        ])?
    };
    let mut writes = vec![write];
    let mut applied_attachments = Vec::new();
    if existing.is_some() {
        let (attachment_writes, applied) = collect_attachment_key_updates(
            &db,
            &cipher.id,
            &claims.sub,
            &payload,
            &now,
        )
        .await?;
        writes.extend(attachment_writes);
        applied_attachments = applied;
    }
    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    if let Some(list) = &mut cipher.attachments {
        for attachment in list {
            if !applied_attachments.contains(&attachment.id) {
                continue;
            }
            if let Some(update) = payload
                .attachments2
                .as_ref()
                .and_then(|m| m.get(&attachment.id))
            {
                attachment.file_name = update.file_name.clone();
                attachment.key = Some(update.key.clone());
            }
        }
    }
    let revision =
        cipher_mutation::commit(&db, &claims, guards, writes).await?;
    notify_cipher(
        &state,
        &claims,
        if existing.is_some() {
            UpdateType::SyncCipherUpdate
        } else {
            UpdateType::SyncCipherCreate
        },
        &cipher.id,
        &revision,
    )
    .await;
    admin_notify::emit(
        &state.env,
        if existing.is_some() {
            Event::CipherUpdate
        } else {
            Event::CipherCreate
        },
        &claims.sub,
    )
    .await;
    Ok(Json(cipher))
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateCipherRequest>,
) -> AppResult<Json<Cipher>> {
    if !payload.collection_ids.is_empty() {
        return Err(AppError::bad_request("Collections are not supported"));
    }
    save_cipher(claims, state, None, payload.cipher).await
}
#[worker::send]
pub async fn create_cipher_simple(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CipherRequestData>,
) -> AppResult<Json<Cipher>> {
    save_cipher(claims, state, None, payload).await
}
#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> AppResult<Json<Cipher>> {
    save_cipher(claims, state, Some(id), payload).await
}

#[worker::send]
pub async fn list_ciphers(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<RawJson> {
    let data = CipherDB::fetch_cipher_json_array_raw(
        &state.get_db(),
        AttachmentDB::attachments_enabled(&state.env),
        "WHERE c.user_id=?1",
        &[claims.sub.into()],
        "ORDER BY c.updated_at DESC",
        state.get_domain(),
    )
    .await?;
    Ok(RawJson(format!(
        r#"{{"data":{data},"object":"list","continuationToken":null}}"#
    )))
}
#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Cipher>> {
    let db = state.get_db();
    let mut cipher = CipherDB::fetch_for_user(&db, &id, &claims.sub)
        .await?
        .into_api()?;
    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    Ok(Json(cipher))
}
#[worker::send]
pub async fn get_cipher_details(
    claims: Claims,
    state: State<AppState>,
    id: Path<String>,
) -> AppResult<Json<Cipher>> {
    get_cipher(claims, state, id).await
}

#[worker::send]
pub async fn update_cipher_partial(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<PartialCipherData>,
) -> AppResult<Json<Cipher>> {
    let db = state.get_db();
    let old = CipherDB::fetch_for_user(&db, &id, &claims.sub).await?;
    if let Some(folder) = &payload.folder_id {
        FolderDB::ensure_for_user(&db, folder, &claims.sub).await?;
    }
    let now = crate::infra::time::now_rfc3339();
    let guards = vec![
        cipher_snapshot_guard(&db, &old)?,
        folder_guard(&db, &claims.sub, payload.folder_id.as_deref())?,
    ];
    let write = db
        .prepare(
            "UPDATE ciphers SET folder_id=?1,favorite=?2,updated_at=?3 WHERE \
             id=?4 AND user_id=?5",
        )
        .bind(&[
            optional(payload.folder_id.as_deref()),
            payload.favorite.into(),
            now.clone().into(),
            id.into(),
            claims.sub.clone().into(),
        ])?;
    let mut cipher: Cipher = old.into_api()?;
    cipher.folder_id = payload.folder_id;
    cipher.favorite = payload.favorite;
    cipher.updated_at = now;
    attachments::hydrate_cipher_attachments(&db, &state.env, &mut cipher)
        .await?;
    let revision =
        cipher_mutation::commit(&db, &claims, guards, vec![write]).await?;
    notify_cipher(
        &state,
        &claims,
        UpdateType::SyncCipherUpdate,
        &cipher.id,
        &revision,
    )
    .await;
    admin_notify::emit(&state.env, Event::CipherUpdate, &claims.sub).await;
    Ok(Json(cipher))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Selection {
    ids:       Vec<String>,
    folder_id: Option<String>,
}
fn selection(body: &str) -> AppResult<Selection> {
    serde_json::from_str(body)
        .map_err(|_| AppError::bad_request("Invalid cipher selection"))
}

#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<()>> {
    mutate_selected(
        &claims,
        &state,
        vec![id],
        Mutation::SoftDelete,
        None,
        false,
    )
    .await?;
    Ok(Json(()))
}
#[worker::send]
pub async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> AppResult<Json<()>> {
    mutate_selected(
        &claims,
        &state,
        selection(&body)?.ids,
        Mutation::SoftDelete,
        None,
        true,
    )
    .await?;
    Ok(Json(()))
}
#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<()>> {
    mutate_selected(
        &claims,
        &state,
        vec![id],
        Mutation::HardDelete,
        None,
        false,
    )
    .await?;
    Ok(Json(()))
}
#[worker::send]
pub async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> AppResult<Json<()>> {
    mutate_selected(
        &claims,
        &state,
        selection(&body)?.ids,
        Mutation::HardDelete,
        None,
        true,
    )
    .await?;
    Ok(Json(()))
}
#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Cipher>> {
    let cipher = mutate_selected(
        &claims,
        &state,
        vec![id],
        Mutation::Restore,
        None,
        false,
    )
    .await?
    .into_iter()
    .next()
    .ok_or(AppError::Internal)?;
    Ok(Json(cipher))
}
#[worker::send]
pub async fn restore_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> AppResult<Json<Value>> {
    let rows = mutate_selected(
        &claims,
        &state,
        selection(&body)?.ids,
        Mutation::Restore,
        None,
        true,
    )
    .await?;
    Ok(Json(
        json!({"data":rows,"object":"list","continuationToken":null}),
    ))
}
#[worker::send]
pub async fn move_cipher_selected(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> AppResult<Json<()>> {
    let selection = selection(&body)?;
    mutate_selected(
        &claims,
        &state,
        selection.ids,
        Mutation::Move,
        selection.folder_id,
        true,
    )
    .await?;
    Ok(Json(()))
}

#[worker::send]
pub async fn purge_vault(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<PasswordOrOtpData>,
) -> AppResult<Json<()>> {
    crate::api::service::email::verify_password_or_otp(
        &state, &claims, &payload,
    )
    .await?;
    let db = state.get_db();
    let revision: String = db
        .prepare("SELECT updated_at FROM users WHERE id=?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("updated_at"))
        .await?
        .ok_or(AppError::Internal)?;
    let guard = cipher_mutation::guard(
        &db,
        "EXISTS(SELECT 1 FROM users WHERE id=?1 AND updated_at IS ?2)",
        &[claims.sub.clone().into(), revision.into()],
    )?;
    let writes = vec![
        db.prepare("DELETE FROM ciphers WHERE user_id=?1")
            .bind(&[claims.sub.clone().into()])?,
        db.prepare("DELETE FROM folders WHERE user_id=?1")
            .bind(&[claims.sub.clone().into()])?,
    ];
    let revision =
        cipher_mutation::commit(&db, &claims, vec![guard], writes).await?;
    notifications::publish_user_update(
        &state.env,
        &claims.sub,
        UpdateType::SyncVault,
        &revision,
        claims.device(),
    )
    .await;
    admin_notify::emit(&state.env, Event::CipherDelete, &claims.sub).await;
    if let Err(error) =
        crate::infra::storage::cleanup::drain(&state.env, &db).await
    {
        log::warn!("File cleanup deferred: {error}");
    }
    Ok(Json(()))
}
