use std::collections::HashSet;

use axum::{
    Json,
    extract::State,
};
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
        service::{
            cipher_mutation,
            claims::Claims,
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
        cipher::{
            CipherData,
            normalize_optional_rfc3339,
        },
        folder::FolderDB,
        import::ImportRequest,
    },
};

const JSON_BIND_BYTES: usize = 1_900_000;
const D1_STRING_BYTES: usize = 2_000_000;

enum ImportChunk {
    Json(String),
    Columns(Vec<JsValue>),
}

// A JSON string can exceed D1's bind limit solely because ciphertext is escaped
// a second time. Fall back to ordinary column binds for that individual row.
fn import_chunks(
    rows: Vec<Value>,
    maximum_rows: usize,
) -> AppResult<Vec<ImportChunk>> {
    let mut chunks = Vec::new();
    let mut batch = Vec::new();
    let mut bytes = 2;
    for row in rows {
        let columns = row.as_array().ok_or(AppError::Internal)?;
        if columns.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value.len() > D1_STRING_BYTES)
        }) {
            return Err(AppError::PayloadTooLarge {
                message: "Imported field exceeds the D1 size limit".into(),
            });
        }
        let encoded =
            serde_json::to_string(&row).map_err(|_| AppError::Internal)?;
        if !batch.is_empty() &&
            (batch.len() >= maximum_rows ||
                bytes + encoded.len() + 1 > JSON_BIND_BYTES)
        {
            chunks.push(ImportChunk::Json(
                serde_json::to_string(&batch)
                    .map_err(|_| AppError::Internal)?,
            ));
            batch.clear();
            bytes = 2;
        }
        if encoded.len() + 2 > JSON_BIND_BYTES {
            let columns = columns
                .iter()
                .map(|value| match value {
                    Value::Null => Ok(JsValue::NULL),
                    Value::String(v) => Ok(v.clone().into()),
                    Value::Bool(v) => Ok(i32::from(*v).into()),
                    Value::Number(v) => v
                        .as_f64()
                        .map(JsValue::from_f64)
                        .ok_or(AppError::Internal),
                    _ => Err(AppError::Internal),
                })
                .collect::<AppResult<Vec<_>>>()?;
            chunks.push(ImportChunk::Columns(columns));
        } else {
            bytes += encoded.len() + 1;
            batch.push(row);
        }
    }
    if !batch.is_empty() {
        chunks.push(ImportChunk::Json(
            serde_json::to_string(&batch).map_err(|_| AppError::Internal)?,
        ));
    }
    Ok(chunks)
}
fn collect_writes(
    db: &D1Database,
    rows: Vec<Value>,
    maximum_rows: usize,
    json_sql: &str,
    columns_sql: &str,
    shared: &[JsValue],
    writes: &mut Vec<D1PreparedStatement>,
) -> AppResult<()> {
    for chunk in import_chunks(rows, maximum_rows)? {
        let (sql, mut values) = match chunk {
            ImportChunk::Json(value) => (json_sql, vec![value.into()]),
            ImportChunk::Columns(values) => (columns_sql, values),
        };
        values.extend_from_slice(shared);
        writes.push(db.prepare(sql).bind(&values)?);
    }
    Ok(())
}

#[worker::send]
pub async fn import_data(
    claims: Claims,
    State(state): State<AppState>,
    Json(mut payload): Json<ImportRequest>,
) -> AppResult<Json<()>> {
    let db = state.get_db();
    let key_guard = cipher_mutation::account_key_guard(&db, &claims).await?;
    let user_key_id: Option<String> = if payload
        .ciphers
        .iter()
        .any(|cipher| cipher.encrypted_by_key_id.is_some())
    {
        db.prepare("SELECT user_key_id FROM users WHERE id=?1")
            .bind(&[claims.sub.clone().into()])?
            .first(Some("user_key_id"))
            .await?
    } else {
        None
    };
    for cipher in &mut payload.ciphers {
        // Exported organization and folder identifiers belong to the source
        // vault. Relationships below are the import protocol's folder mapping.
        cipher.organization_id = None;
        cipher.folder_id = None;
        cipher.validate_for_personal_vault(&claims.sub)?;
        cipher
            .validate_encryption_context(&claims.sub, user_key_id.as_deref())?;
    }
    for link in &payload.folder_relationships {
        if link.key >= payload.ciphers.len() ||
            link.value >= payload.folders.len()
        {
            return Err(AppError::bad_request(
                "Invalid cipher-folder import relationship",
            ));
        }
    }
    let existing: HashSet<String> = FolderDB::list_for_user(&db, &claims.sub)
        .await?
        .into_iter()
        .map(|folder| folder.id)
        .collect();
    let mut resolved = Vec::new();
    let mut folders = Vec::new();
    for folder in &payload.folders {
        let id = folder
            .id
            .as_ref()
            .filter(|id| existing.contains(*id))
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        if !existing.contains(&id) {
            folders.push(json!([id, folder.name]));
        }
        resolved.push(id);
    }
    for link in &payload.folder_relationships {
        payload.ciphers[link.key].folder_id =
            Some(resolved[link.value].clone());
    }
    let required: HashSet<String> = payload
        .ciphers
        .iter()
        .filter_map(|cipher| cipher.folder_id.as_ref())
        .filter(|id| existing.contains(*id))
        .cloned()
        .collect();
    let folder_guard = cipher_mutation::guard(
        &db,
        "NOT EXISTS(SELECT 1 FROM json_each(?1) required WHERE NOT \
         EXISTS(SELECT 1 FROM folders WHERE id=required.value AND user_id=?2))",
        &[
            serde_json::to_string(&required)
                .map_err(|_| AppError::Internal)?
                .into(),
            claims.sub.clone().into(),
        ],
    )?;
    let now = crate::infra::time::now_rfc3339();
    let mut ciphers = Vec::new();
    for cipher in payload.ciphers {
        let data = serde_json::to_string(&CipherData::from_request(&cipher))
            .map_err(|_| AppError::Internal)?;
        ciphers.push(json!([
            Uuid::new_v4().to_string(),
            cipher.r#type,
            data,
            cipher.favorite.unwrap_or(false),
            cipher.folder_id,
            normalize_optional_rfc3339(cipher.archived_date.as_deref())
        ]));
    }
    let maximum_rows = state.config.import_batch_size.clamp(1, 200) as usize;
    let shared = [claims.sub.clone().into(), now.into()];
    let mut writes = Vec::new();
    collect_writes(
        &db,
        folders,
        maximum_rows,
        "INSERT INTO folders(id,user_id,name,created_at,updated_at) SELECT \
         json_extract(value,'$[0]'),?2,json_extract(value,'$[1]'),?3,?3 FROM \
         json_each(?1)",
        "INSERT INTO folders(id,user_id,name,created_at,updated_at) \
         VALUES(?1,?3,?2,?4,?4)",
        &shared,
        &mut writes,
    )?;
    collect_writes(
        &db,
        ciphers,
        maximum_rows,
        "INSERT INTO \
         ciphers(id,user_id,organization_id,type,data,favorite,folder_id,\
         archived_at,created_at,updated_at) SELECT \
         json_extract(value,'$[0]'),?2,NULL,json_extract(value,'$[1]'),\
         json_extract(value,'$[2]'),json_extract(value,'$[3]'),\
         json_extract(value,'$[4]'),json_extract(value,'$[5]'),?3,?3 FROM \
         json_each(?1)",
        "INSERT INTO \
         ciphers(id,user_id,organization_id,type,data,favorite,folder_id,\
         archived_at,created_at,updated_at) \
         VALUES(?1,?7,NULL,?2,?3,?4,?5,?6,?8,?8)",
        &shared,
        &mut writes,
    )?;
    let revision = cipher_mutation::commit(
        &db,
        &claims,
        vec![key_guard, folder_guard],
        writes,
    )
    .await?;
    crate::api::service::notifications::publish_user_update(
        &state.env,
        &claims.sub,
        crate::api::service::notifications::UpdateType::SyncVault,
        &revision,
        claims.device(),
    )
    .await;
    admin_notify::emit(&state.env, Event::Import, &claims.sub).await;
    Ok(Json(()))
}
