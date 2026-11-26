//! D1 import batching and transaction statement construction.
use std::collections::HashSet;

use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{D1Database, D1PreparedStatement};

#[cfg(test)]
use super::json_batch::JSON_BATCH_BYTES;
use super::json_batch::{BatchPush, JsonBatch};
use crate::{
    errors::{AppError, AppResult},
    infra::db::{self, IntoD1Param},
};

const D1_STRING_BYTES: usize = 2_000_000;

enum ImportChunk {
    Json(String),
    Columns(Vec<JsValue>),
}

impl ImportChunk {
    fn statement(
        self,
        db: &D1Database,
        json_sql: &str,
        columns_sql: &str,
        shared: &[JsValue],
    ) -> worker::Result<D1PreparedStatement> {
        let (sql, mut values) = match self {
            Self::Json(value) => (json_sql, vec![value.to_d1_param()]),
            Self::Columns(values) => (columns_sql, values),
        };
        values.extend_from_slice(shared);
        db.prepare(sql).bind(&values)
    }
}

// A JSON string can exceed D1's bind limit solely because ciphertext is escaped
// a second time. Fall back to ordinary column binds for that individual row.
fn import_chunks(rows: Vec<Value>, maximum_rows: usize) -> AppResult<Vec<ImportChunk>> {
    let mut chunks = Vec::new();
    let mut batch = JsonBatch::new(maximum_rows);
    for row in rows {
        let columns = row
            .as_array()
            .ok_or_else(|| AppError::internal("Encoded import row must be a JSON array"))?;
        if columns.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value.len() > D1_STRING_BYTES)
        }) {
            return Err(AppError::PayloadTooLarge {
                message: "Imported field exceeds the D1 size limit".into(),
            });
        }
        let encoded = serde_json::to_string(&row)
            .map_err(AppError::internal_json("Failed to serialize import row"))?;
        match batch.push(&encoded) {
            BatchPush::Queued(completed) => {
                chunks.extend(completed.map(ImportChunk::Json));
            }
            BatchPush::Oversized => {
                chunks.extend(batch.take().map(ImportChunk::Json));
                let columns = columns
                    .iter()
                    .map(|value| {
                        db::json_scalar_param(value, "Expected scalar import column value")
                    })
                    .collect::<AppResult<Vec<_>>>()?;
                chunks.push(ImportChunk::Columns(columns));
            }
        }
    }
    chunks.extend(batch.take().map(ImportChunk::Json));
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
        writes.push(chunk.statement(db, json_sql, columns_sql, shared)?);
    }
    Ok(())
}

pub(crate) fn required_folder_guard(
    db: &D1Database,
    user_id: &str,
    required: &HashSet<String>,
) -> AppResult<D1PreparedStatement> {
    crate::models::mutation::guard(
        db,
        "NOT EXISTS(SELECT 1 FROM json_each(?1) required WHERE NOT \
         EXISTS(SELECT 1 FROM folders WHERE id=required.value AND user_id=?2))",
        &[
            serde_json::to_string(&required)
                .map_err(AppError::internal_json(
                    "Failed to serialize required import folders",
                ))?
                .into(),
            user_id.into(),
        ],
    )
}

pub(crate) fn collect_import_writes(
    db: &D1Database,
    user_id: &str,
    now: &str,
    folders: Vec<Value>,
    ciphers: Vec<Value>,
    maximum_rows: usize,
) -> AppResult<Vec<D1PreparedStatement>> {
    let shared = [user_id.into(), now.into()];
    let mut writes = Vec::new();
    collect_writes(
        db,
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
        db,
        ciphers,
        maximum_rows,
        "INSERT INTO \
         ciphers(id,user_id,organization_id,cipher_type,data,is_favorite,\
         folder_id,archived_at,created_at,updated_at) SELECT \
         json_extract(value,'$[0]'),?2,NULL,json_extract(value,'$[1]'),\
         json_extract(value,'$[2]'),json_extract(value,'$[3]'),\
         json_extract(value,'$[4]'),json_extract(value,'$[5]'),?3,?3 FROM \
         json_each(?1)",
        "INSERT INTO \
         ciphers(id,user_id,organization_id,cipher_type,data,is_favorite,\
         folder_id,archived_at,created_at,updated_at) \
         VALUES(?1,?7,NULL,?2,?3,?4,?5,?6,?8,?8)",
        &shared,
        &mut writes,
    )?;
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn import_json_chunks_preserve_escaped_rows_and_the_byte_boundary() {
        let first = json!(["encrypted\"🙂"]);
        let first_bytes = serde_json::to_string(&first)
            .expect("encoded fixture")
            .len();
        // The chunk budget reserves one byte after each row, including the
        // last.
        let remaining = JSON_BATCH_BYTES - first_bytes - r#"[""]"#.len() - 4;
        for (extra, expected_chunks) in [(0, 1), (1, 2)] {
            let rows = vec![first.clone(), json!(["x".repeat(remaining + extra)])];
            let chunks = import_chunks(rows.clone(), 200).expect("valid import rows");
            assert_eq!(chunks.len(), expected_chunks);
            let mut result = Vec::new();
            for chunk in chunks {
                let ImportChunk::Json(encoded) = chunk else {
                    panic!("both individual rows fit in JSON binds");
                };
                result.extend(
                    serde_json::from_str::<Vec<Value>>(&encoded).expect("valid JSON chunk"),
                );
            }
            assert_eq!(result, rows);
        }
    }
}
