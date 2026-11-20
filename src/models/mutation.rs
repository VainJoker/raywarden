//! Atomic D1 assertions and writes with a monotonic vault revision.
use wasm_bindgen::JsValue;
use worker::{
    D1Database,
    D1PreparedStatement,
};

use crate::{
    errors::{
        AppError,
        AppResult,
        DatabaseError,
    },
    infra::db,
    models::{
        identity::{
            account_keys::AccountSnapshot,
            device::SessionSnapshot,
        },
        vault::cipher::CipherRow,
    },
};

pub const CONFLICT_SENTINEL: &str = "RAY_VAULT_WRITE_CONFLICT";
const SESSION_SENTINEL: &str = "RAY_VAULT_WRITE_SESSION";
pub(crate) const ATTACHMENT_QUOTA_SENTINEL: &str =
    "RAY_ATTACHMENT_QUOTA_EXCEEDED";
pub(crate) const NEXT_USER_REVISION_SQL: &str =
    "CASE WHEN julianday(updated_at) >= julianday(?1) THEN \
     strftime('%Y-%m-%dT%H:%M:%fZ', julianday(updated_at) + 1.0 / 86400000) \
     ELSE ?1 END";

/// Use the same monotonic cursor expression with an existing bind position.
pub(crate) fn next_user_revision_sql(parameter: usize) -> String {
    NEXT_USER_REVISION_SQL.replace("?1", &format!("?{parameter}"))
}

pub fn guard(
    db: &D1Database,
    predicate: &str,
    values: &[JsValue],
) -> AppResult<D1PreparedStatement> {
    Ok(db
        .prepare(format!(
            "SELECT CASE WHEN ({predicate}) THEN 1 ELSE json_extract('[]', \
             '{CONFLICT_SENTINEL}') END"
        ))
        .bind(values)?)
}

pub(crate) fn cipher_snapshot_guard(
    db: &D1Database,
    row: &CipherRow,
) -> AppResult<D1PreparedStatement> {
    fn optional(value: Option<&str>) -> JsValue {
        value.map_or(JsValue::NULL, JsValue::from_str)
    }
    guard(
        db,
        "EXISTS(SELECT 1 FROM ciphers WHERE id=?1 AND user_id=?2 AND \
         organization_id IS ?3 AND cipher_type IS ?4 AND data IS ?5 AND \
         is_favorite IS ?6 AND folder_id IS ?7 AND deleted_at IS ?8 AND \
         archived_at IS ?9 AND created_at IS ?10 AND updated_at IS ?11)",
        &[
            row.id.clone().into(),
            row.user_id.clone().into(),
            optional(row.organization_id.as_deref()),
            row.cipher_type.into(),
            row.data.clone().into(),
            row.is_favorite.into(),
            optional(row.folder_id.as_deref()),
            optional(row.deleted_at.as_deref()),
            optional(row.archived_at.as_deref()),
            row.created_at.clone().into(),
            row.updated_at.clone().into(),
        ],
    )
}

pub(crate) fn folder_guard(
    db: &D1Database,
    user: &str,
    folder: Option<&str>,
) -> AppResult<D1PreparedStatement> {
    guard(
        db,
        "?1 IS NULL OR EXISTS(SELECT 1 FROM folders WHERE id=?1 AND \
         user_id=?2)",
        &[folder.map_or(JsValue::NULL, JsValue::from_str), user.into()],
    )
}
pub async fn account_snapshot_guard(
    db: &D1Database,
    user_id: &str,
) -> AppResult<(AccountSnapshot, D1PreparedStatement)> {
    let snapshot = AccountSnapshot::load(db, user_id).await?;
    let assertion = guard(
        db,
        &format!(
            "EXISTS(SELECT 1 FROM users WHERE id = ?1 AND ({}))",
            AccountSnapshot::matches_sql(2)
        ),
        &[user_id.into(), snapshot.to_json()?.into()],
    )?;
    Ok((snapshot, assertion))
}

pub async fn commit_session(
    db: &D1Database,
    snapshot: &SessionSnapshot<'_>,
    guards: Vec<D1PreparedStatement>,
    writes: Vec<D1PreparedStatement>,
) -> AppResult<String> {
    let session = db
        .prepare(format!(
            "SELECT CASE WHEN EXISTS(
        SELECT 1 FROM users u JOIN devices d ON d.user_id=u.id
        WHERE u.id=?1 AND u.security_stamp IS ?2 AND d.device_id=?3 AND \
             d.session_token=?4
    ) THEN 1 ELSE json_extract('[]', '{SESSION_SENTINEL}') END"
        ))
        .bind(&[
            snapshot.user_id.into(),
            snapshot.security_stamp.into(),
            snapshot.device_id.into(),
            snapshot.session_token.into(),
        ])?;
    let mut guards = guards;
    guards.insert(0, session);
    commit(db, snapshot.user_id, guards, writes).await
}

/// Only for an already authenticated, resource-bound file capability. Such a
/// capability intentionally remains independent of a bearer login session.
/// Callers include the account, cipher and pending-row snapshot assertions.
pub async fn commit(
    db: &D1Database,
    user_id: &str,
    guards: Vec<D1PreparedStatement>,
    writes: Vec<D1PreparedStatement>,
) -> AppResult<String> {
    let mut statements = Vec::with_capacity(guards.len() + writes.len() + 1);
    statements.extend(guards);
    statements.extend(writes);
    statements.push(
        db.prepare(format!(
            "UPDATE users SET updated_at = {NEXT_USER_REVISION_SQL} WHERE id \
             = ?2 RETURNING updated_at"
        ))
        .bind(&[crate::utils::time::now_rfc3339().into(), user_id.into()])?,
    );
    let results = db.batch(statements).await.map_err(map_database_error)?;
    results
        .last()
        .ok_or(AppError::Internal)?
        .results::<serde_json::Value>()?
        .first()
        .and_then(|row| row.get("updated_at"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(AppError::Internal)
}

/// Count only the rows directly affected by the last write.
pub(super) async fn batch_count_last_write(
    db: &D1Database,
    mut writes: Vec<D1PreparedStatement>,
    context: &str,
) -> AppResult<u32> {
    #[derive(serde::Deserialize)]
    struct CountRow {
        count: u32,
    }

    writes.push(db.prepare("SELECT changes() AS count"));
    let results = db::run_query(db.batch(writes), context).await?;
    let count = results.last().ok_or(AppError::Internal)?;
    count
        .results::<CountRow>()?
        .first()
        .map(|row| row.count)
        .ok_or(AppError::Internal)
}

pub fn map_database_error(error: worker::Error) -> AppError {
    DatabaseError::vault_write(
        error,
        SESSION_SENTINEL,
        CONFLICT_SENTINEL,
        ATTACHMENT_QUOTA_SENTINEL,
    )
}
