//! Atomic D1 assertions and writes with a monotonic vault revision.
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{D1Database, D1PreparedStatement};

use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
    models::{
        identity::{account_keys::AccountSnapshot, device::SessionSnapshot},
        vault::cipher::CipherRow,
    },
};

pub(crate) const NEXT_USER_REVISION_SQL: &str = "CASE WHEN julianday(updated_at) >= julianday(?1) THEN \
     strftime('%Y-%m-%dT%H:%M:%fZ', julianday(updated_at) + 1.0 / 86400000) \
     ELSE ?1 END";

#[derive(Deserialize)]
pub(super) struct RevisionRow {
    pub(super) updated_at: String,
}

/// Use the same monotonic cursor expression with an existing bind position.
pub(crate) fn next_user_revision_sql(parameter: usize) -> String {
    NEXT_USER_REVISION_SQL.replace("?1", &format!("?{parameter}"))
}

pub fn guard(
    db: &D1Database,
    predicate: &str,
    values: &[JsValue],
) -> AppResult<D1PreparedStatement> {
    let abort = DbSentinel::VaultWriteConflict.sql_abort_expr();
    Ok(db
        .prepare(format!(
            "SELECT CASE WHEN ({predicate}) THEN 1 ELSE {abort} END"
        ))
        .bind(values)?)
}

pub(crate) fn cipher_snapshot_guard(
    db: &D1Database,
    row: &CipherRow,
) -> AppResult<D1PreparedStatement> {
    guard(
        db,
        "EXISTS(SELECT 1 FROM ciphers WHERE id=?1 AND user_id=?2 AND \
         organization_id IS ?3 AND cipher_type IS ?4 AND data IS ?5 AND \
         is_favorite IS ?6 AND folder_id IS ?7 AND deleted_at IS ?8 AND \
         archived_at IS ?9 AND created_at IS ?10 AND updated_at IS ?11)",
        &db::d1_params![
            row.id,
            row.user_id,
            row.organization_id,
            row.cipher_type,
            row.data,
            row.is_favorite,
            row.folder_id,
            row.deleted_at,
            row.archived_at,
            row.created_at,
            row.updated_at,
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
        &db::d1_params![folder, user],
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
        &db::d1_params![user_id, snapshot.to_json()?],
    )?;
    Ok((snapshot, assertion))
}

pub async fn commit_session(
    db: &D1Database,
    snapshot: &SessionSnapshot<'_>,
    guards: Vec<D1PreparedStatement>,
    writes: Vec<D1PreparedStatement>,
) -> AppResult<String> {
    let abort = DbSentinel::VaultWriteSession.sql_abort_expr();
    let session = db
        .prepare(format!(
            "SELECT CASE WHEN EXISTS(
        SELECT 1 FROM users u JOIN devices d ON d.user_id=u.id
        WHERE u.id=?1 AND u.security_stamp IS ?2 AND d.device_id=?3 AND \
             d.session_token=?4
    ) THEN 1 ELSE {abort} END"
        ))
        .bind(&db::d1_params![
            snapshot.user_id,
            snapshot.security_stamp,
            snapshot.device_id,
            snapshot.session_token,
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
        .bind(&db::d1_params![crate::utils::time::now_rfc3339(), user_id])?,
    );
    let results = db.batch(statements).await.map_err(map_database_error)?;
    results
        .last()
        .ok_or(AppError::Internal)?
        .results::<RevisionRow>()?
        .into_iter()
        .next()
        .map(|row| row.updated_at)
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
    DatabaseError::vault_write(error)
}
