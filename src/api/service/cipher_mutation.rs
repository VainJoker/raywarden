//! Atomic personal-vault writes: account/session and source-row assertions are
//! evaluated in the same D1 transaction as the data and monotonic sync cursor.
use wasm_bindgen::JsValue;
use worker::{
    D1Database,
    D1PreparedStatement,
};

use crate::{
    api::service::claims::Claims,
    errors::{
        AppError,
        AppResult,
    },
    models::{
        account_keys::AccountSnapshot,
        cipher::CipherDB,
    },
};

pub const CONFLICT_SENTINEL: &str = "RAY_VAULT_WRITE_CONFLICT";
const SESSION_SENTINEL: &str = "RAY_VAULT_WRITE_SESSION";
pub const REVISION_SQL: &str = "UPDATE users SET updated_at = CASE
    WHEN julianday(updated_at) >= julianday(?1)
    THEN strftime('%Y-%m-%dT%H:%M:%fZ', julianday(updated_at) + 1.0 / 86400000)
    ELSE ?1 END WHERE id = ?2 RETURNING updated_at";

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
    row: &CipherDB,
) -> AppResult<D1PreparedStatement> {
    fn optional(value: Option<&str>) -> JsValue {
        value.map_or(JsValue::NULL, JsValue::from_str)
    }
    guard(
        db,
        "EXISTS(SELECT 1 FROM ciphers WHERE id=?1 AND user_id=?2 AND \
         organization_id IS ?3 AND type IS ?4 AND data IS ?5 AND favorite IS \
         ?6 AND folder_id IS ?7 AND deleted_at IS ?8 AND archived_at IS ?9 \
         AND created_at IS ?10 AND updated_at IS ?11)",
        &[
            row.id.clone().into(),
            row.user_id.clone().into(),
            optional(row.organization_id.as_deref()),
            row.r#type.into(),
            row.data.clone().into(),
            row.favorite.into(),
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
        &[
            folder.map(JsValue::from_str).unwrap_or(JsValue::NULL),
            user.into(),
        ],
    )
}
pub async fn account_key_guard(
    db: &D1Database,
    claims: &Claims,
) -> AppResult<D1PreparedStatement> {
    claims.validate_session(db, "access").await?;
    account_snapshot_guard(db, &claims.sub).await
}

pub async fn account_snapshot_guard(
    db: &D1Database,
    user_id: &str,
) -> AppResult<D1PreparedStatement> {
    let snapshot = AccountSnapshot::load(db, user_id).await?;
    guard(
        db,
        &format!(
            "EXISTS(SELECT 1 FROM users WHERE id = ?1 AND ({}))",
            AccountSnapshot::matches_sql(2)
        ),
        &[user_id.into(), snapshot.to_json()?.into()],
    )
}

pub async fn commit(
    db: &D1Database,
    claims: &Claims,
    guards: Vec<D1PreparedStatement>,
    writes: Vec<D1PreparedStatement>,
) -> AppResult<String> {
    claims.validate_purpose("access")?;
    let session = db
        .prepare(format!(
            "SELECT CASE WHEN EXISTS(
        SELECT 1 FROM users u JOIN devices d ON d.user_id=u.id
        WHERE u.id=?1 AND u.security_stamp IS ?2 AND d.identifier=?3 AND \
             d.session_token=?4
    ) THEN 1 ELSE json_extract('[]', '{SESSION_SENTINEL}') END"
        ))
        .bind(&[
            claims.sub.clone().into(),
            claims.sstamp.clone().into(),
            claims.device().unwrap_or_default().into(),
            claims.session_token.clone().into(),
        ])?;
    let mut guards = guards;
    guards.insert(0, session);
    commit_capability(db, &claims.sub, guards, writes).await
}

/// Only for an already authenticated, resource-bound file capability. Such a
/// capability intentionally remains independent of a bearer login session.
/// Callers include the account, cipher and pending-row snapshot assertions.
pub async fn commit_capability(
    db: &D1Database,
    user_id: &str,
    guards: Vec<D1PreparedStatement>,
    writes: Vec<D1PreparedStatement>,
) -> AppResult<String> {
    let mut statements = Vec::with_capacity(guards.len() + writes.len() + 1);
    statements.extend(guards);
    statements.extend(writes);
    statements.push(
        db.prepare(REVISION_SQL).bind(&[
            crate::infra::time::now_rfc3339().into(),
            user_id.into(),
        ])?,
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

pub fn map_database_error(error: worker::Error) -> AppError {
    let message = error.to_string();
    if message.contains(SESSION_SENTINEL) {
        AppError::Unauthorized {
            message: "Session expired. Please log in again.".into(),
        }
    } else if message.contains(CONFLICT_SENTINEL) {
        AppError::bad_request(
            "The vault changed during this request. Please retry.",
        )
    } else {
        error.into()
    }
}
