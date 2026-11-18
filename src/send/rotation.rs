//! Complete-collection Send key rewrapping in the account transaction.
use worker::{
    D1Database,
    D1PreparedStatement,
};

use super::mutation::{
    collection_guard,
    snapshot_guard,
};
use crate::{
    errors::AppError,
    send::types::{
        RotateSendData,
        SendDB,
        inaccessible,
    },
};

/// Validate the whole rotation before returning statements to the account
/// transaction. The owner must include every completed Send exactly once.
pub(crate) async fn rotation_statements(
    db: &D1Database,
    user_id: &str,
    sends: &[RotateSendData],
    now: &str,
    write_token: &str,
) -> Result<(Vec<D1PreparedStatement>, Vec<D1PreparedStatement>), AppError> {
    let existing = SendDB::all_for_user(db, user_id).await?;
    if existing.iter().any(|send| send.pending != 0) {
        return Err(AppError::bad_request(
            "Complete or cancel pending Send uploads before rotating keys",
        ));
    }
    let existing_ids: std::collections::HashSet<&str> =
        existing.iter().map(|s| s.id.as_str()).collect();
    let ids: std::collections::HashSet<&str> =
        sends.iter().map(|s| s.id.as_str()).collect();
    if sends.len() != ids.len() || ids != existing_ids {
        return Err(AppError::bad_request(
            "All existing Sends must be included exactly once in key rotation",
        ));
    }
    let mut guards = Vec::with_capacity(existing.len() + 1);
    guards.push(collection_guard(db, user_id, existing.len())?);
    for send in &existing {
        guards.push(snapshot_guard(db, send)?);
    }
    let mut statements = Vec::with_capacity(sends.len());
    for payload in sends {
        if payload.key.is_empty() {
            return Err(AppError::bad_request("Rotated Send key is required"));
        }
        let send = existing
            .iter()
            .find(|send| send.id == payload.id)
            .ok_or_else(inaccessible)?;
        statements.push(send.rotation_statement(
            db,
            &payload.key,
            now,
            write_token,
        )?);
    }
    Ok((statements, guards))
}
