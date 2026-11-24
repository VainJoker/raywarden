//! Push relay projections and registration IDs stored on device rows.
use serde::Deserialize;
use worker::{D1Database, query};

use crate::{errors::AppResult, infra::db};

#[derive(Debug, Deserialize)]
pub struct PushDeviceRow {
    pub device_id: String,
    pub device_type: i32,
    pub push_token: Option<String>,
    pub push_id: Option<String>,
}

pub async fn find_for_user(
    db: &D1Database,
    user_id: &str,
    device_id: &str,
) -> AppResult<Option<PushDeviceRow>> {
    db::run_query(
        async {
            query!(
                db,
                "SELECT device_id,device_type,push_token,push_id \
                     FROM devices WHERE user_id=?1 AND device_id=?2",
                user_id,
                device_id
            )?
            .first(None)
            .await
        },
        "Failed to fetch push device",
    )
    .await
}

pub async fn list_for_user(db: &D1Database, user_id: &str) -> AppResult<Vec<PushDeviceRow>> {
    db::run_query(
        async { list_for_user_statement(db, user_id)?.all().await?.results() },
        "Failed to list push devices",
    )
    .await
}

pub(super) fn list_for_user_statement(
    db: &D1Database,
    user_id: &str,
) -> worker::Result<worker::D1PreparedStatement> {
    query!(
        db,
        "SELECT device_id,device_type,push_token,push_id FROM \
             devices WHERE user_id=?1 AND push_id IS NOT NULL",
        user_id
    )
}

/// The relay ID is stable across a client's session nonce rotations.
pub async fn assign_uuid(
    db: &D1Database,
    user_id: &str,
    device_id: &str,
    id: &str,
) -> AppResult<Option<String>> {
    db::run_query(
        async {
            query!(
                db,
                "UPDATE devices SET push_id=COALESCE(push_id,?1) WHERE \
                     user_id=?2 AND device_id=?3 RETURNING push_id",
                id,
                user_id,
                device_id
            )?
            .first(Some("push_id"))
            .await
        },
        "Failed to assign push device ID",
    )
    .await
}
