use serde::Deserialize;
use uuid::Uuid;
use worker::{
    D1Database,
    query,
};

use crate::{
    errors::AppResult,
    infra::db,
};

#[derive(Debug, Deserialize)]
pub struct PushDevice {
    pub user_id:     String,
    pub identifier:  String,
    #[serde(rename = "type")]
    pub device_type: i32,
    pub push_token:  Option<String>,
    pub push_uuid:   Option<String>,
}

pub struct PushDB;

impl PushDB {
    pub async fn find_for_user(
        db: &D1Database,
        user_id: &str,
        identifier: &str,
    ) -> AppResult<Option<PushDevice>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT user_id,identifier,type,push_token,push_uuid FROM \
                     devices WHERE user_id=?1 AND identifier=?2",
                    user_id,
                    identifier
                )?
                .first(None)
                .await
            },
            "Failed to fetch push device",
        )
        .await
    }

    pub async fn list_for_user(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<Vec<PushDevice>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT user_id,identifier,type,push_token,push_uuid FROM \
                     devices WHERE user_id=?1 AND push_uuid IS NOT NULL",
                    user_id
                )?
                .all()
                .await?
                .results()
            },
            "Failed to list push devices",
        )
        .await
    }

    /// The relay ID is stable across a client's session nonce rotations.
    pub async fn ensure_uuid(
        db: &D1Database,
        user_id: &str,
        identifier: &str,
    ) -> AppResult<Option<String>> {
        let id = Uuid::new_v4().to_string();
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE devices SET push_uuid=COALESCE(push_uuid,?1) \
                     WHERE user_id=?2 AND identifier=?3 RETURNING push_uuid",
                    id,
                    user_id,
                    identifier
                )?
                .first(Some("push_uuid"))
                .await
            },
            "Failed to assign push device ID",
        )
        .await
    }
}
