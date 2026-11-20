use serde::{
    Deserialize,
    Serialize,
};
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
};

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::db,
};

/// Borrowed values to compare against the live session in a database write.
/// This snapshot does not replace the statement's authorization check.
pub struct SessionSnapshot<'a> {
    pub user_id:        &'a str,
    pub security_stamp: &'a str,
    pub device_id:      &'a str,
    pub session_token:  &'a str,
}

/// A login session belongs to a user and a client-generated device identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRow {
    pub device_id:     String,
    pub user_id:       String,
    pub name:          String,
    pub device_type:   i32,
    pub session_token: String,
    pub push_token:    Option<String>,
    pub created_at:    String,
    pub updated_at:    String,
}

#[derive(Deserialize)]
pub struct DeviceSessionRow {
    pub session_token:  String,
    pub security_stamp: String,
}

impl DeviceRow {
    pub async fn find_session(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
    ) -> AppResult<Option<DeviceSessionRow>> {
        let session: Option<DeviceSessionRow> = db::run_query(
            async {
                query!(
                    db,
                    "SELECT d.session_token, u.security_stamp FROM devices d \
                     JOIN users u ON u.id = d.user_id WHERE d.user_id = ?1 \
                     AND d.device_id = ?2",
                    user_id,
                    device_id
                )?
                .first(None)
                .await
            },
            "Failed to validate session",
        )
        .await?;
        Ok(session)
    }

    pub async fn find_for_user(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
    ) -> AppResult<Option<Self>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM devices WHERE user_id = ?1 AND device_id = \
                     ?2",
                    user_id,
                    device_id
                )?
                .first(None)
                .await
            },
            "Failed to fetch device",
        )
        .await
    }

    pub async fn list_for_user(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<Vec<Self>> {
        let rows = db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM devices WHERE user_id = ?1 ORDER BY \
                     updated_at DESC",
                    user_id
                )?
                .all()
                .await
            },
            "Failed to list devices",
        )
        .await?;
        Ok(rows.results()?)
    }

    pub async fn persist_session(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
        name: &str,
        device_type: i32,
        session_token: &str,
    ) -> AppResult<Self> {
        let device = db::run_query(
            async {
                Self::persist_session_statement(
                    db,
                    user_id,
                    device_id,
                    name,
                    device_type,
                    session_token,
                )?
                .first(None)
                .await
            },
            "Failed to start device session",
        )
        .await?;
        device.ok_or(AppError::Internal)
    }

    pub(super) fn persist_session_statement(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
        name: &str,
        device_type: i32,
        session_token: &str,
    ) -> worker::Result<D1PreparedStatement> {
        let now = crate::utils::time::now_rfc3339();
        query!(
            db,
            "INSERT INTO devices (user_id, device_id, name, device_type, \
             session_token, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, \
             ?5, ?6, ?6) ON CONFLICT(user_id, device_id) DO UPDATE SET name = \
             excluded.name, device_type = excluded.device_type, session_token \
             = excluded.session_token, updated_at = excluded.updated_at \
             RETURNING *",
            user_id,
            device_id,
            name,
            device_type,
            session_token,
            now
        )
    }

    pub async fn set_push_token(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
        token: Option<&str>,
    ) -> AppResult<()> {
        let now = crate::utils::time::now_rfc3339();
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE devices SET push_token = ?1, updated_at = ?2 \
                     WHERE user_id = ?3 AND device_id = ?4",
                    token,
                    now,
                    user_id,
                    device_id
                )?
                .run()
                .await
            },
            "Failed to update device token",
        )
        .await?;
        Ok(())
    }

    pub async fn delete_for_user(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
    ) -> AppResult<()> {
        // Remove pending approvals and remembered 2FA credentials with the
        // session.
        db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "DELETE FROM devices WHERE user_id = ?1 AND device_id \
                         = ?2",
                        user_id,
                        device_id
                    )?,
                    query!(
                        db,
                        "DELETE FROM auth_requests WHERE user_id = ?1 AND \
                         (request_device_id = ?2 OR response_device_id = ?2)",
                        user_id,
                        device_id
                    )?,
                    query!(
                        db,
                        "DELETE FROM two_factors WHERE user_id = ?1 AND \
                         provider_type = 5",
                        user_id
                    )?,
                ])
                .await
            },
            "Failed to revoke device",
        )
        .await?;
        Ok(())
    }

    pub async fn revoke_all_with_stamp(
        db: &D1Database,
        user_id: &str,
        stamp: &str,
    ) -> AppResult<()> {
        let now = crate::utils::time::now_rfc3339();
        db::run_query(
            async {
                let statements = vec![
                    query!(
                        db,
                        "UPDATE users SET security_stamp = ?1, updated_at = \
                         ?2 WHERE id = ?3",
                        stamp,
                        now,
                        user_id
                    )?,
                    query!(
                        db,
                        "DELETE FROM devices WHERE user_id = ?1",
                        user_id
                    )?,
                    query!(
                        db,
                        "DELETE FROM auth_requests WHERE user_id = ?1",
                        user_id
                    )?,
                    query!(
                        db,
                        "DELETE FROM two_factors WHERE user_id = ?1 AND \
                         provider_type = 5",
                        user_id
                    )?,
                ];
                db.batch(statements).await
            },
            "Failed to revoke all sessions",
        )
        .await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct PushDeviceRow {
    pub device_id:   String,
    pub device_type: i32,
    pub push_token:  Option<String>,
    pub push_id:     Option<String>,
}

pub struct PushStore;

impl PushStore {
    pub async fn find_for_user(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
    ) -> AppResult<Option<PushDeviceRow>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT user_id,device_id,device_type,push_token,push_id \
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

    pub async fn list_for_user(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<Vec<PushDeviceRow>> {
        db::run_query(
            async {
                Self::list_for_user_statement(db, user_id)?
                    .all()
                    .await?
                    .results()
            },
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
            "SELECT user_id,device_id,device_type,push_token,push_id FROM \
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
}
