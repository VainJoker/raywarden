use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};
use uuid::Uuid;
use worker::{
    D1Database,
    query,
};

use crate::{
    errors::{
        AppError,
        AuthError,
    },
    infra::{
        crypto::ct_eq,
        db,
    },
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
pub struct DeviceDB {
    pub identifier:    String,
    pub user_id:       String,
    pub name:          String,
    #[serde(rename = "type")]
    pub device_type:   i32,
    pub session_token: String,
    pub push_token:    Option<String>,
    pub created_at:    String,
    pub updated_at:    String,
}

impl DeviceDB {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.identifier, "identifier": self.identifier,
            "name": self.name, "type": self.device_type,
            "creationDate": self.created_at, "lastActiveDate": self.updated_at,
            "isTrusted": false, "encryptedPublicKey": null,
            "encryptedUserKey": null, "object": "device"
        })
    }

    pub async fn find_for_user(
        db: &D1Database,
        user_id: &str,
        identifier: &str,
    ) -> Result<Option<Self>, AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM devices WHERE user_id = ?1 AND identifier \
                     = ?2",
                    user_id,
                    identifier
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
    ) -> Result<Vec<Self>, AppError> {
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

    pub async fn start_session(
        db: &D1Database,
        user_id: &str,
        identifier: &str,
        name: &str,
        device_type: i32,
    ) -> Result<Self, AppError> {
        let now = crate::infra::time::now_rfc3339();
        // Rotating this nonce revokes tokens from earlier logins on this
        // device.
        let session_token =
            format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let device: Option<Self> = db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO devices (user_id, identifier, name, type, \
                     session_token, created_at, updated_at) VALUES (?1, ?2, \
                     ?3, ?4, ?5, ?6, ?6) ON CONFLICT(user_id, identifier) DO \
                     UPDATE SET name = excluded.name, type = excluded.type, \
                     session_token = excluded.session_token, updated_at = \
                     excluded.updated_at RETURNING *",
                    user_id,
                    identifier,
                    name,
                    device_type,
                    session_token,
                    now
                )?
                .first(None)
                .await
            },
            "Failed to start device session",
        )
        .await?;
        device.ok_or(AppError::Internal)
    }

    pub async fn validate_session(
        db: &D1Database,
        user_id: &str,
        identifier: &str,
        token: &str,
        stamp: &str,
    ) -> Result<(), AppError> {
        #[derive(Deserialize)]
        struct Session {
            session_token:  String,
            security_stamp: String,
        }
        let session: Option<Session> = db::run_query(
            async {
                query!(
                    db,
                    "SELECT d.session_token, u.security_stamp FROM devices d \
                     JOIN users u ON u.id = d.user_id WHERE d.user_id = ?1 \
                     AND d.identifier = ?2",
                    user_id,
                    identifier
                )?
                .first(None)
                .await
            },
            "Failed to validate session",
        )
        .await?;
        if session.is_some_and(|session| {
            ct_eq(&session.session_token, token) &&
                ct_eq(&session.security_stamp, stamp)
        }) {
            Ok(())
        } else {
            Err(AppError::Auth(AuthError::InvalidCredentials(
                "Session expired. Please log in again.".to_string(),
            )))
        }
    }

    pub async fn set_push_token(
        db: &D1Database,
        user_id: &str,
        identifier: &str,
        token: Option<&str>,
    ) -> Result<(), AppError> {
        let now = crate::infra::time::now_rfc3339();
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE devices SET push_token = ?1, updated_at = ?2 \
                     WHERE user_id = ?3 AND identifier = ?4",
                    token,
                    now,
                    user_id,
                    identifier
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
        identifier: &str,
    ) -> Result<(), AppError> {
        // Remove pending approvals and remembered 2FA credentials with the
        // session.
        db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "DELETE FROM devices WHERE user_id = ?1 AND \
                         identifier = ?2",
                        user_id,
                        identifier
                    )?,
                    query!(
                        db,
                        "DELETE FROM auth_requests WHERE user_id = ?1 AND \
                         (request_device_identifier = ?2 OR \
                         response_device_id = ?2)",
                        user_id,
                        identifier
                    )?,
                    query!(
                        db,
                        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype \
                         = 5",
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

    pub async fn revoke_all(
        db: &D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        let stamp = Uuid::new_v4().to_string();
        let now = crate::infra::time::now_rfc3339();
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
                        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype \
                         = 5",
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
