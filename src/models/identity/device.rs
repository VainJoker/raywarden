use serde::{Deserialize, Serialize};
use worker::{D1Database, D1PreparedStatement, query};

use super::{
    account_keys::AccountSnapshot,
    authorization::VerifiedAccountAction,
    email,
    two_factor::{LoginMfaPolicy, TwoFactorRow},
    user::{StoredPassword, UserRow},
};
use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
    models::mutation,
    utils::constant_time_eq,
};

fn current_login_account_sql(stamp: usize) -> String {
    let hash = stamp + 1;
    let salt = stamp + 2;
    let iterations = stamp + 3;
    let snapshot = AccountSnapshot::matches_sql(stamp + 4);
    format!(
        "EXISTS(SELECT 1 FROM users WHERE id=?1 AND security_stamp=?{stamp} \
         AND master_password_hash=?{hash} AND password_salt IS ?{salt} AND \
         password_iterations=?{iterations} AND ({snapshot}))"
    )
}

/// Borrowed values to compare against the live session in a database write.
/// This snapshot does not replace the statement's authorization check.
pub struct SessionSnapshot<'a> {
    pub user_id: &'a str,
    pub security_stamp: &'a str,
    pub device_id: &'a str,
    pub session_token: &'a str,
}

pub(crate) struct NewDeviceSession<'a> {
    pub(crate) device_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) device_type: i32,
    pub(crate) nonce: &'a str,
}

impl NewDeviceSession<'_> {
    pub(super) fn upsert_statement(
        &self,
        db: &D1Database,
        user_id: &str,
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
            self.device_id,
            self.name,
            self.device_type,
            self.nonce,
            now
        )
    }
}

/// A login session belongs to a user and a client-generated device identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRow {
    pub device_id: String,
    pub user_id: String,
    pub name: String,
    pub device_type: i32,
    pub session_token: String,
    pub push_token: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl SessionSnapshot<'_> {
    pub(crate) async fn revision(&self, db: &D1Database) -> AppResult<String> {
        #[derive(Deserialize)]
        struct CurrentSession {
            session_token: String,
            security_stamp: String,
            updated_at: String,
        }

        let current: Option<CurrentSession> = db::query_first(
            query!(
                db,
                "SELECT d.session_token, u.security_stamp, u.updated_at FROM devices d \
                 JOIN users u ON u.id=d.user_id WHERE d.user_id=?1 AND d.device_id=?2",
                self.user_id,
                self.device_id
            ),
            None,
            "Failed to validate session",
        )
        .await?;
        current
            .filter(|session| {
                constant_time_eq(
                    session.session_token.as_bytes(),
                    self.session_token.as_bytes(),
                ) && constant_time_eq(
                    session.security_stamp.as_bytes(),
                    self.security_stamp.as_bytes(),
                )
            })
            .map(|session| session.updated_at)
            .ok_or_else(|| AppError::invalid_credentials("Session expired. Please log in again."))
    }
}

impl DeviceRow {
    pub async fn find_for_user(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
    ) -> AppResult<Option<Self>> {
        db::query_first(
            query!(
                db,
                "SELECT * FROM devices WHERE user_id = ?1 AND device_id = \
                 ?2",
                user_id,
                device_id
            ),
            None,
            "Failed to fetch device",
        )
        .await
    }

    pub async fn list_for_user(db: &D1Database, user_id: &str) -> AppResult<Vec<Self>> {
        db::query_results(
            query!(
                db,
                "SELECT * FROM devices WHERE user_id = ?1 ORDER BY updated_at DESC",
                user_id
            ),
            "Failed to list devices",
        )
        .await
    }

    pub(crate) async fn persist_session_if_current(
        db: &D1Database,
        user: &UserRow,
        session: &NewDeviceSession<'_>,
        mfa: &LoginMfaPolicy,
        proofs: Vec<D1PreparedStatement>,
        replacement: Option<&StoredPassword>,
    ) -> AppResult<()> {
        let mfa_matches = LoginMfaPolicy::matches_sql(2);
        let abort = DbSentinel::LoginMfaConflict.sql_abort_expr();
        let policy = serde_json::to_string(mfa).map_err(AppError::internal_json(
            "Failed to serialize login MFA policy",
        ))?;
        let mut writes = vec![
            Self::guard_current_login_account(db, user)?,
            query!(
                db,
                format!("SELECT CASE WHEN {mfa_matches} THEN 1 ELSE {abort} END"),
                user.id,
                policy
            )?,
        ];
        writes.extend(proofs);
        if let Some(password) = replacement {
            writes.extend(Self::migrate_login_password(db, user, password)?);
        }
        writes.push(session.upsert_statement(db, &user.id)?);
        db.batch(writes).await.map_err(|error| {
            if DatabaseError::has_marker(&error, DbSentinel::InvalidVerification) {
                email::invalid_verification()
            } else {
                DatabaseError::login_session(&error)
            }
        })?;
        Ok(())
    }

    pub(super) fn migrate_login_password(
        db: &D1Database,
        user: &UserRow,
        replacement: &StoredPassword,
    ) -> worker::Result<[D1PreparedStatement; 2]> {
        Ok([
            UserRow::migrate_password_statement(db, user, replacement)?,
            email::require_changed_row(db, DbSentinel::LoginPasswordConflict)?,
        ])
    }

    pub(super) fn guard_current_login_account(
        db: &D1Database,
        user: &UserRow,
    ) -> AppResult<D1PreparedStatement> {
        mutation::guard(db, &current_login_account_sql(2), &db::d1_params![
            user.id,
            user.security_stamp,
            user.master_password_hash,
            user.password_salt,
            user.password_iterations,
            AccountSnapshot::json_from_user(user)?,
        ])
    }

    pub async fn set_push_token(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
        token: Option<&str>,
    ) -> AppResult<()> {
        let now = crate::utils::time::now_rfc3339();
        db::query_run(
            query!(
                db,
                "UPDATE devices SET push_token = ?1, updated_at = ?2 \
                 WHERE user_id = ?3 AND device_id = ?4",
                token,
                now,
                user_id,
                device_id
            ),
            "Failed to update device token",
        )
        .await?;
        Ok(())
    }

    pub async fn delete_for_user(db: &D1Database, user_id: &str, device_id: &str) -> AppResult<()> {
        db::run_batch(
            db,
            vec![
                query!(
                    db,
                    "DELETE FROM devices WHERE user_id = ?1 AND device_id = ?2",
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
                TwoFactorRow::delete_remembered(db, user_id)?,
            ],
            "Failed to revoke device",
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn revoke_all_with_stamp(
        db: &D1Database,
        authorization: &VerifiedAccountAction<'_>,
        stamp: &str,
    ) -> AppResult<()> {
        let user_id = authorization.session.user_id;
        let now = crate::utils::time::now_rfc3339();
        let revision_sql = crate::models::mutation::next_user_revision_sql(2);
        let writes = vec![
            query!(
                db,
                format!("UPDATE users SET security_stamp=?1,updated_at={revision_sql} WHERE id=?3"),
                stamp,
                now,
                user_id
            )?,
            query!(db, "DELETE FROM devices WHERE user_id = ?1", user_id)?,
            query!(db, "DELETE FROM auth_requests WHERE user_id = ?1", user_id)?,
            TwoFactorRow::delete_remembered(db, user_id)?,
        ];
        authorization
            .commit(db, writes, "Failed to revoke all sessions")
            .await?;
        Ok(())
    }
}
