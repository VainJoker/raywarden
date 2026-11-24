use serde::Deserialize;
use worker::{D1Database, D1PreparedStatement, query};

use super::account_keys::AccountSnapshot;
use crate::{
    errors::{AppError, AppResult, DbSentinel},
    infra::db,
};

#[derive(Debug, Clone, Deserialize)]
pub struct AuthRequestRow {
    pub id: String,
    pub user_id: String,
    pub request_device_id: String,
    pub device_type: i32,
    pub request_ip: String,
    pub access_code: String,
    pub public_key: String,
    pub security_stamp: String,
    #[serde(default)]
    pub account_snapshot: Option<String>,
    pub encrypted_key: Option<String>,
    pub master_password_hash: Option<String>,
    pub approved: Option<i32>,
    pub created_at: String,
    pub expires_at: String,
    pub responded_at: Option<String>,
    pub authenticated_at: Option<String>,
}

impl AuthRequestRow {
    pub async fn insert(&self, db: &D1Database) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO auth_requests (id, user_id, \
                     request_device_id, device_type, request_ip, access_code, \
                     public_key, security_stamp, created_at, expires_at, \
                     account_snapshot) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, \
                     ?8, ?9, ?10, ?11)",
                    self.id,
                    self.user_id,
                    self.request_device_id,
                    self.device_type,
                    self.request_ip,
                    self.access_code,
                    self.public_key,
                    self.security_stamp,
                    self.created_at,
                    self.expires_at,
                    self.account_snapshot
                )?
                .run()
                .await
            },
            "Failed to create authentication request",
        )
        .await?;
        Ok(())
    }

    pub async fn find_by_id(db: &D1Database, id: &str) -> AppResult<Option<Self>> {
        db::run_query(
            async {
                query!(db, "SELECT * FROM auth_requests WHERE id = ?1", id)?
                    .first(None)
                    .await
            },
            "Failed to fetch authentication request",
        )
        .await
    }

    pub async fn list_pending_for_user(db: &D1Database, user_id: &str) -> AppResult<Vec<Self>> {
        let now = crate::utils::time::now_rfc3339();
        let snapshot_predicate =
            AccountSnapshot::matches_sql_expression("u.", "a.account_snapshot");
        let rows = db::run_query(
            async {
                query!(
                    db,
                    format!(
                        "SELECT a.* FROM auth_requests a JOIN users u ON u.id \
                         = a.user_id WHERE a.user_id = ?1 AND a.approved IS \
                         NULL AND a.authenticated_at IS NULL AND \
                         julianday(a.expires_at) > julianday(?2) AND \
                         a.security_stamp = u.security_stamp AND \
                         {snapshot_predicate} ORDER BY a.created_at DESC"
                    ),
                    user_id,
                    now
                )?
                .all()
                .await
            },
            "Failed to list authentication requests",
        )
        .await?;
        Ok(rows.results()?)
    }

    pub async fn respond(
        &self,
        db: &D1Database,
        session: &super::device::SessionSnapshot<'_>,
        approved: bool,
        key: &str,
        hash: Option<&str>,
    ) -> AppResult<Self> {
        if session.user_id != self.user_id {
            return Err(AppError::auth_request_unavailable());
        }
        let now = crate::utils::time::now_rfc3339();
        let snapshot_predicate =
            AccountSnapshot::matches_sql_expression("u.", "auth_requests.account_snapshot");
        let row: Option<Self> = db::run_query(
            async {
                query!(
                    db,
                    format!(
                        "UPDATE auth_requests SET approved = ?1, \
                         encrypted_key = ?2, master_password_hash = ?3, \
                         responded_at = ?4, response_device_id = ?5 WHERE id \
                         = ?6 AND user_id = ?7 AND approved IS NULL AND \
                         authenticated_at IS NULL AND julianday(expires_at) > \
                         julianday(?4) AND security_stamp = (SELECT \
                         security_stamp FROM users WHERE id = ?7) AND \
                         EXISTS(SELECT 1 FROM users u WHERE \
                         u.id=auth_requests.user_id AND {snapshot_predicate}) AND \
                         security_stamp=?8 AND EXISTS(SELECT 1 FROM devices \
                         WHERE user_id=?7 AND device_id=?5 AND session_token=?9) \
                         RETURNING *"
                    ),
                    i32::from(approved),
                    if approved { Some(key) } else { None },
                    if approved { hash } else { None },
                    now,
                    session.device_id,
                    self.id,
                    self.user_id,
                    session.security_stamp,
                    session.session_token
                )?
                .first(None)
                .await
            },
            "Failed to respond to authentication request",
        )
        .await?;
        row.ok_or_else(|| {
            AppError::bad_request("Authentication request expired or already answered")
        })
    }

    /// The conditional write prevents concurrent token exchanges from reusing
    /// approval.
    fn consume(&self, db: &D1Database) -> worker::Result<D1PreparedStatement> {
        let now = crate::utils::time::now_rfc3339();
        let snapshot_predicate =
            AccountSnapshot::matches_sql_expression("u.", "auth_requests.account_snapshot");
        query!(
            db,
            format!(
                "UPDATE auth_requests SET authenticated_at = ?1 WHERE \
                         id = ?2 AND approved = 1 AND authenticated_at IS \
                         NULL AND julianday(expires_at) > julianday(?1) AND \
                         security_stamp = (SELECT security_stamp FROM users \
                         WHERE id = auth_requests.user_id) AND EXISTS(SELECT \
                         1 FROM users u WHERE u.id=auth_requests.user_id AND \
                         {snapshot_predicate}) RETURNING id"
            ),
            now,
            self.id
        )
    }

    pub(crate) fn consume_statements(
        &self,
        db: &D1Database,
    ) -> worker::Result<[D1PreparedStatement; 2]> {
        Ok([
            self.consume(db)?,
            super::email::require_changed_row(db, DbSentinel::LoginApprovalConflict)?,
        ])
    }

    pub async fn purge_expired(db: &D1Database) -> AppResult<u32> {
        let now = crate::utils::time::now_rfc3339();
        let result = db::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM auth_requests WHERE julianday(expires_at) <= \
                     julianday(?1)",
                    now
                )?
                .run()
                .await
            },
            "Failed to purge expired authentication requests",
        )
        .await?;
        Ok(db::changes_count(&result)? as u32)
    }
}
