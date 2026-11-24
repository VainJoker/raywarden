use serde::Deserialize;
use worker::{D1Database, query, wasm_bindgen::JsValue};

use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel, worker_failure},
    infra::db,
    models::identity::{
        account_keys::AccountSnapshot,
        device::{DeviceRow, NewDeviceSession, SessionSnapshot},
        user::UserRow,
    },
};

#[derive(Deserialize)]
pub struct ApiKeyRow {
    pub encrypted_key: String,
    pub key_hash: String,
    pub updated_at: String,
}

#[derive(Clone, Copy)]
pub struct ApiKeyReplacement<'a> {
    pub previous: Option<&'a ApiKeyRow>,
    pub encrypted: &'a str,
    pub hash: &'a str,
}

impl ApiKeyRow {
    pub async fn find(db: &D1Database, user: &str) -> AppResult<Option<Self>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT encrypted_key,key_hash,updated_at FROM \
                     user_api_keys WHERE user_id=?1",
                    user
                )?
                .first(None)
                .await
            },
            "Failed to fetch API key",
        )
        .await
    }
    pub async fn find_current(
        db: &D1Database,
        user: &UserRow,
        session: &SessionSnapshot<'_>,
    ) -> AppResult<Option<Self>> {
        let sql = format!(
            "SELECT encrypted_key,key_hash,updated_at FROM user_api_keys \
             WHERE user_id=?1 AND EXISTS(SELECT 1 FROM users u JOIN devices d \
             ON d.user_id=u.id WHERE u.id=?1 AND u.security_stamp=?2 AND \
             u.master_password_hash=?3 AND u.password_salt IS ?4 AND \
             u.password_iterations=?5 AND ({}) AND d.device_id=?7 AND \
             d.session_token=?8)",
            AccountSnapshot::matches_sql(6)
        );
        db::run_query(
            async {
                db.prepare(sql)
                    .bind(&account_bindings(user, session)?)?
                    .first(None)
                    .await
            },
            "Failed to fetch current API key",
        )
        .await
    }

    pub async fn replace(
        db: &D1Database,
        user: &UserRow,
        session: &SessionSnapshot<'_>,
        replacement: ApiKeyReplacement<'_>,
    ) -> AppResult<Option<Self>> {
        let ApiKeyReplacement {
            previous,
            encrypted,
            hash,
        } = replacement;
        let now = crate::utils::time::now_rfc3339();
        let marker = uuid::Uuid::new_v4().to_string();
        let revision_sql = crate::models::mutation::next_user_revision_sql(10);
        let sql = format!(
            "UPDATE users SET \
             account_write_token=?9,updated_at={revision_sql} WHERE id=?1 AND \
             security_stamp=?2 AND master_password_hash=?3 AND password_salt \
             IS ?4 AND password_iterations=?5 AND ({}) AND EXISTS(SELECT 1 \
             FROM devices WHERE user_id=?1 AND device_id=?7 AND \
             session_token=?8) AND ((?11 IS NULL AND NOT EXISTS(SELECT 1 FROM \
             user_api_keys WHERE user_id=?1)) OR EXISTS(SELECT 1 FROM \
             user_api_keys WHERE user_id=?1 AND encrypted_key=?11 AND \
             key_hash=?12 AND updated_at=?13)) RETURNING id",
            AccountSnapshot::matches_sql(6)
        );
        let mut values = Vec::from(account_bindings(user, session)?);
        values.extend(db::d1_params![
            marker,
            now,
            previous.map(|key| key.encrypted_key.as_str()),
            previous.map(|key| key.key_hash.as_str()),
            previous.map(|key| key.updated_at.as_str()),
        ]);
        let claim = db.prepare(sql).bind(&values)?;
        let results = db::run_query(
            async {
                db.batch(vec![
                    claim,
                    query!(
                        db,
                        "DELETE FROM devices WHERE user_id=?1 AND \
                         EXISTS(SELECT 1 FROM user_api_key_sessions s WHERE \
                         s.user_id=devices.user_id AND \
                         s.device_id=devices.device_id AND \
                         s.session_token=devices.session_token) AND EXISTS \
                         (SELECT 1 FROM users WHERE id=?1 AND \
                         account_write_token=?2)",
                        user.id,
                        marker
                    )?,
                    query!(
                        db,
                        "DELETE FROM user_api_key_sessions WHERE user_id=?1 \
                         AND EXISTS(SELECT 1 FROM users WHERE id=?1 AND \
                         account_write_token=?2)",
                        user.id,
                        marker
                    )?,
                    query!(
                        db,
                        "INSERT INTO \
                         user_api_keys(user_id,encrypted_key,key_hash,\
                         updated_at) SELECT ?1,?2,?3,updated_at FROM users \
                         WHERE id=?1 AND account_write_token=?4 ON \
                         CONFLICT(user_id) DO UPDATE SET \
                         encrypted_key=excluded.encrypted_key,\
                         key_hash=excluded.key_hash,updated_at=excluded.\
                         updated_at RETURNING \
                         encrypted_key,key_hash,updated_at",
                        user.id,
                        encrypted,
                        hash,
                        marker
                    )?,
                ])
                .await
            },
            "Failed to rotate API key",
        )
        .await?;
        Ok(results
            .last()
            .ok_or(AppError::Internal)?
            .results::<Self>()?
            .into_iter()
            .next())
    }
    /// Attach the nonce to the authenticated key in the same transaction as the
    /// device upsert. A failed bind rolls back the nonce rotation.
    pub(crate) async fn start_session(
        db: &D1Database,
        user: &UserRow,
        session: &NewDeviceSession<'_>,
        key_hash: &str,
    ) -> AppResult<()> {
        let abort = DbSentinel::ApiKeySessionConflict.sql_abort_expr();
        db.batch(vec![
            DeviceRow::guard_current_login_account(db, user)?,
            session.upsert_statement(db, &user.id)?,
            query!(
                db,
                "INSERT INTO \
                 user_api_key_sessions(user_id,device_id,session_token) \
                 SELECT ?1,?2,?3 WHERE changes()=1 AND EXISTS(SELECT 1 FROM \
                 user_api_keys WHERE user_id=?1 AND key_hash=?4) AND EXISTS( \
                 SELECT 1 FROM devices WHERE user_id=?1 AND device_id=?2 AND \
                 session_token=?3) ON CONFLICT(user_id,device_id) DO UPDATE \
                 SET session_token=excluded.session_token",
                user.id,
                session.device_id,
                session.nonce,
                key_hash
            )?,
            db.prepare(format!(
                "SELECT CASE WHEN changes()=1 THEN 1 ELSE {abort} END"
            )),
        ])
        .await
        .map_err(|error| DatabaseError::api_key_session(&error))?;
        Ok(())
    }
}

fn account_bindings(user: &UserRow, session: &SessionSnapshot<'_>) -> worker::Result<[JsValue; 8]> {
    if user.id != session.user_id {
        return Err(worker_failure("Account does not match session"));
    }
    Ok(db::d1_params![
        user.id,
        session.security_stamp,
        user.master_password_hash,
        user.password_salt,
        user.password_iterations,
        AccountSnapshot::json_from_user(user).map_err(worker::Error::from)?,
        session.device_id,
        session.session_token,
    ])
}
