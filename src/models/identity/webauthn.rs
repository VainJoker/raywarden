use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use worker::{D1Database, D1PreparedStatement, query};

use super::{
    account_keys::AccountSnapshot,
    authorization::VerifiedAccountAction,
    device::{DeviceRow, NewDeviceSession, SessionSnapshot},
    email::require_changed_row,
    two_factor::TwoFactorRow,
    user::UserRow,
};
use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebauthnCredentialRow {
    pub id: String,
    pub user_id: String,
    pub slot: i32,
    pub name: String,
    pub credential_id: String,
    pub public_key: String,
    pub sign_count: i64,
    pub credential_use: String,
    pub prf_status: i32,
    pub encrypted_public_key: Option<String>,
    pub encrypted_user_key: Option<String>,
    pub encrypted_private_key: Option<String>,
    pub last_challenge: Option<String>,
    #[serde(default)]
    pub account_snapshot: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
impl WebauthnCredentialRow {
    pub async fn list(db: &D1Database, user: &str, usage: &str) -> AppResult<Vec<Self>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM webauthn_credentials WHERE user_id=?1 AND \
                     credential_use=?2 ORDER BY slot",
                    user,
                    usage
                )?
                .all()
                .await?
                .results()
            },
            "Failed to list WebAuthn credentials",
        )
        .await
    }
    pub async fn find(db: &D1Database, id: &str) -> AppResult<Option<Self>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM webauthn_credentials WHERE credential_id=?1",
                    id
                )?
                .first(None)
                .await
            },
            "Failed to find WebAuthn credential",
        )
        .await
    }
    pub async fn find_owned(db: &D1Database, user: &str, usage: &str, id: &str) -> AppResult<Self> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM webauthn_credentials WHERE user_id=?1 AND \
                     credential_use=?2 AND (id=?3 OR CAST(slot AS TEXT)=?3 OR \
                     credential_id=?3)",
                    user,
                    usage,
                    id
                )?
                .first(None)
                .await
            },
            "Failed to find owned WebAuthn credential",
        )
        .await?
        .ok_or_else(|| AppError::not_found("WebAuthn credential"))
    }
    #[allow(
        clippy::too_many_lines,
        reason = "Keep challenge consumption and credential registration in \
                  one atomic transaction"
    )]
    pub async fn register(
        &self,
        db: &D1Database,
        challenge: &WebauthnChallengeRow,
    ) -> AppResult<()> {
        let now = crate::utils::time::now_rfc3339();
        let snapshot_predicate =
            AccountSnapshot::matches_sql_expression("u.", "c.account_snapshot");
        let result = db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        format!(
                            "INSERT INTO webauthn_credentials \
                             (id,user_id,slot,name,credential_id,public_key,\
                             sign_count,credential_use,prf_status,\
                             encrypted_public_key,encrypted_user_key,\
                             encrypted_private_key,last_challenge,created_at,\
                             updated_at,account_snapshot) SELECT \
                             ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?\
                             14,?15 WHERE EXISTS(SELECT 1 FROM \
                             webauthn_challenges c JOIN users u ON \
                             u.id=c.user_id WHERE c.id=?13 AND c.user_id=?2 \
                             AND c.security_stamp=u.security_stamp  AND \
                             {snapshot_predicate} AND c.consumed_at IS NULL \
                             AND julianday(c.expires_at) > julianday(?14) AND \
                             EXISTS(SELECT 1 FROM devices d WHERE \
                             d.user_id=u.id AND d.device_id=c.device_id AND \
                             d.session_token=c.session_token))"
                        ),
                        self.id,
                        self.user_id,
                        self.slot,
                        self.name,
                        self.credential_id,
                        self.public_key,
                        self.sign_count,
                        self.credential_use,
                        self.prf_status,
                        self.encrypted_public_key,
                        self.encrypted_user_key,
                        self.encrypted_private_key,
                        challenge.id,
                        now,
                        self.account_snapshot
                    )?,
                    query!(
                        db,
                        "UPDATE webauthn_challenges SET consumed_at=?1 WHERE \
                         id=?2 AND EXISTS(SELECT 1 FROM webauthn_credentials \
                         WHERE id=?3 AND last_challenge=?2)",
                        now,
                        challenge.id,
                        self.id
                    )?,
                    query!(
                        db,
                        "INSERT INTO \
                         two_factors(id,user_id,provider_type,is_enabled,data,\
                         last_used_step) SELECT ?1,?2,7,1,'{}',0 WHERE \
                         ?3='2fa' AND EXISTS(SELECT 1 FROM \
                         webauthn_credentials WHERE id=?4 AND \
                         last_challenge=?5) ON \
                         CONFLICT(user_id,provider_type) DO UPDATE SET \
                         is_enabled=1",
                        Uuid::new_v4().to_string(),
                        self.user_id,
                        self.credential_use,
                        self.id,
                        challenge.id
                    )?,
                    query!(
                        db,
                        format!(
                            "UPDATE users SET \
                             updated_at={NEXT_USER_REVISION_SQL},\
                             two_factor_recovery_code=CASE WHEN ?3='2fa' THEN \
                             COALESCE(two_factor_recovery_code,?4) ELSE \
                             two_factor_recovery_code END WHERE id=?2 AND \
                             EXISTS(SELECT 1 FROM webauthn_credentials WHERE \
                             id=?5 AND last_challenge=?6)",
                            NEXT_USER_REVISION_SQL =
                                crate::models::mutation::NEXT_USER_REVISION_SQL
                        ),
                        now,
                        self.user_id,
                        self.credential_use,
                        Uuid::new_v4().simple().to_string(),
                        self.id,
                        challenge.id
                    )?,
                ])
                .await
            },
            "Failed to register WebAuthn credential",
        )
        .await?;
        let inserted = result.first().ok_or(AppError::Internal)?;
        if db::changes_count(inserted)? != 1 {
            return Err(AppError::bad_request(
                "WebAuthn challenge expired or already used",
            ));
        }
        Ok(())
    }
    pub(crate) fn consume_assertion_statements(
        &self,
        db: &D1Database,
        challenge: &WebauthnChallengeRow,
        new_count: i64,
    ) -> AppResult<[D1PreparedStatement; 3]> {
        let [advance, consume] = self.assertion_statements(db, challenge, new_count)?;
        Ok([
            advance,
            consume,
            require_changed_row(db, DbSentinel::LoginPasskeyConflict)?,
        ])
    }

    pub(crate) async fn accept_login_assertion(
        &self,
        db: &D1Database,
        challenge: &WebauthnChallengeRow,
        new_count: i64,
        user: &UserRow,
        session: &NewDeviceSession<'_>,
    ) -> AppResult<()> {
        let mut writes = vec![DeviceRow::guard_current_login_account(db, user)?];
        writes.extend(self.consume_assertion_statements(db, challenge, new_count)?);
        writes.push(session.upsert_statement(db, &user.id)?);
        db.batch(writes)
            .await
            .map_err(|error| DatabaseError::login_session(&error))?;
        Ok(())
    }

    fn assertion_statements(
        &self,
        db: &D1Database,
        challenge: &WebauthnChallengeRow,
        new_count: i64,
    ) -> worker::Result<[D1PreparedStatement; 2]> {
        let now = crate::utils::time::now_rfc3339();
        let snapshot_predicate =
            AccountSnapshot::matches_sql_expression("u.", "c.account_snapshot");
        Ok([
            query!(
                db,
                format!(
                    "UPDATE webauthn_credentials SET \
                     sign_count=MAX(sign_count,?1),last_challenge=?2,\
                     updated_at=?3 WHERE id=?4 AND sign_count=?5 AND \
                     user_id=?6 AND credential_id=?7 AND public_key=?8 AND \
                     credential_use=?9 AND EXISTS(SELECT 1 FROM \
                     webauthn_challenges c WHERE c.id=?2 AND c.consumed_at IS \
                     NULL AND julianday(c.expires_at) > julianday(?3) AND \
                     (c.user_id IS NULL OR (c.user_id=?6 AND EXISTS(SELECT 1 \
                     FROM users u WHERE u.id=?6 AND \
                     u.security_stamp=c.security_stamp  AND \
                     {snapshot_predicate}))) AND (c.session_token IS NULL OR \
                     EXISTS(SELECT 1 FROM devices d WHERE d.user_id=?6 AND \
                     d.device_id=c.device_id AND \
                     d.session_token=c.session_token)))"
                ),
                new_count,
                challenge.id,
                now,
                self.id,
                self.sign_count,
                self.user_id,
                self.credential_id,
                self.public_key,
                self.credential_use,
            )?,
            query!(
                db,
                "UPDATE webauthn_challenges SET consumed_at=?1 WHERE id=?2 \
                 AND changes()=1 AND consumed_at IS NULL AND EXISTS(SELECT 1 \
                 FROM webauthn_credentials WHERE id=?3 AND last_challenge=?2)",
                now,
                challenge.id,
                self.id
            )?,
        ])
    }
    pub(crate) async fn update_keys(
        &self,
        db: &D1Database,
        session: &crate::models::identity::device::SessionSnapshot<'_>,
        proof: [D1PreparedStatement; 4],
    ) -> AppResult<()> {
        if self.user_id != session.user_id {
            return Err(AppError::conflict(
                "Passkey owner does not match the session",
            ));
        }
        let snapshot_predicate = AccountSnapshot::matches_sql_expression("u.", "?9");
        let update = query!(
            db,
            format!(
                "UPDATE webauthn_credentials SET \
                         name=?1,prf_status=?2,encrypted_public_key=?3,\
                         encrypted_user_key=?4,encrypted_private_key=?5,\
                         updated_at=?6,account_snapshot=?9 WHERE id=?7 AND \
                         user_id=?8 AND credential_use='login' AND \
                         sign_count=?13 AND last_challenge=?14 AND \
                         EXISTS(SELECT 1 FROM users u WHERE u.id=?8 AND \
                         u.security_stamp=?10 AND {snapshot_predicate}) AND \
                         EXISTS(SELECT 1 FROM devices WHERE user_id=?8 AND \
                         device_id=?11 AND session_token=?12) AND \
                         EXISTS(SELECT 1 FROM webauthn_challenges WHERE \
                         id=?14 AND user_id=?8 AND purpose='assert.login' AND \
                         security_stamp=?10 AND device_id=?11 AND \
                         session_token=?12 AND consumed_at IS NOT NULL) \
                         RETURNING id"
            ),
            self.name,
            self.prf_status,
            self.encrypted_public_key,
            self.encrypted_user_key,
            self.encrypted_private_key,
            crate::utils::time::now_rfc3339(),
            self.id,
            self.user_id,
            self.account_snapshot,
            session.security_stamp,
            session.device_id,
            session.session_token,
            self.sign_count,
            self.last_challenge
        )?;
        let mut writes = Vec::from(proof);
        writes.push(update);
        writes.push(require_changed_row(db, DbSentinel::VaultWriteConflict)?);
        db.batch(writes).await.map_err(|error| {
            match DatabaseError::find_sentinel(&error, &[
                DbSentinel::LoginPasskeyConflict,
                DbSentinel::VaultWriteConflict,
            ]) {
                Some(DbSentinel::LoginPasskeyConflict) => DatabaseError::login_session(&error),
                Some(DbSentinel::VaultWriteConflict) => {
                    AppError::conflict("Account encryption changed during PRF update")
                }
                _ => DatabaseError::query("Failed to update passkey encryption", &error),
            }
        })?;
        Ok(())
    }

    pub(crate) fn prepare_prf_assertion(
        &self,
        db: &D1Database,
        session: &SessionSnapshot<'_>,
        challenge: &WebauthnChallengeRow,
        new_count: i64,
    ) -> AppResult<[D1PreparedStatement; 4]> {
        let expected = serde_json::to_string(self).map_err(AppError::internal_error)?;
        let guard = crate::models::mutation::guard(
            db,
            "EXISTS(SELECT 1 FROM users u JOIN devices d ON u.id=d.user_id \
             WHERE u.id=?1 AND u.security_stamp=?2 AND d.device_id=?3 AND d.session_token=?4) \
             AND EXISTS(SELECT 1 FROM webauthn_credentials WHERE id=?5 AND user_id=?1 \
             AND name IS json_extract(?6,'$.name') AND sign_count IS json_extract(?6,'$.sign_count') \
             AND last_challenge IS json_extract(?6,'$.last_challenge') \
             AND prf_status IS json_extract(?6,'$.prf_status') \
             AND encrypted_public_key IS json_extract(?6,'$.encrypted_public_key') \
             AND encrypted_user_key IS json_extract(?6,'$.encrypted_user_key') \
             AND encrypted_private_key IS json_extract(?6,'$.encrypted_private_key') \
             AND account_snapshot IS json_extract(?6,'$.account_snapshot'))",
            &db::d1_params![
                session.user_id,
                session.security_stamp,
                session.device_id,
                session.session_token,
                self.id,
                expected
            ],
        )?;
        let [advance, consume, accepted] =
            self.consume_assertion_statements(db, challenge, new_count)?;
        Ok([guard, advance, consume, accepted])
    }

    pub(super) fn guard_second_factor_keys(
        db: &D1Database,
        user_id: &str,
        keys: &[Self],
    ) -> AppResult<D1PreparedStatement> {
        let snapshot = serde_json::to_string(keys).map_err(AppError::internal_error)?;
        crate::models::mutation::guard(
            db,
            "(SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?1 AND credential_use='2fa') \
             =json_array_length(?2) AND NOT EXISTS(SELECT 1 FROM json_each(?2) p WHERE NOT EXISTS(\
             SELECT 1 FROM webauthn_credentials WHERE user_id=?1 AND credential_use='2fa' \
             AND id=json_extract(p.value,'$.id') AND credential_id=json_extract(p.value,'$.credential_id') \
             AND public_key=json_extract(p.value,'$.public_key')))",
            &db::d1_params![user_id, snapshot],
        )
    }

    pub(super) fn purge_2fa_statement(
        db: &D1Database,
        user_id: &str,
    ) -> worker::Result<D1PreparedStatement> {
        query!(
            db,
            "DELETE FROM webauthn_credentials WHERE user_id=?1 AND \
             credential_use='2fa'",
            user_id
        )
    }

    /// Clear precisely the observed second-factor set without touching
    /// passkeys.
    #[allow(
        clippy::too_many_lines,
        reason = "Keep factor snapshots and all related cleanup visible in \
                  one atomic transaction"
    )]
    pub async fn clear_2fa_if_current(
        db: &D1Database,
        session: &crate::models::identity::device::SessionSnapshot<'_>,
        account: &crate::models::identity::account_keys::AccountSnapshot,
        keys: &[Self],
    ) -> AppResult<()> {
        let snapshot = serde_json::to_string(keys).map_err(AppError::internal_error)?;
        let account = account.to_json()?;
        let columns = [
            "id",
            "user_id",
            "slot",
            "name",
            "credential_id",
            "public_key",
            "sign_count",
            "credential_use",
            "prf_status",
            "encrypted_public_key",
            "encrypted_user_key",
            "encrypted_private_key",
            "last_challenge",
            "account_snapshot",
            "created_at",
            "updated_at",
        ];
        let matches = columns
            .map(|column| format!("k.{column} IS json_extract(j.value,'$.{column}')"))
            .join(" AND ");
        let revision_sql = crate::models::mutation::next_user_revision_sql(8);
        let claim = format!(
            "UPDATE users SET \
             account_write_token=?1,updated_at={revision_sql} WHERE id=?2 AND \
             security_stamp=?3 AND ({}) AND EXISTS(SELECT 1 FROM devices \
             WHERE user_id=?2 AND device_id=?4 AND session_token=?5) AND \
             json_array_length(?7)>0 AND (SELECT COUNT(*) FROM \
             webauthn_credentials WHERE user_id=?2 AND \
             credential_use='2fa')=json_array_length(?7) AND NOT EXISTS \
             (SELECT 1 FROM json_each(?7) j WHERE NOT EXISTS(SELECT 1 FROM \
             webauthn_credentials k WHERE k.user_id=?2 AND \
             k.credential_use='2fa' AND {matches})) RETURNING id",
            AccountSnapshot::matches_sql(6),
        );
        let marker = Uuid::new_v4().to_string();
        let results = db::run_query(
            async {
                db.batch(vec![
                    db.prepare(claim).bind(&db::d1_params![
                        marker,
                        session.user_id,
                        session.security_stamp,
                        session.device_id,
                        session.session_token,
                        account,
                        snapshot,
                        crate::utils::time::now_rfc3339(),
                    ])?,
                    query!(
                        db,
                        "DELETE FROM webauthn_credentials WHERE user_id=?1 \
                         AND credential_use='2fa' AND EXISTS(SELECT 1 FROM \
                         users WHERE id=?1 AND account_write_token=?2)",
                        session.user_id,
                        marker
                    )?,
                    query!(
                        db,
                        "DELETE FROM webauthn_challenges WHERE user_id=?1 AND \
                         purpose IN ('register.2fa','assert.2fa') AND EXISTS \
                         (SELECT 1 FROM users WHERE id=?1 AND \
                         account_write_token=?2)",
                        session.user_id,
                        marker
                    )?,
                    query!(
                        db,
                        "DELETE FROM two_factors WHERE user_id=?1 AND \
                         provider_type IN (5,7) AND EXISTS(SELECT 1 FROM \
                         users WHERE id=?1 AND account_write_token=?2)",
                        session.user_id,
                        marker
                    )?,
                    TwoFactorRow::clear_recovery_statement(db, session.user_id, Some(&marker))?,
                ])
                .await
            },
            "Failed to clear WebAuthn second factors",
        )
        .await?;
        if results
            .first()
            .ok_or(AppError::Internal)?
            .results::<Value>()?
            .is_empty()
        {
            return Err(AppError::conflict(
                "WebAuthn credentials or session changed; retry",
            ));
        }
        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        db: &D1Database,
        authorization: &VerifiedAccountAction<'_>,
        expected_keys: Option<&[Self]>,
    ) -> AppResult<()> {
        let user_id = authorization.session.user_id;
        let revision_sql = crate::models::mutation::next_user_revision_sql(1);
        let mut writes = Vec::new();
        if let Some(keys) = expected_keys {
            writes.push(Self::guard_second_factor_keys(db, user_id, keys)?);
        }
        writes.extend([
            query!(
                db,
                "DELETE FROM webauthn_credentials WHERE id=?1 AND user_id=?2 \
                 AND credential_use=?3 AND credential_id=?4 AND public_key=?5",
                self.id,
                user_id,
                self.credential_use,
                self.credential_id,
                self.public_key
            )?,
            require_changed_row(db, DbSentinel::VaultWriteConflict)?,
            query!(
                db,
                "DELETE FROM two_factors WHERE user_id=?1 AND provider_type=7 AND NOT EXISTS(\
                 SELECT 1 FROM webauthn_credentials WHERE user_id=?1 AND credential_use='2fa')",
                user_id
            )?,
            query!(
                db,
                format!("UPDATE users SET updated_at={revision_sql} WHERE id=?2"),
                crate::utils::time::now_rfc3339(),
                user_id
            )?,
        ]);
        if self.credential_use == "2fa" {
            writes.push(TwoFactorRow::clear_recovery_statement(db, user_id, None)?);
        }
        authorization
            .commit(db, writes, "Failed to delete WebAuthn credential")
            .await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct WebauthnChallengeRow {
    pub id: String,
    pub challenge: String,
    pub purpose: String,
    pub user_id: Option<String>,
    pub security_stamp: Option<String>,
    pub device_id: Option<String>,
    pub session_token: Option<String>,
    #[serde(default)]
    pub account_snapshot: Option<String>,
    pub rp_id: String,
    pub origin: String,
    pub expires_at: String,
}
impl WebauthnChallengeRow {
    pub async fn insert(&self, db: &D1Database) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO webauthn_challenges \
                     (id,challenge,purpose,user_id,security_stamp,device_id,\
                     session_token,rp_id,origin,expires_at,account_snapshot) \
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    self.id,
                    self.challenge,
                    self.purpose,
                    self.user_id,
                    self.security_stamp,
                    self.device_id,
                    self.session_token,
                    self.rp_id,
                    self.origin,
                    self.expires_at,
                    self.account_snapshot
                )?
                .run()
                .await
            },
            "Failed to store WebAuthn challenge",
        )
        .await?;
        Ok(())
    }
    pub async fn find_challenge(
        db: &D1Database,
        challenge: &str,
        purpose: &str,
    ) -> AppResult<Self> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM webauthn_challenges WHERE challenge=?1 AND \
                     purpose=?2 AND consumed_at IS NULL AND \
                     julianday(expires_at) > julianday(?3)",
                    challenge,
                    purpose,
                    crate::utils::time::now_rfc3339()
                )?
                .first(None)
                .await
            },
            "Failed to fetch WebAuthn challenge",
        )
        .await?
        .ok_or_else(|| AppError::bad_request("WebAuthn challenge missing or expired"))
    }
    pub async fn purge(db: &D1Database) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM webauthn_challenges WHERE \
                     julianday(expires_at) <= julianday(?1)",
                    crate::utils::time::now_rfc3339()
                )?
                .run()
                .await
            },
            "Failed to purge WebAuthn challenges",
        )
        .await?;
        Ok(())
    }
}
