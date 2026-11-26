use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1PreparedStatement, query};

use super::{
    authorization::{VerifiedAccountAction, session_guard_with_sentinel},
    email::{self, VerifiedCode},
    webauthn::WebauthnCredentialRow,
};
use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
    models::identity::{
        account_keys::AccountSnapshot,
        device::{DeviceRow, NewDeviceSession, SessionSnapshot},
        user::{StoredPassword, UserRow},
    },
    utils::serde::bool_from_int,
};

pub(crate) const REMEMBER_PROVIDER: i32 = 5;
const FIRST_INTERNAL_PROVIDER: i32 = 1000;

/// The enabled factor configuration used to authorize a password login.
/// Replay counters are checked by the proof that updates them.
#[derive(Default, Serialize)]
pub(crate) struct LoginMfaPolicy {
    providers: Vec<(String, i32, String)>,
    pub(crate) remembered: Option<(String, String)>,
    pub(crate) webauthn_id: Option<String>,
}

impl LoginMfaPolicy {
    pub(crate) fn from_providers(providers: &[&TwoFactorRow]) -> Self {
        Self {
            providers: providers
                .iter()
                .map(|factor| (factor.id.clone(), factor.provider_type, factor.data.clone()))
                .collect(),
            ..Self::default()
        }
    }

    pub(super) fn matches_sql(parameter: usize) -> String {
        let enabled = format!(
            "user_id=?1 AND is_enabled=1 AND \
             provider_type<>{REMEMBER_PROVIDER} AND \
             provider_type<{FIRST_INTERNAL_PROVIDER}"
        );
        format!(
            "((SELECT COUNT(*) FROM two_factors WHERE \
             {enabled})=json_array_length(?{parameter},'$.providers') AND NOT \
             EXISTS(SELECT 1 FROM json_each(?{parameter},'$.providers') p \
             WHERE NOT EXISTS(SELECT 1 FROM two_factors WHERE {enabled} AND \
             id=json_extract(p.value,'$[0]') AND \
             provider_type=json_extract(p.value,'$[1]') AND \
             data=json_extract(p.value,'$[2]'))) AND \
             (json_extract(?{parameter},'$.remembered') IS NULL OR \
             EXISTS(SELECT 1 FROM two_factors WHERE user_id=?1 AND \
             is_enabled=1 AND provider_type={REMEMBER_PROVIDER} AND \
             id=json_extract(?{parameter},'$.remembered[0]') AND \
             data=json_extract(?{parameter},'$.remembered[1]'))) AND \
             (json_extract(?{parameter},'$.webauthn_id') IS NULL OR \
             EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_id=?1 AND \
             credential_use='2fa' AND \
             id=json_extract(?{parameter},'$.webauthn_id'))))"
        )
    }
}

/// `TwoFactorRow` database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorRow {
    pub id: String,
    pub user_id: String,
    pub provider_type: i32,
    #[serde(with = "bool_from_int")]
    pub is_enabled: bool,
    pub data: String,
    pub last_used_step: i64,
}

impl TwoFactorRow {
    /// List all 2FA records for a user (includes Remember tokens, excludes
    /// `provider_type >= 1000`).
    pub async fn list_for_user(db: &worker::D1Database, user_id: &str) -> AppResult<Vec<Self>> {
        let results = db
            .prepare(format!(
                "SELECT * FROM two_factors WHERE user_id = ?1 AND provider_type < \
                 {FIRST_INTERNAL_PROVIDER}"
            ))
            .bind(&db::d1_params![user_id])?
            .all()
            .await
            .map_err(|err| DatabaseError::query("Failed to query two-factor providers", &err))?;
        db::decode_results(&results)
    }

    pub async fn find_provider(
        db: &worker::D1Database,
        user_id: &str,
        provider_type: i32,
    ) -> AppResult<Option<Self>> {
        db.prepare(
            "SELECT * FROM two_factors WHERE user_id = ?1 AND provider_type = \
             ?2",
        )
        .bind(&db::d1_params![user_id, provider_type])?
        .first(None)
        .await
        .map_err(|err| DatabaseError::query("Failed to fetch two-factor provider", &err))?
        .map(|value| db::decode_row(value, "Failed to read two-factor provider"))
        .transpose()
    }

    pub(crate) async fn disable_provider(
        db: &worker::D1Database,
        authorization: &VerifiedAccountAction<'_>,
        provider_type: i32,
        previous: Option<&Self>,
        webauthn: Option<&[WebauthnCredentialRow]>,
    ) -> AppResult<()> {
        let user_id = authorization.session.user_id;
        let mut writes = vec![
            Self::snapshot_guard(
                db,
                user_id,
                provider_type,
                previous,
                DbSentinel::VaultWriteConflict,
            )?,
            email::invalidate_user_statement(db, user_id)?,
        ];
        if let Some(keys) = webauthn {
            writes.push(WebauthnCredentialRow::guard_second_factor_keys(
                db, user_id, keys,
            )?);
            writes.push(WebauthnCredentialRow::purge_2fa_statement(db, user_id)?);
        }
        writes.push(query!(
            db,
            "DELETE FROM two_factors WHERE user_id=?1 AND provider_type IN (?2,?3)",
            user_id,
            provider_type,
            REMEMBER_PROVIDER,
        )?);
        writes.push(Self::clear_recovery_statement(db, user_id)?);
        authorization
            .commit(db, writes, "Failed to delete two_factors entries")
            .await?;
        Ok(())
    }

    pub(super) fn snapshot_guard(
        db: &worker::D1Database,
        user_id: &str,
        provider_type: i32,
        previous: Option<&Self>,
        sentinel: DbSentinel,
    ) -> AppResult<D1PreparedStatement> {
        let snapshot =
            previous
                .map(serde_json::to_string)
                .transpose()
                .map_err(AppError::internal_json(
                    "Failed to serialize two-factor provider snapshot",
                ))?;
        crate::models::mutation::guard_with_sentinel(
            db,
            "CASE WHEN ?3 IS NULL THEN NOT EXISTS(SELECT 1 FROM two_factors \
             WHERE user_id=?1 AND provider_type=?2) ELSE EXISTS(SELECT 1 FROM \
             two_factors WHERE user_id=?1 AND provider_type=?2 AND \
             id=json_extract(?3,'$.id') AND data=json_extract(?3,'$.data') AND \
             is_enabled=json_extract(?3,'$.is_enabled') AND \
             last_used_step=json_extract(?3,'$.last_used_step')) END",
            &db::d1_params![user_id, provider_type, snapshot],
            sentinel,
        )
    }

    /// Keep legacy enabled providers in the login policy. Remember and internal
    /// records do not require a challenge or preserve a recovery code.
    pub(crate) const fn requires_login_challenge(&self) -> bool {
        self.is_enabled
            && self.provider_type != REMEMBER_PROVIDER
            && self.provider_type < FIRST_INTERNAL_PROVIDER
    }

    /// Evaluate the same provider policy as login inside the factor write.
    pub(super) fn clear_recovery_statement(
        db: &worker::D1Database,
        user_id: &str,
    ) -> worker::Result<D1PreparedStatement> {
        query!(
            db,
            format!(
                "UPDATE users SET two_factor_recovery_code=NULL WHERE id=?1 \
                 AND NOT EXISTS \
                 (SELECT 1 FROM two_factors WHERE user_id=?1 AND is_enabled=1 \
                 AND provider_type<>{REMEMBER_PROVIDER} AND \
                 provider_type<{FIRST_INTERNAL_PROVIDER})"
            ),
            user_id,
        )
    }

    fn update_last_used_step(
        db: &worker::D1Database,
        id: &str,
        last_used_step: i64,
    ) -> worker::Result<D1PreparedStatement> {
        query!(
            db,
            "UPDATE two_factors SET last_used_step = ?1 WHERE id = ?2 AND \
             is_enabled = 1 AND last_used_step < ?1",
            last_used_step,
            id
        )
    }

    pub(crate) fn consume_totp(
        db: &worker::D1Database,
        id: &str,
        step: i64,
    ) -> worker::Result<[D1PreparedStatement; 2]> {
        Ok([
            Self::update_last_used_step(db, id, step)?,
            email::require_changed_row(db, DbSentinel::TotpWriteConflict)?,
        ])
    }

    pub(crate) async fn replace_authenticator(
        db: &worker::D1Database,
        session: &SessionSnapshot<'_>,
        previous: Option<&Self>,
        value: &Self,
        recovery_code: &str,
        authorization: Option<&VerifiedCode>,
    ) -> AppResult<()> {
        let sentinel = DbSentinel::TotpWriteConflict;
        let statements = vec![
            session_guard_with_sentinel(db, session, sentinel)?,
            Self::snapshot_guard(db, session.user_id, 0, previous, sentinel)?,
            query!(
                db,
                "INSERT INTO two_factors(id,user_id,provider_type,is_enabled,data,last_used_step) \
                 VALUES (?1,?2,0,?3,?4,?5) ON CONFLICT(user_id,provider_type) DO UPDATE SET \
                 id=excluded.id,is_enabled=excluded.is_enabled,data=excluded.data, \
                 last_used_step=excluded.last_used_step",
                value.id,
                session.user_id,
                i32::from(value.is_enabled),
                value.data,
                value.last_used_step
            )?,
            email::require_changed_row(db, sentinel)?,
            Self::delete_remembered(db, session.user_id)?,
            query!(
                db,
                "UPDATE users SET two_factor_recovery_code=?2 WHERE id=?1 AND \
                 two_factor_recovery_code IS NULL",
                session.user_id,
                recovery_code
            )?,
        ];
        VerifiedCode::commit(db, authorization, statements, DatabaseError::totp_write).await
    }

    pub(super) fn delete_remembered(
        db: &worker::D1Database,
        user_id: &str,
    ) -> worker::Result<D1PreparedStatement> {
        query!(
            db,
            "DELETE FROM two_factors WHERE user_id=?1 AND provider_type=5",
            user_id
        )
    }

    pub(crate) async fn delete_authenticator_snapshot(
        db: &worker::D1Database,
        authorization: &VerifiedAccountAction<'_>,
        previous: &Self,
        clear_verification_codes: bool,
    ) -> AppResult<()> {
        let user_id = authorization.session.user_id;
        let sentinel = DbSentinel::TotpWriteConflict;
        let mut writes = vec![
            Self::snapshot_guard(db, user_id, 0, Some(previous), sentinel)?,
            query!(
                db,
                "DELETE FROM two_factors WHERE id=?1 AND user_id=?2",
                previous.id,
                user_id
            )?,
            email::require_changed_row(db, sentinel)?,
            Self::delete_remembered(db, user_id)?,
            Self::clear_recovery_statement(db, user_id)?,
        ];
        if clear_verification_codes {
            writes.push(email::invalidate_user_statement(db, user_id)?);
        }
        authorization
            .commit(db, writes, "Failed to disable authenticator")
            .await
    }

    /// Consume a verified recovery code and remove its second factors together.
    /// A changed credential snapshot leaves every factor untouched.
    pub async fn recover_if_current(db: &worker::D1Database, user: &UserRow) -> AppResult<()> {
        let marker = Uuid::new_v4().to_string();
        let results = db::run_batch(
            db,
            Self::recovery_statements(db, user, &marker)?.into(),
            "Failed to recover second factors",
        )
        .await?;
        let changed =
            db::changes_count(results.first().ok_or_else(|| {
                AppError::internal("Missing second-factor recovery batch result")
            })?)?;
        if changed != 1 {
            return Err(AppError::conflict(
                "Account or recovery code changed; retry recovery",
            ));
        }
        Ok(())
    }

    pub(crate) async fn recover_and_start_session(
        db: &worker::D1Database,
        user: &UserRow,
        session: &NewDeviceSession<'_>,
        replacement: Option<&StoredPassword>,
        approval: Option<&super::auth_request::AuthRequestRow>,
    ) -> AppResult<()> {
        let marker = Uuid::new_v4().to_string();
        let [claim, otp, credentials, factors] = Self::recovery_statements(db, user, &marker)?;
        let mut writes = vec![
            DeviceRow::guard_current_login_account(db, user)?,
            claim,
            email::require_changed_row(db, DbSentinel::LoginRecoveryConflict)?,
            otp,
            credentials,
            factors,
        ];
        if let Some(approval) = approval {
            writes.extend(approval.consume_statements(db)?);
        }
        if let Some(password) = replacement {
            writes.extend(DeviceRow::migrate_login_password(db, user, password)?);
        }
        writes.push(session.upsert_statement(db, &user.id)?);
        db.batch(writes)
            .await
            .map_err(|error| DatabaseError::login_session(&error))?;
        Ok(())
    }

    fn recovery_statements(
        db: &worker::D1Database,
        user: &UserRow,
        marker: &str,
    ) -> worker::Result<[D1PreparedStatement; 4]> {
        Ok([
            query!(
                db,
                "UPDATE users SET \
                 two_factor_recovery_code=NULL,account_write_token=?1 WHERE \
                 id=?2 AND security_stamp=?3 AND master_password_hash=?4 AND \
                 password_salt IS ?5 AND password_iterations=?6 AND \
                 two_factor_recovery_code IS ?7 AND two_factor_recovery_code \
                 IS NOT NULL AND two_factor_recovery_code<>'' AND email=?8",
                marker,
                user.id,
                user.security_stamp,
                user.master_password_hash,
                user.password_salt,
                user.password_iterations,
                user.two_factor_recovery_code,
                user.email
            )?,
            query!(
                db,
                "DELETE FROM verification_codes WHERE user_id=?1 AND EXISTS \
                 (SELECT 1 FROM users WHERE id=?1 AND account_write_token=?2)",
                user.id,
                marker
            )?,
            query!(
                db,
                "DELETE FROM webauthn_credentials WHERE user_id=?1 AND \
                 credential_use='2fa' AND EXISTS (SELECT 1 FROM users WHERE \
                 id=?1 AND account_write_token=?2)",
                user.id,
                marker
            )?,
            query!(
                db,
                "DELETE FROM two_factors WHERE user_id=?1 AND EXISTS (SELECT \
                 1 FROM users WHERE id=?1 AND account_write_token=?2)",
                user.id,
                marker
            )?,
        ])
    }

    pub(crate) fn persist_remember_if_current(
        db: &worker::D1Database,
        user: &UserRow,
        verified_factor: &Self,
        previous: Option<&Self>,
        json_data: &str,
    ) -> AppResult<[D1PreparedStatement; 2]> {
        let sql = format!(
            "INSERT INTO two_factors \
             (id,user_id,provider_type,is_enabled,data,last_used_step) SELECT \
             ?1,?2,5,1,?3,0 WHERE EXISTS(SELECT 1 FROM users WHERE id=?2 AND \
             security_stamp=?4 AND master_password_hash=?5 AND password_salt \
             IS ?6 AND password_iterations=?7 AND ({})) AND EXISTS(SELECT 1 \
             FROM two_factors WHERE user_id=?2 AND id=?9 AND \
             provider_type=?10 AND is_enabled=1 AND data=?11) AND \
             EXISTS(SELECT 1 FROM two_factors WHERE user_id=?2 AND \
             is_enabled=1 AND provider_type<>5 AND provider_type<1000) AND \
             ((?12 IS NULL AND NOT EXISTS(SELECT 1 FROM two_factors WHERE \
             user_id=?2 AND provider_type=5)) OR EXISTS(SELECT 1 FROM \
             two_factors WHERE user_id=?2 AND provider_type=5 AND id=?12 AND \
             data=?13 AND is_enabled=1)) ON CONFLICT(user_id,provider_type) \
             DO UPDATE SET data=excluded.data,is_enabled=1 RETURNING id",
            AccountSnapshot::matches_sql(8),
        );
        Ok([
            db.prepare(sql).bind(&db::d1_params![
                Uuid::new_v4().to_string(),
                user.id,
                json_data,
                user.security_stamp,
                user.master_password_hash,
                user.password_salt,
                user.password_iterations,
                AccountSnapshot::json_from_user(user).map_err(worker::Error::from)?,
                verified_factor.id,
                verified_factor.provider_type,
                verified_factor.data,
                previous.map(|factor| factor.id.as_str()),
                previous.map(|factor| factor.data.as_str()),
            ])?,
            email::require_changed_row(db, DbSentinel::LoginRememberConflict)?,
        ])
    }
}
