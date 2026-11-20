use serde::{
    Deserialize,
    Serialize,
};
use uuid::Uuid;
use worker::{
    D1PreparedStatement,
    query,
    wasm_bindgen::JsValue,
};

use super::{
    email::EmailStore,
    webauthn::WebauthnCredentialRow,
};
use crate::{
    errors::{
        AppError,
        AppResult,
        DatabaseError,
    },
    infra::db,
    models::identity::{
        account_keys::AccountSnapshot,
        device::SessionSnapshot,
        user::UserRow,
    },
    utils::serde::bool_from_int,
};

pub(crate) const REMEMBER_PROVIDER: i32 = 5;
const FIRST_INTERNAL_PROVIDER: i32 = 1000;

/// `TwoFactorRow` database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorRow {
    pub id:             String,
    pub user_id:        String,
    pub provider_type:  i32,
    #[serde(with = "bool_from_int")]
    pub is_enabled:     bool,
    pub data:           String,
    pub last_used_step: i64,
}

impl TwoFactorRow {
    /// List all 2FA records for a user (includes Remember tokens, excludes
    /// `provider_type >= 1000`).
    pub async fn list_for_user(
        db: &worker::D1Database,
        user_id: &str,
    ) -> AppResult<Vec<Self>> {
        db.prepare(format!(
            "SELECT * FROM two_factors WHERE user_id = ?1 AND provider_type < \
             {FIRST_INTERNAL_PROVIDER}"
        ))
        .bind(&[user_id.to_string().into()])?
        .all()
        .await
        .map_err(|err| {
            DatabaseError::query(
                format_args!(
                    "Failed to query two_factors records for user {user_id}"
                ),
                err,
            )
        })?
        .results::<Self>()
        .map_err(|err| {
            DatabaseError::query(
                format_args!(
                    "Failed to deserialize two_factors records for user \
                     {user_id}"
                ),
                err,
            )
        })
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
        .bind(&[user_id.to_string().into(), provider_type.into()])?
        .first(None)
        .await
        .map_err(|err| {
            DatabaseError::query(
                format_args!(
                    "Failed to fetch two_factors type {provider_type} for \
                     user {user_id}"
                ),
                err,
            )
        })?
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                DatabaseError::invalid_result(
                    "Failed to deserialize two_factors record",
                    error,
                )
            })
        })
        .transpose()
    }

    pub async fn disable_provider(
        db: &worker::D1Database,
        user_id: &str,
        provider_type: i32,
    ) -> AppResult<()> {
        db::run_query(
            async {
                let mut writes =
                    vec![EmailStore::invalidate_user_statement(db, user_id)?];
                if provider_type == 7 {
                    writes.push(WebauthnCredentialRow::purge_2fa_statement(
                        db, user_id,
                    )?);
                }
                writes.push(query!(
                    db,
                    "DELETE FROM two_factors WHERE user_id=?1 AND \
                     provider_type IN (?2,?3)",
                    user_id,
                    provider_type,
                    REMEMBER_PROVIDER,
                )?);
                writes.push(Self::clear_recovery_statement(db, user_id, None)?);
                db.batch(writes).await
            },
            "Failed to delete two_factors entries",
        )
        .await?;
        Ok(())
    }

    /// Keep legacy enabled providers in the login policy. Remember and internal
    /// records do not require a challenge or preserve a recovery code.
    pub(crate) const fn requires_login_challenge(&self) -> bool {
        self.is_enabled &&
            self.provider_type != REMEMBER_PROVIDER &&
            self.provider_type < FIRST_INTERNAL_PROVIDER
    }

    /// Evaluate the same provider policy as login inside the factor write.
    /// Account writes using a claim marker also require that claim to succeed.
    pub(super) fn clear_recovery_statement(
        db: &worker::D1Database,
        user_id: &str,
        write_marker: Option<&str>,
    ) -> worker::Result<D1PreparedStatement> {
        query!(
            db,
            format!(
                "UPDATE users SET two_factor_recovery_code=NULL WHERE id=?1 \
                 AND (?2 IS NULL OR account_write_token=?2) AND NOT EXISTS \
                 (SELECT 1 FROM two_factors WHERE user_id=?1 AND is_enabled=1 \
                 AND provider_type<>{REMEMBER_PROVIDER} AND \
                 provider_type<{FIRST_INTERNAL_PROVIDER})"
            ),
            user_id,
            write_marker,
        )
    }

    pub async fn update_last_used_step(
        db: &worker::D1Database,
        id: &str,
        last_used_step: i64,
    ) -> AppResult<()> {
        let result = query!(
            db,
            "UPDATE two_factors SET last_used_step = ?1 WHERE id = ?2 AND \
             is_enabled = 1 AND last_used_step < ?1",
            last_used_step,
            id
        )?
        .run()
        .await?;
        if result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) != 1 {
            return Err(crate::errors::AuthError::InvalidTotp.into());
        }
        Ok(())
    }

    pub async fn replace_authenticator(
        db: &worker::D1Database,
        session: &SessionSnapshot<'_>,
        previous: Option<&Self>,
        value: &Self,
        recovery_code: &str,
    ) -> AppResult<()> {
        let previous = previous
            .map(serde_json::to_string)
            .transpose()
            .map_err(AppError::internal_error)?;
        let statements = vec![
            query!(
                db,
                "INSERT INTO \
                 two_factors(id,user_id,provider_type,is_enabled,data,\
                 last_used_step) SELECT ?1,?2,0,?3,?4,?5 WHERE EXISTS (SELECT \
                 1 FROM users u JOIN devices d ON d.user_id=u.id WHERE \
                 u.id=?2 AND u.security_stamp=?7 AND d.device_id=?8 AND \
                 d.session_token=?9) AND ((?6 IS NULL AND NOT EXISTS (SELECT \
                 1 FROM two_factors WHERE user_id=?2 AND provider_type=0)) OR \
                 EXISTS (SELECT 1 FROM two_factors WHERE user_id=?2 AND \
                 provider_type=0 AND id=json_extract(?6,'$.id') AND \
                 data=json_extract(?6,'$.data') AND \
                 is_enabled=json_extract(?6,'$.is_enabled') AND \
                 last_used_step=json_extract(?6,'$.last_used_step'))) ON \
                 CONFLICT(user_id,provider_type) DO UPDATE SET \
                 id=excluded.id,is_enabled=excluded.is_enabled, \
                 data=excluded.data,last_used_step=excluded.last_used_step",
                value.id,
                session.user_id,
                i32::from(value.is_enabled),
                value.data,
                value.last_used_step,
                previous,
                session.security_stamp,
                session.device_id,
                session.session_token
            )?,
            db.prepare(
                "SELECT CASE WHEN changes()=1 THEN 1 ELSE json_extract('[]', \
                 'RAY_TOTP_WRITE_CONFLICT') END",
            ),
            query!(
                db,
                "DELETE FROM two_factors WHERE user_id=?1 AND provider_type=5 \
                 AND EXISTS (SELECT 1 FROM two_factors WHERE id=?2)",
                session.user_id,
                value.id
            )?,
            query!(
                db,
                "UPDATE users SET two_factor_recovery_code=?2 WHERE id=?1 AND \
                 two_factor_recovery_code IS NULL",
                session.user_id,
                recovery_code
            )?,
        ];
        let result = db
            .batch(statements)
            .await
            .map_err(DatabaseError::totp_write)?;
        if result
            .first()
            .and_then(|r| r.meta().ok().flatten())
            .and_then(|m| m.changes)
            .unwrap_or(0) !=
            1
        {
            return Err(AppError::conflict(
                "Authenticator configuration changed; retry",
            ));
        }
        Ok(())
    }

    pub async fn delete_authenticator_snapshot(
        db: &worker::D1Database,
        session: &SessionSnapshot<'_>,
        previous: &Self,
        clear_verification_codes: bool,
    ) -> AppResult<()> {
        let mut writes = vec![
            query!(
                db,
                "DELETE FROM two_factors WHERE id=?1 AND user_id=?2 AND \
                 provider_type=0 AND data=?3 AND is_enabled=?4 AND \
                 last_used_step=?5 AND EXISTS (SELECT 1 FROM users u JOIN \
                 devices d ON d.user_id=u.id WHERE u.id=?2 AND \
                 u.security_stamp=?6 AND d.device_id=?7 AND \
                 d.session_token=?8)",
                previous.id,
                session.user_id,
                previous.data,
                i32::from(previous.is_enabled),
                previous.last_used_step,
                session.security_stamp,
                session.device_id,
                session.session_token
            )?,
            db.prepare(
                "SELECT CASE WHEN changes()=1 THEN 1 ELSE json_extract('[]', \
                 'RAY_TOTP_WRITE_CONFLICT') END",
            ),
            query!(
                db,
                "DELETE FROM two_factors WHERE user_id=?1 AND provider_type=5 \
                 AND NOT EXISTS (SELECT 1 FROM two_factors WHERE user_id=?1 \
                 AND provider_type=0)",
                session.user_id
            )?,
            Self::clear_recovery_statement(db, session.user_id, None)?,
        ];
        if clear_verification_codes {
            writes.push(EmailStore::invalidate_user_statement(
                db,
                session.user_id,
            )?);
        }
        let result =
            db.batch(writes).await.map_err(DatabaseError::totp_write)?;
        if result
            .first()
            .and_then(|r| r.meta().ok().flatten())
            .and_then(|m| m.changes)
            .unwrap_or(0) !=
            1
        {
            return Err(AppError::conflict(
                "Authenticator configuration changed; retry",
            ));
        }
        Ok(())
    }

    /// Consume a verified recovery code and remove its second factors together.
    /// A changed credential snapshot leaves every factor untouched.
    pub async fn recover_if_current(
        db: &worker::D1Database,
        user: &UserRow,
    ) -> AppResult<()> {
        let marker = Uuid::new_v4().to_string();
        let results = db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "UPDATE users SET \
                         two_factor_recovery_code=NULL,account_write_token=?1 \
                         WHERE id=?2 AND security_stamp=?3 AND \
                         master_password_hash=?4 AND password_salt IS ?5 AND \
                         password_iterations=?6 AND two_factor_recovery_code \
                         IS ?7 AND two_factor_recovery_code IS NOT NULL AND \
                         two_factor_recovery_code<>'' AND email=?8",
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
                        "DELETE FROM verification_codes WHERE user_id=?1 AND \
                         EXISTS (SELECT 1 FROM users WHERE id=?1 AND \
                         account_write_token=?2)",
                        user.id,
                        marker
                    )?,
                    query!(
                        db,
                        "DELETE FROM webauthn_credentials WHERE user_id=?1 \
                         AND credential_use='2fa' AND EXISTS (SELECT 1 FROM \
                         users WHERE id=?1 AND account_write_token=?2)",
                        user.id,
                        marker
                    )?,
                    query!(
                        db,
                        "DELETE FROM two_factors WHERE user_id=?1 AND EXISTS \
                         (SELECT 1 FROM users WHERE id=?1 AND \
                         account_write_token=?2)",
                        user.id,
                        marker
                    )?,
                ])
                .await
            },
            "Failed to recover second factors",
        )
        .await?;
        let changed = results
            .first()
            .ok_or(AppError::Internal)?
            .meta()?
            .and_then(|meta| meta.changes)
            .unwrap_or(0);
        if changed != 1 {
            return Err(AppError::conflict(
                "Account or recovery code changed; retry recovery",
            ));
        }
        Ok(())
    }

    pub async fn persist_remember_if_current(
        db: &worker::D1Database,
        user: &UserRow,
        verified_factor: &Self,
        previous: Option<&Self>,
        json_data: &str,
    ) -> AppResult<()> {
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
        let changed: Option<String> = db::run_query(
            async {
                db.prepare(sql)
                    .bind(&[
                        Uuid::new_v4().to_string().into(),
                        user.id.clone().into(),
                        json_data.into(),
                        user.security_stamp.clone().into(),
                        user.master_password_hash.clone().into(),
                        user.password_salt
                            .clone()
                            .map_or(JsValue::NULL, Into::into),
                        user.password_iterations.into(),
                        AccountSnapshot::from_user(user)
                            .to_json()
                            .map_err(worker::Error::from)?
                            .into(),
                        verified_factor.id.clone().into(),
                        verified_factor.provider_type.into(),
                        verified_factor.data.clone().into(),
                        previous.map_or(JsValue::NULL, |factor| {
                            factor.id.clone().into()
                        }),
                        previous.map_or(JsValue::NULL, |factor| {
                            factor.data.clone().into()
                        }),
                    ])?
                    .first(Some("id"))
                    .await
            },
            "Failed to upsert remember token",
        )
        .await?;
        if changed.is_none() {
            return Err(AppError::conflict(
                "Second-factor or account state changed during remembered \
                 login",
            ));
        }
        Ok(())
    }
}
