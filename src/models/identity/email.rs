use serde::Deserialize;
use worker::{D1Database, D1PreparedStatement, D1Result, query};

use super::two_factor::TwoFactorRow;
use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
    models::identity::{
        account_keys::AccountSnapshot,
        authorization::VerifiedAccountAction,
        device::SessionSnapshot,
        user::{StoredPassword, UserRow},
    },
};

#[derive(Clone, Copy)]
pub struct VerificationCode<'a> {
    pub id: &'a str,
    pub owner: &'a str,
    pub user_id: Option<&'a str>,
    pub purpose: &'a str,
    pub recipient: &'a str,
    pub context: &'a str,
    pub hash: &'a str,
    pub stamp: &'a str,
    pub session: &'a str,
}

const CODE_ATTEMPTS: i32 = 5;

pub(super) fn invalid_verification() -> AppError {
    AppError::bad_request("Verification code is invalid, expired or already used")
}

/// Verified proof scoped to the identity of the issued code. A resend replaces
/// that identity, so the final write must claim the same row.
pub(crate) struct VerifiedCode {
    id: String,
    hash: String,
}

impl VerifiedCode {
    pub(super) async fn batch(
        &self,
        db: &D1Database,
        writes: Vec<D1PreparedStatement>,
        write_error: impl FnOnce(&worker::Error) -> AppError,
    ) -> AppResult<Vec<D1Result>> {
        Self::batch_with_proofs(db, [self], writes, |error| write_error(&error)).await
    }

    pub(super) async fn batch_with_proofs<'a>(
        db: &D1Database,
        proofs: impl IntoIterator<Item = &'a Self>,
        writes: Vec<D1PreparedStatement>,
        write_error: impl FnOnce(worker::Error) -> AppError,
    ) -> AppResult<Vec<D1Result>> {
        let mut statements = Vec::new();
        for proof in proofs {
            statements.extend(proof.consume_statements(db)?);
        }
        let proof_statements = statements.len();
        statements.extend(writes);
        let count = statements.len();
        let results = db.batch(statements).await.map_err(|error| {
            if DatabaseError::has_marker(&error, DbSentinel::InvalidVerification) {
                invalid_verification()
            } else {
                write_error(error)
            }
        })?;
        if results.len() != count {
            return Err(AppError::Internal);
        }
        Ok(results.into_iter().skip(proof_statements).collect())
    }

    pub(crate) fn consume_statements(
        &self,
        db: &D1Database,
    ) -> worker::Result<[D1PreparedStatement; 2]> {
        Ok([
            query!(
                db,
                "UPDATE verification_codes SET attempts=attempts+1, consumed_at=?1 \
                 WHERE id=?2 AND code_hash=?3 AND ready=1 AND consumed_at IS NULL \
                 AND expires_at>?1 AND attempts<?4",
                crate::utils::time::now_seconds(),
                self.id,
                self.hash,
                CODE_ATTEMPTS
            )?,
            require_changed_row(db, DbSentinel::InvalidVerification)?,
        ])
    }
}

/// Cause D1 to roll back the batch if its preceding write had no effect.
pub(super) fn require_changed_row(
    db: &D1Database,
    marker: DbSentinel,
) -> worker::Result<D1PreparedStatement> {
    query!(
        db,
        "SELECT CASE WHEN changes()=1 THEN 1 ELSE json_extract('[]', ?1) END",
        marker.as_str()
    )
}

#[derive(Clone, Copy)]
pub(crate) enum CodeCheck {
    CountAttempt = 0,
    Consume = 1,
    PreserveOnSuccess = 2,
}

#[derive(Deserialize)]
struct VerificationMatch {
    id: String,
    valid: i32,
}

pub struct EmailChange<'a> {
    pub address: &'a str,
    pub password: &'a StoredPassword,
    pub key: &'a str,
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
}

pub async fn reserve_until(
    db: &D1Database,
    code: &VerificationCode<'_>,
    now: i64,
    expires_at: i64,
    cooldown_before: i64,
) -> AppResult<bool> {
    let id: Option<String> = db::run_query(
        async {
            query!(
                db,
                "INSERT INTO verification_codes
                 \
                     (id,owner_key,user_id,purpose,recipient,context,\
                     code_hash,security_stamp,
                  session_token,issued_at,expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
                 ON CONFLICT(owner_key,purpose,recipient,context) DO UPDATE SET
                   \
                     id=excluded.id,code_hash=excluded.code_hash,\
                     security_stamp=excluded.security_stamp,
                   \
                     session_token=excluded.session_token,issued_at=excluded.\
                     issued_at,
                   \
                     expires_at=excluded.expires_at,attempts=0,ready=0,\
                     consumed_at=NULL
                 WHERE verification_codes.issued_at<=?12 OR \
                     verification_codes.consumed_at IS NOT NULL
                    OR \
                     verification_codes.security_stamp<>excluded.\
                     security_stamp
                    OR \
                     verification_codes.session_token<>excluded.session_token \
                     RETURNING id",
                code.id,
                code.owner,
                code.user_id,
                code.purpose,
                code.recipient,
                code.context,
                code.hash,
                code.stamp,
                code.session,
                now,
                expires_at,
                cooldown_before
            )?
            .first(Some("id"))
            .await
        },
        "Failed to reserve verification code",
    )
    .await?;
    Ok(id.is_some())
}

pub(crate) async fn can_reuse(
    db: &D1Database,
    code: &VerificationCode<'_>,
    now: i64,
) -> AppResult<bool> {
    let id: Option<String> = db::run_query(
        async {
            query!(
                db,
                "SELECT id FROM verification_codes WHERE owner_key=?1 AND \
                     purpose=?2 AND recipient=?3 AND context=?4 AND \
                     security_stamp=?5 AND session_token=?6 AND ready=1 AND \
                     consumed_at IS NULL AND expires_at>?7 AND attempts<?8",
                code.owner,
                code.purpose,
                code.recipient,
                code.context,
                code.stamp,
                code.session,
                now,
                CODE_ATTEMPTS
            )?
            .first(Some("id"))
            .await
        },
        "Failed to check reusable verification code",
    )
    .await?;
    Ok(id.is_some())
}

pub async fn mark_ready(db: &D1Database, id: &str) -> AppResult<()> {
    let changed: Option<String> = db::run_query(
        async {
            query!(
                db,
                "UPDATE verification_codes SET ready=1 WHERE id=?1 \
                     RETURNING id",
                id
            )?
            .first(Some("id"))
            .await
        },
        "Failed to enable delivered verification code",
    )
    .await?;
    changed.ok_or_else(|| AppError::bad_request("Verification code was superseded"))?;
    Ok(())
}

pub async fn cancel(db: &D1Database, id: &str) -> AppResult<()> {
    db::run_query(
        async {
            query!(db, "DELETE FROM verification_codes WHERE id=?1", id)?
                .run()
                .await
        },
        "Failed to cancel verification code",
    )
    .await?;
    Ok(())
}

/// Verify eligibility and record attempts atomically. An accepted final
/// action also consumes the code in this statement.
pub(crate) async fn check(
    db: &D1Database,
    code: &VerificationCode<'_>,
    now: i64,
    mode: CodeCheck,
) -> AppResult<VerifiedCode> {
    let result: Option<VerificationMatch> = db::run_query(
        async {
            query!(
                db,
                "UPDATE verification_codes SET attempts=attempts+CASE \
                     WHEN code_hash=?1 AND ?2=2 THEN 0 ELSE 1 END,
                   consumed_at=CASE WHEN code_hash=?1 AND ?2=1 THEN ?3 ELSE \
                     consumed_at END
                 WHERE owner_key=?4 AND purpose=?5 AND recipient=?6 AND \
                     context=?7
                   AND security_stamp=?8 AND session_token=?9 AND ready=1
                   AND consumed_at IS NULL AND expires_at>?3 AND attempts<?10
                 RETURNING id, CASE WHEN code_hash=?1 THEN 1 ELSE 0 END AS \
                     valid",
                code.hash,
                mode as i32,
                now,
                code.owner,
                code.purpose,
                code.recipient,
                code.context,
                code.stamp,
                code.session,
                CODE_ATTEMPTS
            )?
            .first(None)
            .await
        },
        "Failed to verify one-time code",
    )
    .await?;
    let matched = result
        .filter(|row| row.valid == 1)
        .ok_or_else(invalid_verification)?;
    Ok(VerifiedCode {
        id: matched.id,
        hash: code.hash.to_owned(),
    })
}

pub async fn purge(db: &D1Database, now: i64) -> AppResult<()> {
    db::run_query(
        async {
            query!(
                db,
                "DELETE FROM verification_codes WHERE expires_at<=?1",
                now
            )?
            .run()
            .await
        },
        "Failed to purge verification codes",
    )
    .await?;
    db::run_query(
        async {
            query!(
                db,
                "DELETE FROM turnstile_redemptions WHERE expires_at<=?1",
                now
            )?
            .run()
            .await
        },
        "Failed to purge Turnstile redemptions",
    )
    .await?;
    Ok(())
}

pub(crate) async fn update_verified(
    db: &D1Database,
    user_id: &str,
    email: &str,
    stamp: &str,
    verification: &VerifiedCode,
    now: &str,
) -> AppResult<()> {
    let revision_sql = crate::models::mutation::next_user_revision_sql(1);
    let write = query!(
        db,
        format!(
            "UPDATE users SET \
                 is_email_verified=1,updated_at={revision_sql} WHERE id=?2 \
                 AND email=?3 AND security_stamp=?4"
        ),
        now,
        user_id,
        email,
        stamp
    )?;
    verification
        .batch(
            db,
            vec![
                write,
                require_changed_row(db, DbSentinel::EmailVerificationConflict)?,
            ],
            |error| {
                if DatabaseError::has_marker(error, DbSentinel::EmailVerificationConflict) {
                    AppError::bad_request("Account changed during verification")
                } else {
                    DatabaseError::query("Failed to verify account email", error)
                }
            },
        )
        .await?;
    Ok(())
}
pub async fn pending_recipient(
    db: &D1Database,
    user_id: &str,
    purpose: &str,
    now: i64,
    session: &str,
) -> AppResult<Option<String>> {
    db::run_query(
        async {
            query!(
                db,
                "SELECT recipient FROM verification_codes WHERE \
                     user_id=?1 AND purpose=?2
                AND ready=1 AND consumed_at IS NULL AND expires_at>?3 AND \
                     session_token=?4 ORDER BY issued_at DESC LIMIT 1",
                user_id,
                purpose,
                now,
                session
            )?
            .first(Some("recipient"))
            .await
        },
        "Failed to fetch pending email verification",
    )
    .await
}

pub async fn email_in_use(db: &D1Database, email: &str, user_id: &str) -> AppResult<bool> {
    let id: Option<String> = db::run_query(
        async {
            query!(
                db,
                "SELECT id FROM users WHERE email=?1 AND id<>?2",
                email,
                user_id
            )?
            .first(Some("id"))
            .await
        },
        "Failed to check email availability",
    )
    .await?;
    Ok(id.is_some())
}

pub(crate) async fn change_email(
    db: &D1Database,
    user: &UserRow,
    session: &SessionSnapshot<'_>,
    verification: &VerifiedCode,
    change: EmailChange<'_>,
    now: &str,
) -> AppResult<()> {
    if user.id != session.user_id {
        return Err(AppError::conflict("Account does not match the session"));
    }
    let snapshot = AccountSnapshot::json_from_user(user)?;
    let token = uuid::Uuid::new_v4().to_string();
    let snapshot_predicate = AccountSnapshot::matches_sql(14);
    let revision_sql = crate::models::mutation::next_user_revision_sql(10);
    let claim = query!(
        db,
        format!(
            "UPDATE users SET \
                 email=?1,is_email_verified=1,master_password_hash=?2,\
                 password_salt=?3,key=?4,kdf_type=?5,kdf_iterations=?6,\
                 kdf_memory=?7,kdf_parallelism=?8,security_stamp=?9,\
                 account_write_token=?9,v2_upgrade_token=NULL,\
                 security_stamp_exceptions=NULL,updated_at={revision_sql},\
                 password_iterations=?19 WHERE id=?11 AND security_stamp=?12 \
                 AND master_password_hash=?13 AND password_salt IS ?17 AND \
                 password_iterations=?18 AND ({snapshot_predicate}) AND \
                 EXISTS(SELECT 1 FROM devices WHERE user_id=?11 AND \
                 device_id=?15 AND session_token=?16) AND NOT EXISTS(SELECT 1 \
                 FROM users other WHERE other.email=?1 AND other.id<>?11) \
                 RETURNING id"
        ),
        change.address,
        change.password.hash,
        change.password.salt,
        change.key,
        change.kdf_type,
        change.kdf_iterations,
        change.kdf_memory,
        change.kdf_parallelism,
        token,
        now,
        user.id,
        session.security_stamp,
        user.master_password_hash,
        snapshot,
        session.device_id,
        session.session_token,
        user.password_salt,
        user.password_iterations,
        change.password.iterations
    )?;
    let mut writes = vec![
        claim,
        require_changed_row(db, DbSentinel::EmailChangeConflict)?,
    ];
    writes.extend(change_email_cleanup(
        db, &user.id, &token, change.key, &snapshot,
    )?);
    verification
        .batch(db, writes, |error| {
            if DatabaseError::has_marker(error, DbSentinel::EmailChangeConflict) {
                AppError::conflict("Account changed or email is unavailable")
            } else {
                DatabaseError::query("Failed to update account email", error)
            }
        })
        .await?;
    Ok(())
}

fn change_email_cleanup(
    db: &D1Database,
    user_id: &str,
    token: &str,
    key: &str,
    snapshot: &str,
) -> AppResult<Vec<worker::D1PreparedStatement>> {
    Ok(vec![
        query!(
            db,
            "DELETE FROM two_factors WHERE user_id=?1 AND provider_type=5 \
                 AND EXISTS(SELECT 1 FROM users WHERE id=?1 AND \
                 account_write_token=?2)",
            user_id,
            token
        )?,
        query!(
            db,
            "DELETE FROM auth_requests WHERE user_id=?1 AND EXISTS(SELECT \
                 1 FROM users WHERE id=?1 AND account_write_token=?2)",
            user_id,
            token
        )?,
        query!(
            db,
            "DELETE FROM verification_codes WHERE user_id=?1 AND \
                 EXISTS(SELECT 1 FROM users WHERE id=?1 AND \
                 account_write_token=?2)",
            user_id,
            token
        )?,
        query!(
            db,
            "UPDATE webauthn_credentials SET \
                 account_snapshot=json_set(account_snapshot,'$.key',?1) WHERE \
                 user_id=?2 AND account_snapshot=?3 AND EXISTS(SELECT 1 FROM \
                 users WHERE id=?2 AND account_write_token=?4)",
            key,
            user_id,
            snapshot,
            token
        )?,
    ])
}

pub async fn claim_turnstile(db: &D1Database, hash: &str, expires_at: i64) -> AppResult<()> {
    let claimed: Option<String> = db::run_query(
        async {
            query!(
                db,
                "INSERT INTO turnstile_redemptions(token_hash,expires_at) \
                     VALUES(?1,?2)
                ON CONFLICT(token_hash) DO NOTHING RETURNING token_hash",
                hash,
                expires_at
            )?
            .first(Some("token_hash"))
            .await
        },
        "Failed to claim Turnstile verification",
    )
    .await?;
    claimed.ok_or_else(|| AppError::bad_request("Turnstile response has already been used"))?;
    Ok(())
}
pub(crate) async fn enable_provider(
    db: &D1Database,
    session: &SessionSnapshot<'_>,
    email: &str,
    recovery: &str,
    verification: &VerifiedCode,
    authorization: Option<&VerifiedCode>,
) -> AppResult<()> {
    let user_id = session.user_id;
    let id = uuid::Uuid::new_v4().to_string();
    let data = serde_json::json!({"email":email}).to_string();
    let revision_sql = crate::models::mutation::next_user_revision_sql(2);
    VerifiedCode::batch_with_proofs(
        db,
        authorization.into_iter().chain([verification]),
        vec![
            query!(
                db,
                "SELECT CASE WHEN EXISTS (SELECT 1 FROM users u JOIN \
                     devices d ON d.user_id=u.id WHERE u.id=?1 AND \
                     u.security_stamp=?2 AND d.device_id=?3 AND \
                     d.session_token=?4) THEN 1 ELSE json_extract('[]', ?5) \
                     END",
                user_id,
                session.security_stamp,
                session.device_id,
                session.session_token,
                DbSentinel::EmailProviderSessionConflict.as_str()
            )?,
            query!(
                db,
                "INSERT INTO \
                     two_factors(id,user_id,provider_type,is_enabled,data,\
                     last_used_step)
                    VALUES(?1,?2,1,1,?3,0) ON CONFLICT(user_id,provider_type) \
                     DO UPDATE SET
                    is_enabled=1,data=excluded.data,last_used_step=0",
                id,
                user_id,
                data
            )?,
            require_changed_row(db, DbSentinel::EnableEmailProviderFailed)?,
            query!(
                db,
                format!(
                    "UPDATE users SET two_factor_recovery_code=\
                         COALESCE(two_factor_recovery_code,?1),\
                         updated_at={revision_sql} WHERE id=?3"
                ),
                recovery,
                crate::utils::time::now_rfc3339(),
                user_id
            )?,
            query!(
                db,
                "DELETE FROM verification_codes WHERE user_id=?1 AND \
                     purpose='email-setup'",
                user_id
            )?,
            query!(
                db,
                "DELETE FROM two_factors WHERE user_id=?1 AND \
                     provider_type=5",
                user_id
            )?,
        ],
        |error| {
            if DatabaseError::has_marker(&error, DbSentinel::EmailProviderSessionConflict) {
                return AppError::conflict("Account or session changed; retry");
            }
            DatabaseError::query("Failed to enable email two-factor authentication", &error)
        },
    )
    .await?;
    Ok(())
}
pub(super) fn invalidate_user_statement(
    db: &D1Database,
    user_id: &str,
) -> worker::Result<D1PreparedStatement> {
    query!(
        db,
        "DELETE FROM verification_codes WHERE user_id=?1",
        user_id
    )
}

pub(crate) async fn disable_provider(
    db: &D1Database,
    authorization: &VerifiedAccountAction<'_>,
    previous: Option<&TwoFactorRow>,
) -> AppResult<()> {
    let user_id = authorization.session.user_id;
    let revision_sql = crate::models::mutation::next_user_revision_sql(1);
    authorization.commit(db, vec![
        TwoFactorRow::snapshot_guard(db, user_id, 1, previous)?,
        query!(
            db,
            "DELETE FROM two_factors WHERE user_id=?1 AND provider_type IN (1,5)",
            user_id
        )?,
        query!(
            db,
            "DELETE FROM verification_codes WHERE user_id=?1 AND purpose IN ('email-login','email-setup')",
            user_id
        )?,
        query!(
            db,
            format!("UPDATE users SET updated_at={revision_sql} WHERE id=?2"),
            crate::utils::time::now_rfc3339(),
            user_id
        )?,
        TwoFactorRow::clear_recovery_statement(db, user_id, None)?,
    ], "Failed to disable email two-factor authentication").await?;
    Ok(())
}
