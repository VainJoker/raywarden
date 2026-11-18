use worker::{
    D1Database,
    query,
};

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::db,
};

pub const CODE_TTL_SECONDS: i64 = 600;
pub const CODE_COOLDOWN_SECONDS: i64 = 60;
pub const CODE_ATTEMPTS: i32 = 5;

pub struct VerificationCode<'a> {
    pub id:        &'a str,
    pub owner:     &'a str,
    pub user_id:   Option<&'a str>,
    pub purpose:   &'a str,
    pub recipient: &'a str,
    pub context:   &'a str,
    pub hash:      &'a str,
    pub stamp:     &'a str,
    pub session:   &'a str,
}

pub struct EmailDB;

impl EmailDB {
    pub async fn reserve(
        db: &D1Database,
        code: &VerificationCode<'_>,
        now: i64,
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
                    now + CODE_TTL_SECONDS,
                    now - CODE_COOLDOWN_SECONDS
                )?
                .first(Some("id"))
                .await
            },
            "Failed to reserve verification code",
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
        changed.ok_or_else(|| {
            AppError::bad_request("Verification code was superseded")
        })?;
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

    /// Every attempt is recorded atomically, including failed comparisons. A
    /// successful final action consumes the code in this same statement.
    pub async fn check(
        db: &D1Database,
        code: &VerificationCode<'_>,
        now: i64,
        consume: bool,
    ) -> AppResult<()> {
        let valid: Option<i32> = db::run_query(
            async {
                query!(
                    db,
                    "UPDATE verification_codes SET attempts=attempts+1,
                   consumed_at=CASE WHEN code_hash=?1 AND ?2 THEN ?3 ELSE \
                     consumed_at END
                 WHERE owner_key=?4 AND purpose=?5 AND recipient=?6 AND \
                     context=?7
                   AND security_stamp=?8 AND session_token=?9 AND ready=1
                   AND consumed_at IS NULL AND expires_at>?3 AND attempts<?10
                 RETURNING CASE WHEN code_hash=?1 THEN 1 ELSE 0 END AS valid",
                    code.hash,
                    consume,
                    now,
                    code.owner,
                    code.purpose,
                    code.recipient,
                    code.context,
                    code.stamp,
                    code.session,
                    CODE_ATTEMPTS
                )?
                .first(Some("valid"))
                .await
            },
            "Failed to verify one-time code",
        )
        .await?;
        if valid == Some(1) {
            Ok(())
        } else {
            Err(AppError::bad_request(
                "Verification code is invalid, expired or already used",
            ))
        }
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

    pub async fn update_verified(
        db: &D1Database,
        user_id: &str,
        email: &str,
        stamp: &str,
        now: &str,
    ) -> AppResult<()> {
        let changed: Option<String> = db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET email_verified=1,updated_at=?1 WHERE \
                     id=?2 AND email=?3 AND security_stamp=?4 RETURNING id",
                    now,
                    user_id,
                    email,
                    stamp
                )?
                .first(Some("id"))
                .await
            },
            "Failed to verify account email",
        )
        .await?;
        changed.ok_or_else(|| {
            AppError::bad_request("Account changed during verification")
        })?;
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

    pub async fn email_in_use(
        db: &D1Database,
        email: &str,
        user_id: &str,
    ) -> AppResult<bool> {
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

    #[allow(clippy::too_many_arguments)]
    pub async fn change_email(
        db: &D1Database,
        user_id: &str,
        old_stamp: &str,
        email: &str,
        hash: &str,
        salt: &str,
        key: &str,
        kdf: i32,
        iterations: i32,
        memory: Option<i32>,
        parallelism: Option<i32>,
        now: &str,
        old_hash: &str,
        snapshot: &str,
        device: &str,
        session: &str,
    ) -> AppResult<()> {
        let token = uuid::Uuid::new_v4().to_string();
        let claim = query!(
            db,
            "UPDATE users SET \
             email=?1,email_verified=1,master_password_hash=?2,password_salt=?\
             3,key=?4,kdf_type=?5,kdf_iterations=?6,kdf_memory=?7,\
             kdf_parallelism=?8,security_stamp=?9,account_write_token=?9,\
             v2_upgrade_token=NULL,security_stamp_exceptions=NULL,updated_at=?\
             10 WHERE id=?11 AND security_stamp=?12 AND \
             master_password_hash=?13 AND (key IS json_extract(?14, '$.key') \
             AND user_key_id IS json_extract(?14, '$.user_key_id') AND \
             private_key IS json_extract(?14, '$.private_key') AND public_key \
             IS json_extract(?14, '$.public_key') AND signed_public_key IS \
             json_extract(?14, '$.signed_public_key') AND security_state IS \
             json_extract(?14, '$.security_state') AND security_version IS \
             json_extract(?14, '$.security_version') AND signature_key_pair \
             IS json_extract(?14, '$.signature_key_pair')) AND EXISTS(SELECT \
             1 FROM devices WHERE user_id=?11 AND identifier=?15 AND \
             session_token=?16) RETURNING id",
            email,
            hash,
            salt,
            key,
            kdf,
            iterations,
            memory,
            parallelism,
            token,
            now,
            user_id,
            old_stamp,
            old_hash,
            snapshot,
            device,
            session
        )?;
        let mut writes = vec![claim];
        writes.extend(Self::change_email_cleanup(
            db, user_id, &token, key, snapshot,
        )?);
        let rows = db::run_query(
            async { db.batch(writes).await },
            "Failed to update account email",
        )
        .await?;
        if rows[0].results::<serde_json::Value>()?.is_empty() {
            return Err(AppError::conflict(
                "Account changed during email update",
            ));
        }
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
                "DELETE FROM twofactor WHERE user_uuid=?1 AND atype=5 AND \
                 EXISTS(SELECT 1 FROM users WHERE id=?1 AND \
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

    pub async fn claim_turnstile(
        db: &D1Database,
        hash: &str,
        now: i64,
    ) -> AppResult<()> {
        let claimed: Option<String> = db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO turnstile_redemptions(token_hash,expires_at) \
                     VALUES(?1,?2)
                ON CONFLICT(token_hash) DO NOTHING RETURNING token_hash",
                    hash,
                    now + 600
                )?
                .first(Some("token_hash"))
                .await
            },
            "Failed to claim Turnstile verification",
        )
        .await?;
        claimed.ok_or_else(|| {
            AppError::bad_request("Turnstile response has already been used")
        })?;
        Ok(())
    }
    pub async fn enable_provider(
        db: &D1Database,
        user_id: &str,
        email: &str,
        recovery: &str,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let data = serde_json::json!({"email":email}).to_string();
        db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "INSERT INTO \
                         twofactor(uuid,user_uuid,atype,enabled,data,\
                         last_used)
                    VALUES(?1,?2,1,1,?3,0) ON CONFLICT(user_uuid,atype) DO \
                         UPDATE SET
                    enabled=1,data=excluded.data,last_used=0",
                        id,
                        user_id,
                        data
                    )?,
                    query!(
                        db,
                        "UPDATE users SET \
                         totp_recover=COALESCE(totp_recover,?1),updated_at=?2 \
                         WHERE id=?3",
                        recovery,
                        crate::infra::time::now_rfc3339(),
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
                        "DELETE FROM twofactor WHERE user_uuid=?1 AND atype=5",
                        user_id
                    )?,
                ])
                .await
            },
            "Failed to enable email two-factor authentication",
        )
        .await?;
        Ok(())
    }
    pub async fn invalidate_user(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM verification_codes WHERE user_id=?1",
                    user_id
                )?
                .run()
                .await
            },
            "Failed to invalidate account verification codes",
        )
        .await?;
        Ok(())
    }

    pub async fn disable_provider(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<()> {
        db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "DELETE FROM twofactor WHERE user_uuid=?1 AND atype \
                         IN (1,5)",
                        user_id
                    )?,
                    query!(
                        db,
                        "DELETE FROM verification_codes WHERE user_id=?1 AND \
                         purpose IN ('email-login','email-setup')",
                        user_id
                    )?,
                    query!(
                        db,
                        "UPDATE users SET updated_at=?1 WHERE id=?2",
                        crate::infra::time::now_rfc3339(),
                        user_id
                    )?,
                ])
                .await
            },
            "Failed to disable email two-factor authentication",
        )
        .await?;
        Ok(())
    }
}
