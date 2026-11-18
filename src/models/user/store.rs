use serde_json::Value;
use worker::{
    D1Database,
    query,
};

use super::{
    UserDB,
    UserKdfParams,
};
use crate::{
    errors::{
        AppError,
        DatabaseError,
    },
    infra::db,
    models::account_keys,
};

impl UserDB {
    pub async fn exists_any(db: &D1Database) -> Result<bool, AppError> {
        let found: Option<i64> = db::run_query(
            async {
                db.prepare("SELECT 1 AS present FROM users LIMIT 1")
                    .first(Some("present"))
                    .await
            },
            "Failed to check owner initialization",
        )
        .await?;
        Ok(found.is_some())
    }

    pub async fn kdf_params_by_email(
        db: &D1Database,
        email: &str,
    ) -> Result<UserKdfParams, AppError> {
        let stmt = db.prepare(
            "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism \
             FROM users WHERE email = ?1",
        );
        let email = email.trim().to_lowercase();
        let query = stmt.bind(&[email.into()])?;

        let row: Option<Value> = query.first(None).await.map_err(|e| {
            log::warn!("get_kdf_params_by_email query failed: {e}");
            AppError::Database(DatabaseError::QueryFailed(e.to_string()))
        })?;

        if let Some(row) = row {
            let kdf_type = row
                .get("kdf_type")
                .and_then(serde_json::Value::as_i64)
                .map(|value| value as i32);
            let kdf_iterations = row
                .get("kdf_iterations")
                .and_then(serde_json::Value::as_i64)
                .map(|value| value as i32);
            let kdf_memory = row
                .get("kdf_memory")
                .and_then(serde_json::Value::as_i64)
                .map(|value| value as i32);
            let kdf_parallelism = row
                .get("kdf_parallelism")
                .and_then(serde_json::Value::as_i64)
                .map(|value| value as i32);

            Ok(UserKdfParams {
                kdf_type,
                kdf_iterations,
                kdf_memory,
                kdf_parallelism,
            })
        } else {
            Ok(UserKdfParams {
                kdf_type:        None,
                kdf_iterations:  None,
                kdf_memory:      None,
                kdf_parallelism: None,
            })
        }
    }

    pub async fn insert(
        db: &D1Database,
        user: &UserDB,
    ) -> Result<(), AppError> {
        let result = async {
            query!(
                db,
                "INSERT INTO users (id, name, email, master_password_hash, \
                 master_password_hint, password_salt, key, private_key, \
                 public_key, kdf_type, kdf_iterations, kdf_memory, \
                 kdf_parallelism, security_stamp, equivalent_domains, \
                 excluded_globals,totp_recover, created_at, updated_at, \
                 email_verified, user_key_id, signed_public_key, \
                 security_state, security_version, signature_key_pair) VALUES \
                 (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
                 ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
                user.id,
                user.name,
                user.email,
                user.master_password_hash,
                user.master_password_hint,
                user.password_salt,
                user.key,
                user.private_key,
                user.public_key,
                user.kdf_type,
                user.kdf_iterations,
                user.kdf_memory,
                user.kdf_parallelism,
                user.security_stamp,
                user.equivalent_domains,
                user.excluded_globals,
                user.totp_recover,
                user.created_at,
                user.updated_at,
                i32::from(user.email_verified),
                user.user_key_id,
                user.signed_public_key,
                user.security_state,
                user.security_version,
                user.signature_key_pair
            )?
            .run()
            .await
        }
        .await;
        match result {
            Err(error) if owner_registration_conflict(&error.to_string()) => {
                Err(AppError::conflict("The owner account already exists"))
            }
            result => {
                db::run_query(
                    async { result.map(|_| ()) },
                    "Failed to insert user",
                )
                .await
            }
        }
    }

    pub async fn revision_date_ms(
        db: &D1Database,
        user_id: &str,
    ) -> Result<i64, AppError> {
        let updated_at: Option<String> = db
            .prepare("SELECT updated_at FROM users WHERE id = ?1")
            .bind(&[user_id.into()])
            .map_err(|e| {
                log::error!("Database error fetching revision date: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch revision date".to_string(),
                ))
            })?
            .first(Some("updated_at"))
            .await
            .map_err(|e| {
                log::error!("Database error fetching revision date: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch revision date".to_string(),
                ))
            })?;

        let revision_date = updated_at
            .and_then(|ts| crate::infra::time::parse(&ts).ok())
            .map_or_else(
                || crate::infra::time::now().as_millisecond(),
                |dt| dt.as_millisecond(),
            );

        Ok(revision_date)
    }

    pub async fn migrate_legacy_password_if_current(
        db: &D1Database,
        user: &Self,
        hash: &str,
        salt: &str,
        now: &str,
    ) -> Result<(), AppError> {
        let sql = format!(
            "UPDATE users SET \
             master_password_hash=?1,password_salt=?2,updated_at=?3 WHERE \
             id=?4 AND master_password_hash=?5 AND password_salt IS NULL AND \
             security_stamp=?6 AND ({}) RETURNING id",
            account_keys::AccountSnapshot::matches_sql(7)
        );
        let row: Option<String> = db::run_query(
            async {
                db.prepare(&sql)
                    .bind(&[
                        hash.into(),
                        salt.into(),
                        now.into(),
                        user.id.clone().into(),
                        user.master_password_hash.clone().into(),
                        user.security_stamp.clone().into(),
                        account_keys::AccountSnapshot::from_user(user)
                            .to_json()
                            .map_err(worker::Error::from)?
                            .into(),
                    ])?
                    .first(Some("id"))
                    .await
            },
            "Failed to migrate password verifier",
        )
        .await?;
        if row.is_none() {
            return Err(AppError::conflict(
                "Account changed while upgrading password verifier",
            ));
        }
        Ok(())
    }

    pub async fn clear_recovery_code(
        db: &D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET totp_recover = NULL WHERE id = ?1",
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to clear recovery code",
        )
        .await
    }

    pub async fn set_recovery_code(
        db: &D1Database,
        user_id: &str,
        recovery_code: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET totp_recover = ?1 WHERE id = ?2",
                    recovery_code,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to set recovery code",
        )
        .await
    }

    /// Update a user's display name and revision timestamp.
    pub async fn update_profile_name(
        db: &D1Database,
        user_id: &str,
        name: &Option<String>,
        updated_at: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3",
                    name,
                    updated_at,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update user profile",
        )
        .await
    }

    /// Update a user's avatar color and revision timestamp.
    pub async fn update_avatar_color(
        db: &D1Database,
        user_id: &str,
        avatar_color: &Option<String>,
        updated_at: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET avatar_color = ?1, updated_at = ?2 \
                     WHERE id = ?3",
                    avatar_color,
                    updated_at,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update user avatar",
        )
        .await
    }

    /// Delete a user row by id.
    pub async fn delete_user(
        db: &D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(db, "DELETE FROM users WHERE id = ?1", user_id)?
                    .run()
                    .await
                    .map(|_| ())
            },
            "Failed to delete user",
        )
        .await
    }

    /// Fetch a user by id with consistent error mapping and not-found handling.
    pub async fn fetch_by_id_with<F>(
        db: &D1Database,
        user_id: &str,
        context: &str,
        not_found: F,
    ) -> Result<Self, AppError>
    where
        F: FnOnce() -> AppError,
    {
        let user_value: Option<Value> = db
            .prepare("SELECT * FROM users WHERE id = ?1")
            .bind(&[user_id.into()])
            .map_err(|e| {
                log::error!("{context}: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    context.to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("{context}: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    context.to_string(),
                ))
            })?;

        let user_value = user_value.ok_or_else(not_found)?;

        serde_json::from_value(user_value).map_err(|e| {
            log::error!("{context} deserialize: {e}");
            AppError::Internal
        })
    }

    /// Fetch a user by email (normalized to lowercase) with consistent error
    /// mapping.
    pub async fn fetch_by_email_with<F>(
        db: &D1Database,
        email: &str,
        context: &str,
        not_found: F,
    ) -> Result<Self, AppError>
    where
        F: FnOnce() -> AppError,
    {
        let normalized_email = email.trim().to_lowercase();
        let user_value: Option<Value> = db
            .prepare("SELECT * FROM users WHERE email = ?1")
            .bind(&[normalized_email.into()])
            .map_err(|e| {
                log::error!("{context}: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    context.to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("{context}: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    context.to_string(),
                ))
            })?;

        let user_value = user_value.ok_or_else(not_found)?;

        serde_json::from_value(user_value).map_err(|e| {
            log::error!("{context} deserialize: {e}");
            AppError::Internal
        })
    }
}

fn owner_registration_conflict(message: &str) -> bool {
    message.contains("UNIQUE constraint failed") &&
        (message.contains("index 'users_single_owner'") ||
            message.contains("users.email"))
}

#[cfg(test)]
mod registration_tests {
    use super::owner_registration_conflict;

    #[test]
    fn only_known_owner_uniqueness_conflicts_map_to_initialized() {
        assert!(owner_registration_conflict(
            "D1_ERROR: UNIQUE constraint failed: index 'users_single_owner': \
             SQLITE_CONSTRAINT"
        ));
        assert!(owner_registration_conflict(
            "UNIQUE constraint failed: users.email"
        ));
        for other in [
            "UNIQUE constraint failed: users.id",
            "FOREIGN KEY constraint failed",
            "no such table: users",
            "network unavailable",
        ] {
            assert!(!owner_registration_conflict(other));
        }
    }
}
