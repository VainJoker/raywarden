//! Persisted accounts, credential values and guarded database operations.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::{D1Database, D1PreparedStatement, query};

use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
    models::{
        identity::{
            account_keys,
            authorization::VerifiedAccountAction,
            device::SessionSnapshot,
            email::{VerifiedCode, require_changed_row},
        },
        mutation::{NEXT_USER_REVISION_SQL, RevisionRow},
    },
    utils::serde::bool_from_int,
};

/// The complete server-side verifier persisted as one credential value.
pub struct StoredPassword {
    pub hash: String,
    pub salt: String,
    pub iterations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRow {
    pub id: String,
    pub name: Option<String>,
    pub avatar_color: Option<String>,
    pub email: String,
    #[serde(with = "bool_from_int")]
    pub is_email_verified: bool,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub password_salt: Option<String>, /* Salt for server-side PBKDF2
                                        * (NULL for legacy users) */
    #[serde(default = "legacy_password_iterations")]
    pub password_iterations: u32,
    pub key: String,
    pub private_key: String,
    pub public_key: String,
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>, /* Argon2 memory parameter
                                  * (15-1024 MB) */
    pub kdf_parallelism: Option<i32>, /* Argon2 parallelism parameter
                                       * (1-16) */
    #[serde(default)]
    pub user_key_id: Option<String>,
    #[serde(default)]
    pub signed_public_key: Option<String>,
    #[serde(default)]
    pub security_state: Option<String>,
    #[serde(default)]
    pub security_version: Option<i32>,
    #[serde(default)]
    pub signature_key_pair: Option<String>,
    #[serde(default)]
    pub v2_upgrade_token: Option<String>,
    #[serde(default)]
    pub security_stamp_exceptions: Option<String>,
    pub security_stamp: String,
    /// JSON string of `Vec<Vec<String>>` storing user-defined equivalent
    /// domain groups.
    #[serde(default = "default_json_array_string")]
    pub equivalent_domains: String,
    /// JSON string of `Vec<i32>` storing excluded global group IDs (reserved
    /// for future global groups).
    #[serde(default = "default_json_array_string")]
    pub excluded_globals: String,
    pub two_factor_recovery_code: Option<String>, // Recovery code for 2FA
    pub created_at: String,
    pub updated_at: String,
}

fn default_json_array_string() -> String {
    "[]".to_string()
}

const fn legacy_password_iterations() -> u32 {
    100_000
}

#[derive(Deserialize)]
#[allow(
    clippy::struct_field_names,
    reason = "Persisted query fields use the exact SQL KDF column names"
)]
pub struct UserKdfParams {
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
}

impl UserRow {
    pub async fn has_available_email(db: &D1Database, emails: &[String]) -> AppResult<bool> {
        let emails_json = serde_json::to_string(emails).map_err(AppError::internal_json(
            "Failed to serialize allowed email list",
        ))?;
        let found: Option<i64> = db::query_first(
            db.prepare(
                "SELECT 1 AS present FROM json_each(?1) AS allowed WHERE \
                 NOT EXISTS (SELECT 1 FROM users WHERE \
                 email=allowed.value) LIMIT 1",
            )
            .bind(&db::d1_params![emails_json]),
            Some("present"),
            "Failed to check available account emails",
        )
        .await?;
        Ok(found.is_some())
    }

    pub async fn kdf_params_by_email(
        db: &D1Database,
        email: &str,
    ) -> AppResult<Option<UserKdfParams>> {
        let row: Option<Value> = db::query_first(
            db.prepare(
                "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism \
                 FROM users WHERE email = ?1",
            )
            .bind(&db::d1_params![email]),
            None,
            "Failed to fetch KDF settings",
        )
        .await?;
        row.map(|row| db::decode_row(row, "Failed to decode stored KDF settings"))
            .transpose()
    }

    pub(crate) async fn insert(
        db: &D1Database,
        user: &Self,
        verification: Option<&VerifiedCode>,
    ) -> AppResult<()> {
        let insert = Self::insert_statement(db, user)
            .map_err(|error| DatabaseError::registration(&error))?;
        if let Some(verification) = verification {
            return VerifiedCode::commit(
                db,
                [verification],
                vec![
                    insert,
                    require_changed_row(db, DbSentinel::RegistrationInsertFailed)?,
                ],
                |error| DatabaseError::registration(&error),
            )
            .await;
        }
        insert
            .run()
            .await
            .map(|_| ())
            .map_err(|error| DatabaseError::registration(&error))
    }

    fn insert_statement(db: &D1Database, user: &Self) -> worker::Result<D1PreparedStatement> {
        query!(
            db,
            "INSERT INTO users (id, name, email, master_password_hash, \
             master_password_hint, password_salt, key, private_key, \
             public_key, kdf_type, kdf_iterations, kdf_memory, \
             kdf_parallelism, security_stamp, equivalent_domains, \
             excluded_globals,two_factor_recovery_code, created_at, \
             updated_at, is_email_verified, user_key_id, signed_public_key, \
             security_state, security_version, signature_key_pair, \
             password_iterations) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, \
             ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, \
             ?23, ?24, ?25, ?26)",
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
            user.two_factor_recovery_code,
            user.created_at,
            user.updated_at,
            i32::from(user.is_email_verified),
            user.user_key_id,
            user.signed_public_key,
            user.security_state,
            user.security_version,
            user.signature_key_pair,
            user.password_iterations
        )
    }

    pub async fn revision_date(db: &D1Database, user_id: &str) -> AppResult<Option<String>> {
        db::query_first(
            db.prepare("SELECT updated_at FROM users WHERE id = ?1")
                .bind(&db::d1_params![user_id]),
            Some("updated_at"),
            "Database error fetching revision date",
        )
        .await
    }

    pub(super) fn migrate_password_statement(
        db: &D1Database,
        user: &Self,
        replacement: &StoredPassword,
    ) -> worker::Result<D1PreparedStatement> {
        let sql = format!(
            "UPDATE users SET \
             master_password_hash=?1,password_salt=?2,password_iterations=?3 \
             WHERE id=?4 AND master_password_hash=?5 AND password_salt IS ?6 \
             AND password_iterations=?7 AND security_stamp=?8 AND ({}) \
             RETURNING id",
            account_keys::AccountSnapshot::matches_sql(9)
        );
        db.prepare(&sql).bind(&db::d1_params![
            replacement.hash,
            replacement.salt,
            replacement.iterations,
            user.id,
            user.master_password_hash,
            user.password_salt,
            user.password_iterations,
            user.security_stamp,
            account_keys::AccountSnapshot::json_from_user(user).map_err(worker::Error::from)?,
        ])
    }

    /// Update a user's display name and revision timestamp.
    pub async fn update_profile_name(
        db: &D1Database,
        session: &SessionSnapshot<'_>,
        name: Option<&str>,
        updated_at: &str,
    ) -> AppResult<String> {
        Self::update_profile_field(
            db,
            session,
            "name",
            name,
            updated_at,
            "Failed to update user profile",
        )
        .await
    }

    /// Update a user's avatar color and revision timestamp.
    pub async fn update_avatar_color(
        db: &D1Database,
        session: &SessionSnapshot<'_>,
        avatar_color: Option<&str>,
        updated_at: &str,
    ) -> AppResult<String> {
        Self::update_profile_field(
            db,
            session,
            "avatar_color",
            avatar_color,
            updated_at,
            "Failed to update user avatar",
        )
        .await
    }

    async fn update_profile_field(
        db: &D1Database,
        session: &SessionSnapshot<'_>,
        column: &'static str,
        value: Option<&str>,
        updated_at: &str,
        context: &'static str,
    ) -> AppResult<String> {
        let statement = query!(
            db,
            format!(
                "UPDATE users SET {column} = ?3, updated_at = \
                 {NEXT_USER_REVISION_SQL} WHERE id = ?2 RETURNING updated_at"
            ),
            updated_at,
            session.user_id,
            value
        )?;
        let results = db
            .batch(vec![
                super::authorization::session_guard(db, session)?,
                statement,
            ])
            .await
            .map_err(|error| super::authorization::map_session_write_error(context, &error))?;
        results
            .last()
            .ok_or_else(|| AppError::internal("Missing profile update batch result"))?
            .results::<RevisionRow>()?
            .into_iter()
            .next()
            .map(|row| row.updated_at)
            .ok_or_else(|| AppError::internal("Missing updated profile revision row"))
    }

    pub(crate) async fn delete_user(
        db: &D1Database,
        authorization: &VerifiedAccountAction<'_>,
    ) -> AppResult<()> {
        let id = authorization.session.user_id;
        authorization
            .commit(
                db,
                vec![
                    query!(db, "DELETE FROM users WHERE id = ?1 RETURNING id", id)?,
                    require_changed_row(db, DbSentinel::VaultWriteConflict)?,
                ],
                "Failed to delete user",
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn delete_user_with_email(
        db: &D1Database,
        user: &Self,
        verification: &VerifiedCode,
    ) -> AppResult<()> {
        VerifiedCode::commit(
            db,
            [verification],
            vec![
                query!(
                    db,
                    "DELETE FROM users WHERE id=?1 AND email=?2 AND security_stamp=?3 RETURNING id",
                    user.id,
                    user.email,
                    user.security_stamp
                )?,
                require_changed_row(db, DbSentinel::InvalidVerification)?,
            ],
            |error| DatabaseError::query("Failed to delete user", &error),
        )
        .await
    }

    /// Fetch a user by id with consistent error mapping and not-found handling.
    pub async fn fetch_by_id_with<F>(
        db: &D1Database,
        user_id: &str,
        context: &'static str,
        not_found: F,
    ) -> AppResult<Self>
    where
        F: FnOnce() -> AppError,
    {
        Self::fetch_where(
            db,
            "SELECT * FROM users WHERE id = ?1",
            user_id,
            context,
            not_found,
        )
        .await
    }

    /// Fetch a user by an already normalized email with consistent error
    /// mapping.
    pub async fn fetch_by_email_with<F>(
        db: &D1Database,
        email: &str,
        context: &'static str,
        not_found: F,
    ) -> AppResult<Self>
    where
        F: FnOnce() -> AppError,
    {
        Self::fetch_where(
            db,
            "SELECT * FROM users WHERE email = ?1",
            email,
            context,
            not_found,
        )
        .await
    }

    async fn fetch_where<F>(
        db: &D1Database,
        sql: &str,
        key: &str,
        context: &'static str,
        not_found: F,
    ) -> AppResult<Self>
    where
        F: FnOnce() -> AppError,
    {
        let user_value: Option<Value> =
            db::query_first(db.prepare(sql).bind(&db::d1_params![key]), None, context).await?;
        db::decode_row(user_value.ok_or_else(not_found)?, context)
    }
}
