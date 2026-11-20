//! Persisted accounts, credential values and guarded database operations.
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use worker::{
    D1Database,
    query,
    wasm_bindgen::JsValue,
};

use crate::{
    errors::{
        AppError,
        AppResult,
        DatabaseError,
    },
    infra::db,
    models::{
        identity::{
            account_keys,
            device::{
                PushDeviceRow,
                PushStore,
                SessionSnapshot,
            },
        },
        mutation::NEXT_USER_REVISION_SQL,
    },
    utils::serde::bool_from_int,
};

/// The complete server-side verifier persisted as one credential value.
pub struct StoredPassword {
    pub hash:       String,
    pub salt:       String,
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

#[allow(
    clippy::struct_field_names,
    reason = "Persisted query fields use the exact SQL KDF column names"
)]
pub struct UserKdfParams {
    pub kdf_type:        Option<i32>,
    pub kdf_iterations:  Option<i32>,
    pub kdf_memory:      Option<i32>,
    pub kdf_parallelism: Option<i32>,
}

/// Concrete values written by initial-password persistence after service
/// validation.
pub struct PasswordInitialization<'a> {
    pub key:             &'a str,
    pub private_key:     &'a str,
    pub public_key:      &'a str,
    pub hint:            Option<&'a str>,
    pub kdf_type:        i32,
    pub kdf_iterations:  i32,
    pub kdf_memory:      Option<i32>,
    pub kdf_parallelism: Option<i32>,
}

impl UserRow {
    #[allow(
        clippy::too_many_lines,
        reason = "Keep the credential CAS and capability cleanup visible as \
                  one atomic transaction"
    )]
    pub async fn initialize_password_if_current(
        db: &D1Database,
        user: &Self,
        session: &SessionSnapshot<'_>,
        initialization: &PasswordInitialization<'_>,
        password: &StoredPassword,
    ) -> AppResult<()> {
        if user.id != session.user_id {
            return Err(AppError::conflict(
                "Account does not match the session",
            ));
        }
        let now = crate::utils::time::now_rfc3339();
        let token = uuid::Uuid::new_v4().to_string();
        let revision_sql = crate::models::mutation::next_user_revision_sql(13);
        let sql = format!(
            "UPDATE users SET \
             master_password_hash=?1,password_salt=?2,password_iterations=?3,\
             key=?4,private_key=?5,public_key=?6,master_password_hint=?7,\
             kdf_type=?8,kdf_iterations=?9,kdf_memory=?10,kdf_parallelism=?11,\
             account_write_token=?12,v2_upgrade_token=NULL,\
             security_stamp_exceptions=NULL,updated_at={revision_sql} WHERE \
             id=?14 AND security_stamp=?15 AND master_password_hash='' AND \
             private_key='' AND password_salt IS ?16 AND \
             password_iterations=?17 AND ({}) AND kdf_type=?21 AND \
             kdf_iterations=?22 AND kdf_memory IS ?23 AND kdf_parallelism IS \
             ?24 AND EXISTS(SELECT 1 FROM devices WHERE user_id=?14 AND \
             device_id=?19 AND session_token=?20) RETURNING id",
            account_keys::AccountSnapshot::matches_sql(18),
        );
        let claim = db.prepare(sql).bind(&[
            password.hash.clone().into(),
            password.salt.clone().into(),
            password.iterations.into(),
            initialization.key.into(),
            initialization.private_key.into(),
            initialization.public_key.into(),
            initialization.hint.map_or(JsValue::NULL, Into::into),
            initialization.kdf_type.into(),
            initialization.kdf_iterations.into(),
            initialization.kdf_memory.map_or(JsValue::NULL, Into::into),
            initialization
                .kdf_parallelism
                .map_or(JsValue::NULL, Into::into),
            token.clone().into(),
            now.clone().into(),
            user.id.clone().into(),
            session.security_stamp.into(),
            user.password_salt.clone().map_or(JsValue::NULL, Into::into),
            user.password_iterations.into(),
            account_keys::AccountSnapshot::from_user(user)
                .to_json()?
                .into(),
            session.device_id.into(),
            session.session_token.into(),
            user.kdf_type.into(),
            user.kdf_iterations.into(),
            user.kdf_memory.map_or(JsValue::NULL, Into::into),
            user.kdf_parallelism.map_or(JsValue::NULL, Into::into),
        ])?;
        let results = db::run_query(
            async {
                db.batch(vec![
                    claim,
                    query!(
                        db,
                        "DELETE FROM two_factors WHERE user_id=?1 AND \
                         provider_type=5 AND EXISTS(SELECT 1 FROM users WHERE \
                         id=?1 AND account_write_token=?2)",
                        user.id,
                        token
                    )?,
                    query!(
                        db,
                        "DELETE FROM auth_requests WHERE user_id=?1 AND \
                         EXISTS(SELECT 1 FROM users WHERE id=?1 AND \
                         account_write_token=?2)",
                        user.id,
                        token
                    )?,
                    query!(
                        db,
                        "UPDATE webauthn_credentials SET \
                         encrypted_public_key=NULL,encrypted_user_key=NULL,\
                         encrypted_private_key=NULL,account_snapshot=NULL,\
                         prf_status=CASE WHEN prf_status=0 THEN 1 ELSE \
                         prf_status END,updated_at=?1 WHERE user_id=?2 AND \
                         EXISTS(SELECT 1 FROM users WHERE id=?2 AND \
                         account_write_token=?3)",
                        now,
                        user.id,
                        token
                    )?,
                ])
                .await
            },
            "Failed to initialize account password",
        )
        .await?;
        if results
            .first()
            .ok_or(AppError::Internal)?
            .results::<Value>()?
            .is_empty()
        {
            return Err(AppError::conflict(
                "Account or session changed; cannot set password",
            ));
        }
        Ok(())
    }

    pub async fn has_available_email(
        db: &D1Database,
        emails: &[String],
    ) -> AppResult<bool> {
        let emails_json =
            serde_json::to_string(emails).map_err(AppError::internal_error)?;
        let found: Option<i64> = db::run_query(
            async {
                db.prepare(
                    "SELECT 1 AS present FROM json_each(?1) AS allowed WHERE \
                     NOT EXISTS (SELECT 1 FROM users WHERE \
                     email=allowed.value) LIMIT 1",
                )
                .bind(&[emails_json.into()])?
                .first(Some("present"))
                .await
            },
            "Failed to check available account emails",
        )
        .await?;
        Ok(found.is_some())
    }

    pub async fn kdf_params_by_email(
        db: &D1Database,
        email: &str,
    ) -> AppResult<Option<UserKdfParams>> {
        let stmt = db.prepare(
            "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism \
             FROM users WHERE email = ?1",
        );
        let query = stmt.bind(&[email.into()])?;

        let row: Option<Value> = query.first(None).await.map_err(|e| {
            DatabaseError::query("get_kdf_params_by_email query failed", e)
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

            Ok(Some(UserKdfParams {
                kdf_type,
                kdf_iterations,
                kdf_memory,
                kdf_parallelism,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn insert(db: &D1Database, user: &Self) -> AppResult<()> {
        let result = async {
            query!(
                db,
                "INSERT INTO users (id, name, email, master_password_hash, \
                 master_password_hint, password_salt, key, private_key, \
                 public_key, kdf_type, kdf_iterations, kdf_memory, \
                 kdf_parallelism, security_stamp, equivalent_domains, \
                 excluded_globals,two_factor_recovery_code, created_at, \
                 updated_at, is_email_verified, user_key_id, \
                 signed_public_key, security_state, security_version, \
                 signature_key_pair, password_iterations) VALUES (?1, ?2, ?3, \
                 ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
                 ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
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
            )?
            .run()
            .await
        }
        .await;
        result.map(|_| ()).map_err(DatabaseError::registration)
    }

    pub async fn revision_date(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<Option<String>> {
        let updated_at: Option<String> = db
            .prepare("SELECT updated_at FROM users WHERE id = ?1")
            .bind(&[user_id.into()])
            .map_err(|e| {
                DatabaseError::query("Database error fetching revision date", e)
            })?
            .first(Some("updated_at"))
            .await
            .map_err(|e| {
                DatabaseError::query("Database error fetching revision date", e)
            })?;

        Ok(updated_at)
    }

    pub async fn migrate_password_if_current(
        db: &D1Database,
        user: &Self,
        replacement: &StoredPassword,
    ) -> AppResult<()> {
        let sql = format!(
            "UPDATE users SET \
             master_password_hash=?1,password_salt=?2,password_iterations=?3 \
             WHERE id=?4 AND master_password_hash=?5 AND password_salt IS ?6 \
             AND password_iterations=?7 AND security_stamp=?8 AND ({}) \
             RETURNING id",
            account_keys::AccountSnapshot::matches_sql(9)
        );
        let row: Option<String> = db::run_query(
            async {
                db.prepare(&sql)
                    .bind(&[
                        replacement.hash.clone().into(),
                        replacement.salt.clone().into(),
                        replacement.iterations.into(),
                        user.id.clone().into(),
                        user.master_password_hash.clone().into(),
                        user.password_salt
                            .clone()
                            .map_or(JsValue::NULL, Into::into),
                        user.password_iterations.into(),
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

    /// Update a user's display name and revision timestamp.
    pub async fn update_profile_name(
        db: &D1Database,
        user_id: &str,
        name: Option<&str>,
        updated_at: &str,
    ) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    format!(
                        "UPDATE users SET name = ?3, updated_at = \
                         {NEXT_USER_REVISION_SQL} WHERE id = ?2"
                    ),
                    updated_at,
                    user_id,
                    name
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
        avatar_color: Option<&str>,
        updated_at: &str,
    ) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    format!(
                        "UPDATE users SET avatar_color = ?3, updated_at = \
                         {NEXT_USER_REVISION_SQL} WHERE id = ?2"
                    ),
                    updated_at,
                    user_id,
                    avatar_color
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update user avatar",
        )
        .await
    }

    /// Capture registrations before the same transaction deletes the account
    /// and cascades to its devices.
    pub async fn delete_user(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<Option<Vec<PushDeviceRow>>> {
        let results = db::run_query(
            async {
                db.batch(vec![
                    PushStore::list_for_user_statement(db, user_id)?,
                    query!(
                        db,
                        "DELETE FROM users WHERE id = ?1 RETURNING id",
                        user_id
                    )?,
                ])
                .await
            },
            "Failed to delete user",
        )
        .await?;
        let [devices, deletion] = results.as_slice() else {
            return Err(AppError::Internal);
        };
        if deletion.results::<Value>()?.is_empty() {
            return Ok(None);
        }
        let devices = db::decode_results(devices).unwrap_or_else(|error| {
            log::warn!(
                "Deleted user push devices could not be decoded: {error}"
            );
            Vec::new()
        });
        Ok(Some(devices))
    }

    /// Fetch a user by id with consistent error mapping and not-found handling.
    pub async fn fetch_by_id_with<F>(
        db: &D1Database,
        user_id: &str,
        context: &str,
        not_found: F,
    ) -> AppResult<Self>
    where
        F: FnOnce() -> AppError,
    {
        let user_value: Option<Value> = db
            .prepare("SELECT * FROM users WHERE id = ?1")
            .bind(&[user_id.into()])
            .map_err(|e| DatabaseError::query(context, e))?
            .first(None)
            .await
            .map_err(|e| DatabaseError::query(context, e))?;

        let user_value = user_value.ok_or_else(not_found)?;

        serde_json::from_value(user_value).map_err(|error| {
            DatabaseError::invalid_result(
                format_args!("{context} deserialize"),
                error,
            )
        })
    }

    /// Fetch a user by an already normalized email with consistent error
    /// mapping.
    pub async fn fetch_by_email_with<F>(
        db: &D1Database,
        email: &str,
        context: &str,
        not_found: F,
    ) -> AppResult<Self>
    where
        F: FnOnce() -> AppError,
    {
        let user_value: Option<Value> = db
            .prepare("SELECT * FROM users WHERE email = ?1")
            .bind(&[email.into()])
            .map_err(|e| DatabaseError::query(context, e))?
            .first(None)
            .await
            .map_err(|e| DatabaseError::query(context, e))?;

        let user_value = user_value.ok_or_else(not_found)?;

        serde_json::from_value(user_value).map_err(|error| {
            DatabaseError::invalid_result(
                format_args!("{context} deserialize"),
                error,
            )
        })
    }
}
