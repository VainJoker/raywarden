use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
};

use crate::{
    errors::{
        AppError,
        DatabaseError,
    },
    infra::{
        DB,
        cryptor::verify_password,
    },
    models::{
        cipher::{
            CipherData,
            CipherRequestData,
        },
        serde_helpers::bool_from_int,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserDB {
    pub id:                   String,
    pub name:                 Option<String>,
    pub avatar_color:         Option<String>,
    pub email:                String,
    #[serde(with = "bool_from_int")]
    pub email_verified:       bool,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub password_salt:        Option<String>, /* Salt for server-side PBKDF2
                                               * (NULL for legacy users) */
    pub key:                  String,
    pub private_key:          String,
    pub public_key:           String,
    pub kdf_type:             i32,
    pub kdf_iterations:       i32,
    pub kdf_memory:           Option<i32>, /* Argon2 memory parameter
                                            * (15-1024 MB) */
    pub kdf_parallelism:      Option<i32>, /* Argon2 parallelism parameter
                                            * (1-16) */
    pub security_stamp:       String,
    /// JSON string of `Vec<Vec<String>>` storing user-defined equivalent
    /// domain groups.
    #[serde(default = "default_json_array_string")]
    pub equivalent_domains:   String,
    /// JSON string of `Vec<i32>` storing excluded global group IDs (reserved
    /// for future global groups).
    #[serde(default = "default_json_array_string")]
    pub excluded_globals:     String,
    pub totp_recover:         Option<String>, // Recovery code for 2FA
    pub created_at:           String,
    pub updated_at:           String,
}

fn default_json_array_string() -> String {
    "[]".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerification {
    MatchCurrentScheme,
    MatchLegacyScheme,
    Mismatch,
}

impl PasswordVerification {
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::MatchCurrentScheme | Self::MatchLegacyScheme)
    }

    pub const fn needs_migration(&self) -> bool {
        matches!(self, Self::MatchLegacyScheme)
    }
}

impl UserDB {
    pub async fn verify_master_password(
        &self,
        provided_hash: &str,
    ) -> Result<PasswordVerification, AppError> {
        if let Some(ref salt) = self.password_salt {
            let is_valid = verify_password(
                provided_hash,
                &self.master_password_hash,
                salt,
            )
            .await?;
            Ok(if is_valid {
                PasswordVerification::MatchCurrentScheme
            } else {
                PasswordVerification::Mismatch
            })
        } else {
            let is_valid = constant_time_eq(
                self.master_password_hash.as_bytes(),
                provided_hash.as_bytes(),
            );

            Ok(if is_valid {
                PasswordVerification::MatchLegacyScheme
            } else {
                PasswordVerification::Mismatch
            })
        }
    }
}

// For /accounts/prelogin response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf:             i32,
    pub kdf_iterations:  i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory:      Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<i32>,
}

// For /accounts/register request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub name:                 Option<String>,
    pub email:                String,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub user_symmetric_key:   String,
    pub user_asymmetric_keys: KeyData,
    pub kdf:                  i32,
    pub kdf_iterations:       i32,
    pub kdf_memory:           Option<i32>, /* Argon2 memory parameter
                                            * (15-1024 MB) */
    pub kdf_parallelism:      Option<i32>, /* Argon2 parallelism parameter
                                            * (1-16) */
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    pub public_key:            String,
    pub encrypted_private_key: String,
}

/// Request body for password-protected operations (delete account, purge vault,
/// etc.) Supports both master password hash and OTP verification.
/// Note: OTP verification is not implemented in this simplified version.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpData {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    #[allow(dead_code)]
    // OTP verification is not implemented in this simplified version
    pub otp: Option<String>,
}

// For POST /accounts/password request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub key: String,
}

// For POST /accounts/kdf request - Change KDF settings
//
// API Format History:
// - Bitwarden switched to complex format in v2025.10.0
// - Vaultwarden followed in PR #6458, WITHOUT backward compatibility
// - We implement backward compatibility to support both formats
//
// Supports two formats:
//
// 1. Simple/Legacy format (Bitwarden < v2025.10.0, e.g. web vault 2025.07):
// {
//   "kdf": 0,
//   "kdfIterations": 650000,
//   "kdfMemory": null,
//   "kdfParallelism": null,
//   "key": "...",
//   "masterPasswordHash": "...",
//   "newMasterPasswordHash": "..."
// }
//
// 2. Complex format (Bitwarden >= v2025.10.0, e.g. official client 2025.11.x):
// {
//   "authenticationData": { "kdf": {...}, "masterPasswordAuthenticationHash":
// "...", "salt": "..." },   "unlockData": { "kdf": {...},
// "masterKeyWrappedUserKey": "...", "salt": "..." },   "key": "...",
//   "masterPasswordHash": "...",
//   "newMasterPasswordHash": "..."
// }

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    #[serde(alias = "kdfType")]
    pub kdf_type:    i32,
    pub iterations:  i32,
    pub memory:      Option<i32>,
    pub parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationData {
    pub salt: String,
    pub kdf: KdfParams,
    pub master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockData {
    pub salt: String,
    pub kdf: KdfParams,
    pub master_key_wrapped_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfRequest {
    // Common fields (both formats)
    pub key: String,
    pub master_password_hash: String,
    pub new_master_password_hash: String,

    // Simple format fields (optional)
    pub kdf:             Option<i32>,
    pub kdf_iterations:  Option<i32>,
    pub kdf_memory:      Option<i32>,
    pub kdf_parallelism: Option<i32>,

    // Complex format fields (optional)
    pub authentication_data: Option<AuthenticationData>,
    pub unlock_data:         Option<UnlockData>,
}

impl ChangeKdfRequest {
    /// Extract KDF parameters from either simple or complex format
    pub const fn get_kdf_params(
        &self,
    ) -> Option<(i32, i32, Option<i32>, Option<i32>)> {
        // Try complex format first (unlock_data takes precedence)
        if let Some(ref unlock_data) = self.unlock_data {
            return Some((
                unlock_data.kdf.kdf_type,
                unlock_data.kdf.iterations,
                unlock_data.kdf.memory,
                unlock_data.kdf.parallelism,
            ));
        }

        // Fall back to simple format
        if let (Some(kdf), Some(iterations)) = (self.kdf, self.kdf_iterations) {
            return Some((
                kdf,
                iterations,
                self.kdf_memory,
                self.kdf_parallelism,
            ));
        }

        None
    }

    /// Get the new password hash to store (from `authentication_data` if
    /// available)
    pub fn get_new_password_hash(&self) -> &str {
        if let Some(ref auth_data) = self.authentication_data {
            &auth_data.master_password_authentication_hash
        } else {
            &self.new_master_password_hash
        }
    }

    /// Get the new encrypted user key (from `unlock_data` if available, else
    /// from key)
    pub fn get_new_key(&self) -> &str {
        if let Some(ref unlock_data) = self.unlock_data {
            &unlock_data.master_key_wrapped_user_key
        } else {
            &self.key
        }
    }
}

// For POST /accounts/key-management/rotate-user-account-keys request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateKeyRequest {
    pub account_unlock_data: RotateAccountUnlockData,
    pub account_keys: RotateAccountKeys,
    pub account_data: RotateAccountData,
    pub old_master_key_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountUnlockData {
    pub master_password_unlock_data: MasterPasswordUnlockData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlockData {
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_parallelism: Option<i32>,
    pub kdf_memory: Option<i32>,
    pub email: String,
    pub master_key_authentication_hash: String,
    pub master_key_encrypted_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountKeys {
    pub user_key_encrypted_account_private_key: String,
    pub account_public_key:                     String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountData {
    pub ciphers: Vec<crate::models::cipher::CipherRequestData>,
    pub folders: Vec<RotateFolderData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateFolderData {
    // There is a bug in 2024.3.x which adds a `null` item.
    // To bypass this we allow an Option here, but skip it during the updates
    // See: https://github.com/bitwarden/clients/issues/8453
    pub id:   Option<String>,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileData {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarData {
    pub avatar_color: Option<String>,
}

impl UserDB {
    pub async fn touch_user_updated_at(
        db: &D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        Self::set_updated_at(db, user_id, &now).await
    }

    pub async fn set_updated_at(
        db: &D1Database,
        user_id: &str,
        updated_at: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET updated_at = ?1 WHERE id = ?2",
                    updated_at,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update user",
        )
        .await
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
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(&ts).ok())
            .map_or_else(
                || chrono::Utc::now().timestamp_millis(),
                |dt| dt.timestamp_millis(),
            );

        Ok(revision_date)
    }

    pub async fn migrate_legacy_password(
        db: &D1Database,
        user_id: &str,
        new_hash: &str,
        new_salt: &str,
        updated_at: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET master_password_hash = ?1, \
                     password_salt = ?2, updated_at = ?3 WHERE id = ?4",
                    new_hash,
                    new_salt,
                    updated_at,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to migrate legacy password",
        )
        .await
    }

    pub async fn clear_recovery_code(
        db: &D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
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
        DB::run_query(
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
        DB::run_query(
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
        DB::run_query(
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
        DB::run_query(
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

    /// Update master password, salt, key, hint, and security stamp.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_master_password(
        db: &D1Database,
        user_id: &str,
        new_hashed_password: &str,
        new_salt: &str,
        new_key: &str,
        master_password_hint: &Option<String>,
        new_security_stamp: &str,
        updated_at: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET master_password_hash = ?1, \
                     password_salt = ?2, key = ?3, master_password_hint = ?4, \
                     security_stamp = ?5, updated_at = ?6 WHERE id = ?7",
                    new_hashed_password,
                    new_salt,
                    new_key,
                    master_password_hint,
                    new_security_stamp,
                    updated_at,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update master password",
        )
        .await
    }

    /// Validate that rotation input matches DB state (counts and IDs).
    pub async fn validate_rotation_state(
        db: &D1Database,
        user_id: &str,
        cipher_ids_json: &str,
        folder_ids_json: &str,
    ) -> Result<(), AppError> {
        let results = db
            .batch(vec![
                db.prepare(
                    "SELECT COUNT(*) AS cnt FROM ciphers WHERE user_id = ?1 \
                     AND organization_id IS NULL",
                )
                .bind(&[user_id.to_string().into()])?,
                db.prepare(
                    "SELECT COUNT(*) AS cnt FROM folders WHERE user_id = ?1",
                )
                .bind(&[user_id.to_string().into()])?,
                db.prepare(
                    "SELECT id FROM ciphers WHERE user_id = ?1 AND \
                     organization_id IS NULL
                     EXCEPT
                     SELECT value FROM json_each(?2) LIMIT 1",
                )
                .bind(&[
                    user_id.to_string().into(),
                    cipher_ids_json.to_string().into(),
                ])?,
                db.prepare(
                    "SELECT id FROM folders WHERE user_id = ?1
                     EXCEPT
                     SELECT value FROM json_each(?2) LIMIT 1",
                )
                .bind(&[
                    user_id.to_string().into(),
                    folder_ids_json.to_string().into(),
                ])?,
            ])
            .await?;

        let db_cipher_count = results[0]
            .results::<Value>()?
            .first()
            .and_then(|v| v.get("cnt")?.as_i64())
            .unwrap_or(0) as usize;
        let db_folder_count = results[1]
            .results::<Value>()?
            .first()
            .and_then(|v| v.get("cnt")?.as_i64())
            .unwrap_or(0) as usize;

        let request_cipher_ids: Value =
            serde_json::from_str(cipher_ids_json).unwrap_or_default();
        let request_folder_ids: Value =
            serde_json::from_str(folder_ids_json).unwrap_or_default();
        let request_cipher_count =
            request_cipher_ids.as_array().map_or(0, Vec::len);
        let request_folder_count =
            request_folder_ids.as_array().map_or(0, Vec::len);

        if db_cipher_count != request_cipher_count ||
            db_folder_count != request_folder_count
        {
            log::error!(
                "Cipher or folder count mismatch in rotation request: \
                 {db_cipher_count} != {request_cipher_count} or \
                 {db_folder_count} != {request_folder_count}"
            );
            return Err(AppError::Params(
                "All existing ciphers and folders must be included in the \
                 rotation"
                    .to_string(),
            ));
        }

        let has_missing_ciphers = !results[2].results::<Value>()?.is_empty();
        let has_missing_folders = !results[3].results::<Value>()?.is_empty();

        if has_missing_ciphers || has_missing_folders {
            log::error!(
                "Missing ciphers or folders in rotation request: \
                 {has_missing_ciphers:?} or {has_missing_folders:?}"
            );
            return Err(AppError::Params(
                "All existing ciphers and folders must be included in the \
                 rotation"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Apply folder updates during account key rotation.
    pub async fn rotate_folders(
        db: &D1Database,
        user_id: &str,
        folders: &[RotateFolderData],
        updated_at: &str,
        batch_size: usize,
    ) -> Result<(), AppError> {
        let mut statements: Vec<D1PreparedStatement> =
            Vec::with_capacity(folders.len());

        for folder in folders {
            let Some(folder_id) = &folder.id else {
                continue;
            };
            let stmt = query!(
                db,
                "UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 \
                 AND user_id = ?4",
                folder.name,
                updated_at,
                folder_id,
                user_id
            )
            .map_err(|e| {
                log::error!(
                    "Database error updating folder during rotation: {e}"
                );
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to update folder during rotation".to_string(),
                ))
            })?;
            statements.push(stmt);
        }

        if batch_size == 0 {
            db.batch(statements).await?;
        } else {
            for chunk in statements.chunks(batch_size) {
                db.batch(chunk.to_vec()).await?;
            }
        }

        Ok(())
    }

    /// Apply cipher data updates during account key rotation (personal ciphers
    /// only).
    pub async fn rotate_personal_ciphers(
        db: &D1Database,
        user_id: &str,
        ciphers: &[CipherRequestData],
        updated_at: &str,
        batch_size: usize,
    ) -> Result<(), AppError> {
        let mut statements: Vec<D1PreparedStatement> =
            Vec::with_capacity(ciphers.len());

        for cipher in ciphers {
            let Some(cipher_id) = &cipher.id else {
                log::error!("Cipher id missing during rotation");
                return Err(AppError::Params(
                    "All ciphers must have an id for key rotation".to_string(),
                ));
            };

            let cipher_data = CipherData {
                name:        cipher.name.clone(),
                notes:       cipher.notes.clone(),
                type_fields: cipher.type_fields.clone(),
            };

            let data = serde_json::to_string(&cipher_data).map_err(|e| {
                log::error!("Error serializing cipher data for rotation: {e}");
                AppError::Internal
            })?;

            let stmt = query!(
                db,
                "UPDATE ciphers SET data = ?1, folder_id = ?2, favorite = ?3, \
                 updated_at = ?4 WHERE id = ?5 AND user_id = ?6",
                data,
                cipher.folder_id,
                cipher.favorite.unwrap_or(false),
                updated_at,
                cipher_id,
                user_id
            )
            .map_err(|e| {
                log::error!(
                    "Database error updating cipher during rotation: {e}"
                );
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to update cipher during rotation".to_string(),
                ))
            })?;
            statements.push(stmt);
        }

        if batch_size == 0 {
            db.batch(statements).await?;
        } else {
            for chunk in statements.chunks(batch_size) {
                db.batch(chunk.to_vec()).await?;
            }
        }

        Ok(())
    }

    /// Update user keys and password fields after rotation.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_account_keys_after_rotation(
        db: &D1Database,
        user_id: &str,
        new_hashed_password: &str,
        new_salt: &str,
        master_key_encrypted_user_key: &str,
        user_key_encrypted_account_private_key: &str,
        kdf_type: i32,
        kdf_iterations: i32,
        kdf_memory: Option<i32>,
        kdf_parallelism: Option<i32>,
        new_security_stamp: &str,
        updated_at: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET master_password_hash = ?1, \
                     password_salt = ?2, key = ?3, private_key = ?4, kdf_type \
                     = ?5, kdf_iterations = ?6, kdf_memory = ?7, \
                     kdf_parallelism = ?8, security_stamp = ?9, updated_at = \
                     ?10 WHERE id = ?11",
                    new_hashed_password,
                    new_salt,
                    master_key_encrypted_user_key,
                    user_key_encrypted_account_private_key,
                    kdf_type,
                    kdf_iterations,
                    kdf_memory,
                    kdf_parallelism,
                    new_security_stamp,
                    updated_at,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update user account keys",
        )
        .await
    }

    /// Update user KDF settings and security stamp.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_kdf_settings(
        db: &D1Database,
        user_id: &str,
        new_hashed_password: &str,
        new_salt: &str,
        new_key: &str,
        kdf_type: i32,
        kdf_iterations: i32,
        kdf_memory: Option<i32>,
        kdf_parallelism: Option<i32>,
        new_security_stamp: &str,
        updated_at: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET master_password_hash = ?1, \
                     password_salt = ?2, key = ?3, kdf_type = ?4, \
                     kdf_iterations = ?5, kdf_memory = ?6, kdf_parallelism = \
                     ?7, security_stamp = ?8, updated_at = ?9 WHERE id = ?10",
                    new_hashed_password,
                    new_salt,
                    new_key,
                    kdf_type,
                    kdf_iterations,
                    kdf_memory,
                    kdf_parallelism,
                    new_security_stamp,
                    updated_at,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update KDF settings",
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
        let normalized_email = email.to_lowercase();
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
