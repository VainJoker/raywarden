use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::{
    Deserialize,
    Serialize,
};
use worker::{
    D1Database,
    query,
};

use crate::{
    errors::{
        AppError,
        DatabaseError,
    },
    infra::cryptor::verify_password,
    models::serde_helpers::bool_from_int,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
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

impl User {
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

impl User {
    pub async fn touch_user_updated_at(
        db: &D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        query!(
            db,
            "UPDATE users SET updated_at = ?1 WHERE id = ?2",
            now,
            user_id
        )
        .map_err(|_| {
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to bind query for updating user".to_string(),
            ))
        })?
        .run()
        .await?;
        Ok(())
    }
}
