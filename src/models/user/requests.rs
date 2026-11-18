use serde::{
    Deserialize,
    Serialize,
};

use crate::models::account_keys;

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
    pub kdf_settings:    KdfParams,
    pub salt:            String,
}

// For /accounts/register request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(try_from = "RegisterPayload")]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub email: String,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub user_symmetric_key: String,
    pub user_asymmetric_keys: KeyData,
    pub account_keys: account_keys::ValidatedAccountKeys,
    pub user_key_id: Option<String>,
    pub email_verification_token: Option<String>,
    pub kdf: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>, /* Argon2 memory parameter
                                  * (15-1024 MB) */
    pub kdf_parallelism: Option<i32>, /* Argon2 parallelism parameter
                                       * (1-16) */
}

// Accept both the original registration and the separate authentication/unlock
// payload used by newer clients, normalizing both to one internal model.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPayload {
    name:                     Option<String>,
    email:                    String,
    master_password_hint:     Option<String>,
    #[serde(alias = "keys")]
    user_asymmetric_keys:     Option<KeyData>,
    account_keys:             Option<account_keys::AccountKeysData>,
    #[serde(alias = "token")]
    email_verification_token: Option<String>,
    #[serde(flatten)]
    credentials:              RegisterCredentials,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RegisterCredentials {
    Current {
        #[serde(
            rename = "masterPasswordAuthentication",
            alias = "MasterPasswordAuthentication"
        )]
        authentication: RegisterAuthentication,
        #[serde(
            rename = "masterPasswordUnlock",
            alias = "MasterPasswordUnlock"
        )]
        unlock:         RegisterUnlock,
    },
    Legacy {
        #[serde(rename = "masterPasswordHash")]
        hash:        String,
        #[serde(rename = "userSymmetricKey", alias = "key")]
        key:         String,
        kdf:         i32,
        #[serde(rename = "kdfIterations")]
        iterations:  i32,
        #[serde(rename = "kdfMemory")]
        memory:      Option<i32>,
        #[serde(rename = "kdfParallelism")]
        parallelism: Option<i32>,
    },
}

#[derive(Deserialize)]
struct RegisterAuthentication {
    #[serde(alias = "Kdf")]
    kdf:  KdfParams,
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(
        alias = "masterPasswordAuthenticationHash",
        alias = "MasterPasswordAuthenticationHash"
    )]
    hash: String,
}

#[derive(Deserialize)]
struct RegisterUnlock {
    #[serde(alias = "Kdf")]
    kdf:              KdfParams,
    salt:             String,
    #[serde(
        alias = "masterKeyWrappedUserKey",
        alias = "MasterKeyWrappedUserKey"
    )]
    key:              String,
    #[serde(rename = "containedKeyId")]
    contained_key_id: Option<String>,
}

impl TryFrom<RegisterPayload> for RegisterRequest {
    type Error = String;

    fn try_from(payload: RegisterPayload) -> Result<Self, Self::Error> {
        let email = payload.email.trim().to_lowercase();
        if email.is_empty() {
            return Err("Email is required".to_string());
        }
        let account_keys = if let Some(keys) = &payload.account_keys {
            keys.validate().map_err(|e| e.to_string())?
        } else {
            let pair = payload
                .user_asymmetric_keys
                .as_ref()
                .ok_or("Account keys are required")?;
            account_keys::ValidatedAccountKeys {
                private_key:        pair.encrypted_private_key.clone(),
                public_key:         pair.public_key.clone(),
                signed_public_key:  None,
                security_state:     None,
                security_version:   None,
                signature_key_pair: None,
            }
        };
        let user_key_id = match &payload.credentials {
            RegisterCredentials::Current { unlock, .. } => {
                unlock.contained_key_id.clone()
            }
            _ => None,
        };
        if user_key_id
            .as_ref()
            .is_some_and(|value| !account_keys::is_valid_key_id(value))
        {
            return Err("Invalid contained key ID".into());
        }
        let (hash, key, kdf) = match payload.credentials {
            RegisterCredentials::Current {
                authentication,
                unlock,
            } => {
                if authentication.kdf != unlock.kdf ||
                    authentication.salt != email ||
                    unlock.salt != email
                {
                    return Err("Authentication and unlock KDF/salt must \
                                match the account"
                        .to_string());
                }
                (authentication.hash, unlock.key, authentication.kdf)
            }
            RegisterCredentials::Legacy {
                hash,
                key,
                kdf,
                iterations,
                memory,
                parallelism,
            } => (hash, key, KdfParams {
                kdf_type: kdf,
                iterations,
                memory,
                parallelism,
            }),
        };
        if hash.is_empty() || key.is_empty() {
            return Err(
                "Password hash and encrypted key are required".to_string()
            );
        }
        Ok(Self {
            name: payload.name,
            email,
            master_password_hint: payload.master_password_hint,
            user_asymmetric_keys: KeyData {
                encrypted_private_key: account_keys.private_key.clone(),
                public_key:            account_keys.public_key.clone(),
            },
            user_key_id: if account_keys.is_v2() {
                user_key_id
            } else {
                None
            },
            account_keys,
            email_verification_token: payload.email_verification_token,
            master_password_hash: hash,
            user_symmetric_key: key,
            kdf: kdf.kdf_type,
            kdf_iterations: kdf.iterations,
            kdf_memory: kdf.memory,
            kdf_parallelism: kdf.parallelism,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    pub public_key:            String,
    pub encrypted_private_key: String,
}

/// Request body for password-protected operations (delete account, purge vault,
/// etc.) Supports both master password hash and OTP verification.
/// Verification tokens and OTPs are bound to the current authenticated session.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpData {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash:    Option<String>,
    pub otp:                     Option<String>,
    pub user_verification_token: Option<String>,
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default)]
    pub contained_key_id: Option<String>,
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
    #[serde(default)]
    pub old_user_key_id: Option<String>,
    #[serde(default)]
    pub new_user_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountUnlockData {
    pub master_password_unlock_data: MasterPasswordUnlockData,
    #[serde(default)]
    pub passkey_unlock_data: Vec<serde_json::Value>,
    #[serde(default)]
    pub v2_upgrade_token: Option<serde_json::Value>,
    #[serde(default)]
    pub emergency_access_unlock_data: Vec<serde_json::Value>,
    #[serde(default)]
    pub organization_account_recovery_unlock_data: Vec<serde_json::Value>,
    #[serde(default)]
    pub device_key_unlock_data: Vec<serde_json::Value>,
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
    pub master_password_hint: Option<String>,
    #[serde(default)]
    pub contained_key_id: Option<String>,
}

pub type RotateAccountKeys = account_keys::AccountKeysData;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountData {
    pub ciphers: Vec<crate::models::cipher::CipherRequestData>,
    pub folders: Vec<RotateFolderData>,
    #[serde(default)]
    pub sends:   Vec<crate::send::RotateSendData>,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn current_registration() -> serde_json::Value {
        json!({
            "email": " User@Example.com ",
            "userAsymmetricKeys": {
                "publicKey": "public", "encryptedPrivateKey": "private"
            },
            "masterPasswordAuthentication": {
                "hash": "hash", "salt": "user@example.com",
                "kdf": { "kdfType": 0, "iterations": 600000 }
            },
            "masterPasswordUnlock": {
                "key": "wrapped-key", "salt": "user@example.com",
                "kdf": { "kdfType": 0, "iterations": 600000 }
            }
        })
    }

    #[test]
    fn current_registration_normalizes_to_existing_model()
    -> Result<(), serde_json::Error> {
        let request: RegisterRequest =
            serde_json::from_value(current_registration())?;
        assert_eq!(request.email, "user@example.com");
        assert_eq!(request.master_password_hash, "hash");
        assert_eq!(request.user_symmetric_key, "wrapped-key");
        assert_eq!(request.kdf_iterations, 600000);
        Ok(())
    }

    #[test]
    fn registration_rejects_conflicting_unlock_parameters() {
        let mut request = current_registration();
        request["masterPasswordUnlock"]["kdf"]["iterations"] = json!(100000);
        assert!(serde_json::from_value::<RegisterRequest>(request).is_err());
        let mut request = current_registration();
        request["masterPasswordUnlock"]["salt"] = json!("other@example.com");
        assert!(serde_json::from_value::<RegisterRequest>(request).is_err());
    }

    #[test]
    fn legacy_registration_remains_supported() -> Result<(), serde_json::Error>
    {
        let request: RegisterRequest = serde_json::from_value(json!({
            "email": "User@Example.com", "masterPasswordHash": "hash",
            "key": "wrapped-key", "kdf": 0, "kdfIterations": 600000,
            "userAsymmetricKeys": {
                "publicKey": "public", "encryptedPrivateKey": "private"
            }
        }))?;
        assert_eq!(request.email, "user@example.com");
        assert_eq!(request.user_symmetric_key, "wrapped-key");
        Ok(())
    }
}
