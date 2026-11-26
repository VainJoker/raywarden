//! Account request DTOs, protocol compatibility and normalization.
use serde::{Deserialize, Serialize};

use crate::{
    errors::{AppError, AppResult},
    models::identity::user::UserRow,
    service::identity::{account_keys, kdf::KdfKind},
};

// For /accounts/prelogin response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: i32,
    pub kdf_iterations: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<i32>,
    pub kdf_settings: KdfParams,
    pub salt: String,
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
    pub account_keys: account_keys::ValidatedAccountKeys,
    pub user_key_id: Option<String>,
    pub email_verification_token: Option<String>,
    pub kdf: KdfParams,
}

// Accept both the original registration and the separate authentication/unlock
// payload used by newer clients, normalizing both to one internal model.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPayload {
    name: Option<String>,
    email: String,
    master_password_hint: Option<String>,
    #[serde(alias = "keys")]
    user_asymmetric_keys: Option<AccountKeyPairRequest>,
    account_keys: Option<account_keys::AccountKeysRequest>,
    #[serde(alias = "token")]
    email_verification_token: Option<String>,
    #[serde(flatten)]
    credentials: RegisterCredentials,
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
        #[serde(rename = "masterPasswordUnlock", alias = "MasterPasswordUnlock")]
        unlock: RegisterUnlock,
    },
    Legacy {
        #[serde(rename = "masterPasswordHash")]
        hash: String,
        #[serde(rename = "userSymmetricKey", alias = "key")]
        key: String,
        kdf: i32,
        #[serde(rename = "kdfIterations")]
        iterations: i32,
        #[serde(rename = "kdfMemory")]
        memory: Option<i32>,
        #[serde(rename = "kdfParallelism")]
        parallelism: Option<i32>,
    },
}

#[derive(Deserialize)]
struct RegisterAuthentication {
    #[serde(alias = "Kdf")]
    kdf: KdfParams,
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
    kdf: KdfParams,
    salt: String,
    #[serde(alias = "masterKeyWrappedUserKey", alias = "MasterKeyWrappedUserKey")]
    key: String,
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
        let account_keys = if let Some(keys) = payload.account_keys {
            keys.into_validated().map_err(|e| e.to_string())?
        } else {
            let pair = payload
                .user_asymmetric_keys
                .ok_or("Account keys are required")?;
            account_keys::ValidatedAccountKeys::from_legacy_pair(
                pair.encrypted_private_key,
                pair.public_key,
            )
        };
        let (user_key_id, hash, key, kdf) = match payload.credentials {
            RegisterCredentials::Current {
                authentication,
                unlock,
            } => {
                if unlock
                    .contained_key_id
                    .as_deref()
                    .is_some_and(|value| !account_keys::is_valid_key_id(value))
                {
                    return Err("Invalid contained key ID".into());
                }
                if authentication.kdf != unlock.kdf
                    || authentication.salt != email
                    || unlock.salt != email
                {
                    return Err("Authentication and unlock KDF/salt must \
                                match the account"
                        .to_string());
                }
                (
                    unlock.contained_key_id,
                    authentication.hash,
                    unlock.key,
                    authentication.kdf,
                )
            }
            RegisterCredentials::Legacy {
                hash,
                key,
                kdf,
                iterations,
                memory,
                parallelism,
            } => (None, hash, key, KdfParams {
                kdf_type: kdf,
                iterations,
                memory,
                parallelism,
            }),
        };
        if hash.is_empty() || key.is_empty() {
            return Err("Password hash and encrypted key are required".to_string());
        }
        Ok(Self {
            name: payload.name,
            email,
            master_password_hint: payload.master_password_hint,
            user_key_id: if account_keys.is_v2() {
                user_key_id
            } else {
                None
            },
            account_keys,
            email_verification_token: payload.email_verification_token,
            master_password_hash: hash,
            user_symmetric_key: key,
            kdf,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeyPairRequest {
    pub public_key: String,
    pub encrypted_private_key: String,
}

impl AccountKeyPairRequest {
    pub fn validate_password_rewrap(&self, user: &UserRow) -> AppResult<()> {
        if self.public_key.trim().is_empty() || self.encrypted_private_key.trim().is_empty() {
            return Err(AppError::bad_request(
                "Both public key and wrapped private key are required",
            ));
        }
        if self.public_key != user.public_key {
            return Err(AppError::bad_request(
                "Changing the asymmetric public key is not allowed",
            ));
        }
        let version = if super::is_v2(user) || user.private_key.starts_with("7.") {
            "7"
        } else {
            "2"
        };
        if !self
            .encrypted_private_key
            .split_once('.')
            .is_some_and(|(kind, value)| kind == version && !value.is_empty())
        {
            return Err(AppError::bad_request(
                "Wrapped private key must preserve the current encryption \
                 version",
            ));
        }
        Ok(())
    }
}

/// Request body for password-protected operations (delete account, purge vault,
/// etc.) Supports both master password hash and OTP verification.
/// Verification tokens and OTPs are bound to the current authenticated session.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountVerificationRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    pub user_verification_token: Option<String>,
}

// For POST /accounts/password request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub master_password_hash: String,
    #[serde(flatten)]
    data: CredentialChangePayload,
    pub master_password_hint: Option<String>,
    pub user_asymmetric_keys: Option<AccountKeyPairRequest>,
}

impl ChangePasswordRequest {
    pub fn resolve(&self, user: &UserRow) -> AppResult<(&str, &str, KdfParams)> {
        let resolved = self.data.resolve(user, false)?;
        let expected = KdfParams {
            kdf_type: user.kdf_type,
            iterations: user.kdf_iterations,
            memory: if user.kdf_type == 1 {
                user.kdf_memory
            } else {
                None
            },
            parallelism: if user.kdf_type == 1 {
                user.kdf_parallelism
            } else {
                None
            },
        };
        if resolved.2 != expected {
            return Err(AppError::bad_request(
                "Password KDF must match the stored KDF; use the KDF endpoint \
                 to change it",
            ));
        }
        if let Some(keys) = &self.user_asymmetric_keys {
            keys.validate_password_rewrap(user)?;
        }
        Ok(resolved)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    #[serde(alias = "kdfType")]
    pub kdf_type: i32,
    pub iterations: i32,
    pub memory: Option<i32>,
    pub parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordAuthenticationPayload {
    pub salt: String,
    pub kdf: KdfParams,
    pub master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlockPayload {
    pub salt: String,
    pub kdf: KdfParams,
    pub master_key_wrapped_user_key: String,
    #[serde(default)]
    pub contained_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfRequest {
    pub master_password_hash: String,
    #[serde(flatten)]
    data: CredentialChangePayload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialChangePayload {
    key: Option<String>,
    new_master_password_hash: Option<String>,
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    authentication_data: Option<MasterPasswordAuthenticationPayload>,
    unlock_data: Option<MasterPasswordUnlockPayload>,
}

impl ChangeKdfRequest {
    /// Resolve one complete protocol format before deriving or writing keys.
    pub fn resolve(&self, user: &UserRow) -> AppResult<(&str, &str, KdfParams)> {
        self.data.resolve(user, true)
    }
}

impl CredentialChangePayload {
    fn resolve(&self, user: &UserRow, changing_kdf: bool) -> AppResult<(&str, &str, KdfParams)> {
        let resolved = match (&self.authentication_data, &self.unlock_data) {
            (Some(authentication), Some(unlock)) => {
                self.resolve_modern(user, authentication, unlock)?
            }
            (None, None) => self.resolve_legacy(user, changing_kdf)?,
            _ => {
                return Err(AppError::bad_request(
                    "Authentication and unlock data must be provided together",
                ));
            }
        };
        if resolved.0.trim().is_empty() || resolved.1.trim().is_empty() {
            return Err(AppError::bad_request(
                "Password hash and wrapped key must not be empty",
            ));
        }
        Ok(resolved)
    }

    fn resolve_modern<'a>(
        &self,
        user: &UserRow,
        authentication: &'a MasterPasswordAuthenticationPayload,
        unlock: &'a MasterPasswordUnlockPayload,
    ) -> AppResult<(&'a str, &'a str, KdfParams)> {
        if authentication.kdf != unlock.kdf {
            return Err(AppError::bad_request(
                "KDF settings must be equal for authentication and \
                         unlock",
            ));
        }
        if authentication.salt != user.email || unlock.salt != user.email {
            return Err(AppError::bad_request("Invalid master password salt"));
        }
        if self.key.is_some()
            || self.new_master_password_hash.is_some()
            || self.kdf.is_some()
            || self.kdf_iterations.is_some()
            || self.kdf_memory.is_some()
            || self.kdf_parallelism.is_some()
        {
            return Err(AppError::bad_request(
                "Conflicting or incomplete credential request formats",
            ));
        }
        if unlock
            .contained_key_id
            .as_ref()
            .is_some_and(|id| user.user_key_id.as_ref() != Some(id))
        {
            return Err(AppError::bad_request(
                "Contained key id must match the current user key id",
            ));
        }
        Ok((
            authentication.master_password_authentication_hash.as_str(),
            unlock.master_key_wrapped_user_key.as_str(),
            unlock.kdf,
        ))
    }

    fn resolve_legacy(
        &self,
        user: &UserRow,
        changing_kdf: bool,
    ) -> AppResult<(&str, &str, KdfParams)> {
        let hash = self
            .new_master_password_hash
            .as_deref()
            .ok_or_else(|| AppError::bad_request("Missing newMasterPasswordHash"))?;
        let key = self
            .key
            .as_deref()
            .ok_or_else(|| AppError::bad_request("Missing encrypted user key"))?;
        let kdf = self
            .kdf
            .or_else(|| (!changing_kdf).then_some(user.kdf_type))
            .ok_or_else(|| AppError::bad_request("Missing KDF type"))?;
        let iterations = self
            .kdf_iterations
            .or_else(|| (!changing_kdf).then_some(user.kdf_iterations))
            .ok_or_else(|| AppError::bad_request("Missing KDF iterations"))?;
        Ok((hash, key, KdfParams {
            kdf_type: kdf,
            iterations,
            memory: if kdf == KdfKind::Argon2id as i32 {
                self.kdf_memory
                    .or_else(|| (!changing_kdf).then_some(user.kdf_memory).flatten())
            } else {
                None
            },
            parallelism: if kdf == KdfKind::Argon2id as i32 {
                self.kdf_parallelism
                    .or_else(|| (!changing_kdf).then_some(user.kdf_parallelism).flatten())
            } else {
                None
            },
        }))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAvatarColorRequest {
    pub avatar_color: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn registration_and_credential_requests_support_modern_and_legacy_shapes() {
        let user: UserRow = serde_json::from_value(json!({
            "id": "owner", "email": "owner@example.test", "is_email_verified": 0,
            "master_password_hash": "hash", "key": "2.wrapped", "private_key": "2.private",
            "public_key": "public", "kdf_type": 0, "kdf_iterations": 600_000,
            "security_stamp": "stamp", "created_at": "now", "updated_at": "now"
        }))
        .expect("user");
        let modern: ChangeKdfRequest = serde_json::from_value(json!({
            "masterPasswordHash": "hash",
            "authenticationData": {"salt": "owner@example.test", "kdf": {"kdfType": 0, "iterations": 600_000}, "masterPasswordAuthenticationHash": "new-hash"},
            "unlockData": {"salt": "owner@example.test", "kdf": {"kdfType": 0, "iterations": 600_000}, "masterKeyWrappedUserKey": "2.new"}
        }))
        .expect("modern");
        assert_eq!(modern.resolve(&user).expect("resolved").0, "new-hash");

        let mut reg = json!({
            "email": " User@Example.com ",
            "userAsymmetricKeys": {"publicKey": "public", "encryptedPrivateKey": "private"},
            "masterPasswordAuthentication": {"hash": "hash", "salt": "user@example.com", "kdf": {"kdfType": 0, "iterations": 600_000}},
            "masterPasswordUnlock": {"key": "wrapped", "salt": "user@example.com", "kdf": {"kdfType": 0, "iterations": 600_000}}
        });
        assert_eq!(
            serde_json::from_value::<RegisterRequest>(reg.clone())
                .expect("reg")
                .email,
            "user@example.com"
        );
        reg["masterPasswordUnlock"]["salt"] = json!("other@example.com");
        assert!(serde_json::from_value::<RegisterRequest>(reg).is_err());
    }
}
