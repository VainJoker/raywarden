//! Account request DTOs, protocol compatibility and normalization.
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    models::identity::user::UserRow,
    service::identity::account_keys,
};

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
    user_asymmetric_keys:     Option<AccountKeyPairRequest>,
    account_keys:             Option<account_keys::AccountKeysRequest>,
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
                .ok_or("Account keys are required")?;
            account_keys::ValidatedAccountKeys::from_legacy_pair(
                pair.encrypted_private_key,
                pair.public_key,
            )
        };
        let user_key_id = match &payload.credentials {
            RegisterCredentials::Current { unlock, .. } => {
                unlock.contained_key_id.clone()
            }
            RegisterCredentials::Legacy { .. } => None,
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
pub struct AccountKeyPairRequest {
    pub public_key:            String,
    pub encrypted_private_key: String,
}

impl AccountKeyPairRequest {
    pub fn validate_password_rewrap(&self, user: &UserRow) -> AppResult<()> {
        if self.public_key.trim().is_empty() ||
            self.encrypted_private_key.trim().is_empty()
        {
            return Err(AppError::bad_request(
                "Both public key and wrapped private key are required",
            ));
        }
        if self.public_key != user.public_key {
            return Err(AppError::bad_request(
                "Changing the asymmetric public key is not allowed",
            ));
        }
        let version =
            if super::is_v2(user) || user.private_key.starts_with("7.") {
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
    pub master_password_hash:    Option<String>,
    pub otp:                     Option<String>,
    pub user_verification_token: Option<String>,
}

/// Initialize an existing empty V1 account using legacy or registration fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordRequest {
    key: Option<String>,
    master_password_hash: Option<String>,
    keys: Option<AccountKeyPairRequest>,
    user_asymmetric_keys: Option<AccountKeyPairRequest>,
    master_password_hint: Option<String>,
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    master_password_authentication: Option<RegisterAuthentication>,
    master_password_unlock: Option<RegisterUnlock>,
    account_keys: Option<serde_json::Value>,
}

pub struct ValidatedSetPassword {
    pub master_password_hash: String,
    pub wrapped_user_key:     String,
    pub key_pair:             Option<AccountKeyPairRequest>,
    pub master_password_hint: Option<String>,
    pub kdf:                  KdfParams,
}

impl SetPasswordRequest {
    #[allow(
        clippy::too_many_lines,
        reason = "Validate each complete password initialization format \
                  before accepting key material"
    )]
    pub fn resolve(self, user: &UserRow) -> AppResult<ValidatedSetPassword> {
        if self.keys.is_some() && self.user_asymmetric_keys.is_some() {
            return Err(AppError::bad_request(
                "Provide only one keypair field",
            ));
        }
        if self.account_keys.is_some() {
            return Err(AppError::bad_request(
                "V2 JIT password registration is not available in this \
                 personal vault",
            ));
        }
        let (hash, key, kdf, keys) = match (
            self.master_password_authentication,
            self.master_password_unlock,
        ) {
            (Some(authentication), Some(unlock)) => {
                if self.master_password_hash.is_some() ||
                    self.key.is_some() ||
                    self.kdf.is_some() ||
                    self.kdf_iterations.is_some() ||
                    self.kdf_memory.is_some() ||
                    self.kdf_parallelism.is_some()
                {
                    return Err(AppError::bad_request(
                        "Cannot mix modern and legacy password fields",
                    ));
                }
                if authentication.kdf != unlock.kdf ||
                    authentication.salt != user.email ||
                    unlock.salt != user.email
                {
                    return Err(AppError::bad_request(
                        "Authentication and unlock KDF/salt must match the \
                         account",
                    ));
                }
                if let Some(id) = &unlock.contained_key_id {
                    if !account_keys::is_valid_key_id(id) {
                        return Err(AppError::bad_request(
                            "Invalid contained key ID",
                        ));
                    }
                    if user
                        .user_key_id
                        .as_ref()
                        .is_some_and(|current| current != id)
                    {
                        return Err(AppError::bad_request(
                            "Contained key id must match the current user key \
                             id",
                        ));
                    }
                    // V1 registration validates this optional client metadata
                    // without establishing a V2 key id on the account.
                }
                (
                    authentication.hash,
                    unlock.key,
                    authentication.kdf,
                    self.user_asymmetric_keys.or(self.keys),
                )
            }
            (None, None) => {
                if self.user_asymmetric_keys.is_some() {
                    return Err(AppError::bad_request(
                        "Cannot mix modern and legacy keypair fields",
                    ));
                }
                let hash = self.master_password_hash.ok_or_else(|| {
                    AppError::bad_request("Missing masterPasswordHash")
                })?;
                let key = self.key.ok_or_else(|| {
                    AppError::bad_request("Missing encrypted user key")
                })?;
                let kdf = match (self.kdf, self.kdf_iterations) {
                    (Some(kind), Some(iterations)) => KdfParams {
                        kdf_type: kind,
                        iterations,
                        memory: if kind == 1 {
                            self.kdf_memory.or(Some(64))
                        } else {
                            None
                        },
                        parallelism: if kind == 1 {
                            self.kdf_parallelism.or(Some(4))
                        } else {
                            None
                        },
                    },
                    (None, None)
                        if self.kdf_memory.is_none() &&
                            self.kdf_parallelism.is_none() =>
                    {
                        KdfParams {
                            kdf_type:    user.kdf_type,
                            iterations:  user.kdf_iterations,
                            memory:      user.kdf_memory,
                            parallelism: user.kdf_parallelism,
                        }
                    }
                    _ => {
                        return Err(AppError::bad_request(
                            "KDF type and iterations must be provided together",
                        ));
                    }
                };
                (hash, key, kdf, self.keys)
            }
            _ => {
                return Err(AppError::bad_request(
                    "Authentication and unlock data must be provided together",
                ));
            }
        };
        if hash.trim().is_empty() || key.trim().is_empty() {
            return Err(AppError::bad_request(
                "Password hash and wrapped user key must not be empty",
            ));
        }
        if let Some(keys) = &keys {
            if keys.public_key.trim().is_empty() ||
                keys.encrypted_private_key
                    .strip_prefix("2.")
                    .is_none_or(str::is_empty)
            {
                return Err(AppError::bad_request(
                    "A complete V1 public key and wrapped private key are \
                     required",
                ));
            }
            if !user.public_key.is_empty() && user.public_key != keys.public_key
            {
                return Err(AppError::bad_request(
                    "Changing the existing public key identity is not allowed",
                ));
            }
        }
        Ok(ValidatedSetPassword {
            master_password_hash: hash,
            wrapped_user_key: key,
            key_pair: keys,
            master_password_hint: self.master_password_hint,
            kdf,
        })
    }
}

// For POST /accounts/password request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub master_password_hash: String,
    #[serde(flatten)]
    data:                     CredentialChangePayload,
    pub master_password_hint: Option<String>,
    pub user_asymmetric_keys: Option<AccountKeyPairRequest>,
}

impl ChangePasswordRequest {
    pub fn resolve(
        &self,
        user: &UserRow,
    ) -> AppResult<(&str, &str, KdfParams)> {
        let resolved = self.data.resolve(user, false)?;
        let expected = KdfParams {
            kdf_type:    user.kdf_type,
            iterations:  user.kdf_iterations,
            memory:      if user.kdf_type == 1 {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    data:                     CredentialChangePayload,
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
    pub fn resolve(
        &self,
        user: &UserRow,
    ) -> AppResult<(&str, &str, KdfParams)> {
        self.data.resolve(user, true)
    }
}

impl CredentialChangePayload {
    #[allow(
        clippy::too_many_lines,
        reason = "Validate each complete credential-change format without \
                  mixing protocol variants"
    )]
    fn resolve(
        &self,
        user: &UserRow,
        changing_kdf: bool,
    ) -> AppResult<(&str, &str, KdfParams)> {
        let resolved = match (&self.authentication_data, &self.unlock_data) {
            (Some(authentication), Some(unlock)) => {
                if authentication.kdf != unlock.kdf {
                    return Err(AppError::bad_request(
                        "KDF settings must be equal for authentication and \
                         unlock",
                    ));
                }
                if authentication.salt != user.email ||
                    unlock.salt != user.email
                {
                    return Err(AppError::bad_request(
                        "Invalid master password salt",
                    ));
                }
                // Older clients may repeat complete flat fields. They may
                // confirm this pair, never supply an independent fallback.
                if self.key.is_some() != self.new_master_password_hash.is_some() ||
                    self.kdf.is_some() != self.kdf_iterations.is_some() ||
                    self.key.as_ref().is_some_and(|key| {
                        key != &unlock.master_key_wrapped_user_key
                    }) ||
                    self.new_master_password_hash.as_ref().is_some_and(
                        |hash| {
                            hash != &authentication
                                .master_password_authentication_hash
                        },
                    ) ||
                    self.kdf.is_some_and(|kind| kind != unlock.kdf.kdf_type) ||
                    self.kdf_iterations.is_some_and(|iterations| {
                        iterations != unlock.kdf.iterations
                    }) ||
                    self.kdf_memory.is_some_and(|memory| {
                        Some(memory) != unlock.kdf.memory
                    }) ||
                    self.kdf_parallelism.is_some_and(|parallelism| {
                        Some(parallelism) != unlock.kdf.parallelism
                    })
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
                (
                    authentication.master_password_authentication_hash.as_str(),
                    unlock.master_key_wrapped_user_key.as_str(),
                    unlock.kdf.clone(),
                )
            }
            (None, None) => {
                let hash = self
                    .new_master_password_hash
                    .as_deref()
                    .ok_or_else(|| {
                        AppError::bad_request("Missing newMasterPasswordHash")
                    })?;
                let key = self.key.as_deref().ok_or_else(|| {
                    AppError::bad_request("Missing encrypted user key")
                })?;
                let kdf = self
                    .kdf
                    .or_else(|| (!changing_kdf).then_some(user.kdf_type))
                    .ok_or_else(|| AppError::bad_request("Missing KDF type"))?;
                let iterations = self
                    .kdf_iterations
                    .or_else(|| (!changing_kdf).then_some(user.kdf_iterations))
                    .ok_or_else(|| {
                        AppError::bad_request("Missing KDF iterations")
                    })?;
                (hash, key, KdfParams {
                    kdf_type: kdf,
                    iterations,
                    memory: if kdf == 1 {
                        self.kdf_memory.or_else(|| {
                            (!changing_kdf).then_some(user.kdf_memory).flatten()
                        })
                    } else {
                        None
                    },
                    parallelism: if kdf == 1 {
                        self.kdf_parallelism.or_else(|| {
                            (!changing_kdf)
                                .then_some(user.kdf_parallelism)
                                .flatten()
                        })
                    } else {
                        None
                    },
                })
            }
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

    fn user() -> UserRow {
        serde_json::from_value(json!({"id":"owner","email":"owner@example.test","is_email_verified":0,"master_password_hash":"hash","key":"2.wrapped","private_key":"2.private","public_key":"public","kdf_type":0,"kdf_iterations":600_000,"security_stamp":"stamp","created_at":"now","updated_at":"now"})).expect("valid account request fixture")
    }

    #[test]
    fn initial_password_omitted_kdf_keeps_prelogin_settings() {
        let request: SetPasswordRequest = serde_json::from_value(
            json!({"masterPasswordHash":"client-hash","key":"2.new-wrapper"}),
        )
        .expect("valid account request fixture");
        let data = request
            .resolve(&user())
            .expect("valid account request fixture");
        assert_eq!(data.kdf.kdf_type, 0);
        assert_eq!(data.kdf.iterations, 600_000);
        let request: SetPasswordRequest = serde_json::from_value(json!({"masterPasswordHash":"client-hash","key":"2.new-wrapper","kdf":1,"kdfIterations":3})).expect("valid account request fixture");
        let data = request
            .resolve(&user())
            .expect("valid account request fixture");
        assert_eq!(data.kdf.memory, Some(64));
        assert_eq!(data.kdf.parallelism, Some(4));
    }

    #[test]
    fn initial_password_current_fields_are_paired_without_requiring_keys() {
        let value = json!({"masterPasswordAuthentication":{"hash":"client-hash","salt":"owner@example.test","kdf":{"kdfType":0,"iterations":600_000}},
            "masterPasswordUnlock":{"key":"2.new-wrapper","salt":"owner@example.test","kdf":{"kdfType":0,"iterations":600_000}}});
        let request: SetPasswordRequest = serde_json::from_value(value.clone())
            .expect("valid account request fixture");
        assert!(
            request
                .resolve(&user())
                .expect("valid account request fixture")
                .key_pair
                .is_none()
        );
        let mut mixed = value;
        mixed["masterPasswordHash"] = json!("legacy-fallback");
        let request: SetPasswordRequest = serde_json::from_value(mixed)
            .expect("valid account request fixture");
        assert!(request.resolve(&user()).is_err());
    }

    fn current_credential_change() -> serde_json::Value {
        json!({"masterPasswordHash":"hash",
            "authenticationData":{"salt":"owner@example.test","kdf":{"kdfType":0,"iterations":600_000},"masterPasswordAuthenticationHash":"new-hash"},
            "unlockData":{"salt":"owner@example.test","kdf":{"kdfType":0,"iterations":600_000},"masterKeyWrappedUserKey":"2.new-wrapper"}})
    }

    #[test]
    fn current_only_password_and_kdf_requests_need_no_flat_placeholders() {
        let user = user();
        let request: ChangeKdfRequest =
            serde_json::from_value(current_credential_change())
                .expect("valid account request fixture");
        assert_eq!(
            request
                .resolve(&user)
                .expect("valid account request fixture")
                .0,
            "new-hash"
        );
        let mut value = current_credential_change();
        value["userAsymmetricKeys"] = json!({"publicKey":"public","encryptedPrivateKey":"2.rewrapped-private"});
        let request: ChangePasswordRequest = serde_json::from_value(value)
            .expect("valid account request fixture");
        assert_eq!(
            request
                .resolve(&user)
                .expect("valid account request fixture")
                .1,
            "2.new-wrapper"
        );
        assert_eq!(
            request
                .user_asymmetric_keys
                .expect("valid account request fixture")
                .encrypted_private_key,
            "2.rewrapped-private"
        );
    }

    #[test]
    fn flat_password_and_kdf_requests_preserve_their_protocol() {
        let mut value = json!({"masterPasswordHash":"hash","newMasterPasswordHash":"next","key":"2.wrapper"});
        let request: ChangePasswordRequest =
            serde_json::from_value(value.clone())
                .expect("valid account request fixture");
        assert_eq!(
            request
                .resolve(&user())
                .expect("valid account request fixture")
                .2
                .iterations,
            600_000
        );
        value["kdf"] = json!(0);
        value["kdfIterations"] = json!(700_000);
        let request: ChangeKdfRequest = serde_json::from_value(value)
            .expect("valid account request fixture");
        assert_eq!(
            request
                .resolve(&user())
                .expect("valid account request fixture")
                .2
                .iterations,
            700_000
        );
    }

    fn current_registration() -> serde_json::Value {
        json!({
            "email": " User@Example.com ",
            "userAsymmetricKeys": {
                "publicKey": "public", "encryptedPrivateKey": "private"
            },
            "masterPasswordAuthentication": {
                "hash": "hash", "salt": "user@example.com",
                "kdf": { "kdfType": 0, "iterations": 600_000 }
            },
            "masterPasswordUnlock": {
                "key": "wrapped-key", "salt": "user@example.com",
                "kdf": { "kdfType": 0, "iterations": 600_000 }
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
        assert_eq!(request.kdf_iterations, 600_000);
        Ok(())
    }

    #[test]
    fn registration_rejects_conflicting_unlock_parameters() {
        let mut request = current_registration();
        request["masterPasswordUnlock"]["kdf"]["iterations"] = json!(100_000);
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
            "key": "wrapped-key", "kdf": 0, "kdfIterations": 600_000,
            "userAsymmetricKeys": {
                "publicKey": "public", "encryptedPrivateKey": "private"
            }
        }))?;
        assert_eq!(request.email, "user@example.com");
        assert_eq!(request.user_symmetric_key, "wrapped-key");
        Ok(())
    }
}
