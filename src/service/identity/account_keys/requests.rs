//! Account-key protocol DTOs, validation and response projection.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    errors::{AppError, AppResult, AuthError},
    models::identity::{account_keys::AccountKeyMaterial, user::UserRow},
};

fn required(value: &str, field: &str) -> AppResult<()> {
    if value.trim().is_empty() {
        return Err(AppError::bad_request(format!(
            "The {field} field is required."
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeysRequest {
    pub user_key_encrypted_account_private_key: String,
    pub account_public_key: String,
    pub public_key_encryption_key_pair: Option<PublicKeyEncryptionKeyPair>,
    pub signature_key_pair: Option<SignatureKeyPair>,
    pub security_state: Option<SecurityState>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WrappedRotationKeys {
    public_key_encryption_key_pair: PublicKeyEncryptionKeyPair,
    signature_key_pair: Option<SignatureKeyPair>,
    security_state: Option<SecurityState>,
}

impl WrappedRotationKeys {
    pub(crate) fn into_validated(self) -> AppResult<ValidatedAccountKeys> {
        let pair = self.public_key_encryption_key_pair;
        required(
            &pair.wrapped_private_key,
            "UserKeyEncryptedAccountPrivateKey",
        )?;
        required(&pair.public_key, "AccountPublicKey")?;
        ValidatedAccountKeys::from_wire(
            pair.wrapped_private_key,
            pair.public_key,
            pair.signed_public_key,
            self.signature_key_pair,
            self.security_state,
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_field_names,
    reason = "Each client key-pair field names a distinct cryptographic role"
)]
pub struct PublicKeyEncryptionKeyPair {
    pub wrapped_private_key: String,
    pub public_key: String,
    pub signed_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureKeyPair {
    pub signature_algorithm: String,
    pub wrapped_signing_key: String,
    pub verifying_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityState {
    pub security_state: String,
    pub security_version: i32,
}

#[derive(Debug, Clone)]
pub struct ValidatedAccountKeys {
    private_key: String,
    public_key: String,
    version: AccountKeyVersion,
}

#[derive(Debug, Clone)]
enum AccountKeyVersion {
    V1,
    V2 {
        signed_public_key: String,
        security_state: SecurityState,
        signature_key_pair: SignatureKeyPair,
    },
}

impl AccountKeysRequest {
    pub fn into_validated(self) -> AppResult<ValidatedAccountKeys> {
        required(
            &self.user_key_encrypted_account_private_key,
            "UserKeyEncryptedAccountPrivateKey",
        )?;
        required(&self.account_public_key, "AccountPublicKey")?;
        let (private_key, public_key, signed_public_key) = match self.public_key_encryption_key_pair
        {
            Some(pair) => {
                required(&pair.wrapped_private_key, "WrappedPrivateKey")?;
                required(&pair.public_key, "PublicKey")?;
                (
                    pair.wrapped_private_key,
                    pair.public_key,
                    pair.signed_public_key,
                )
            }
            None => (
                self.user_key_encrypted_account_private_key,
                self.account_public_key,
                None,
            ),
        };
        ValidatedAccountKeys::from_wire(
            private_key,
            public_key,
            signed_public_key,
            self.signature_key_pair,
            self.security_state,
        )
    }
}

impl ValidatedAccountKeys {
    fn from_wire(
        private_key: String,
        public_key: String,
        signed_public_key: Option<String>,
        signature_key_pair: Option<SignatureKeyPair>,
        security_state: Option<SecurityState>,
    ) -> AppResult<Self> {
        if let Some(pair) = &signature_key_pair {
            required(&pair.signature_algorithm, "SignatureAlgorithm")?;
            required(&pair.wrapped_signing_key, "WrappedSigningKey")?;
            required(&pair.verifying_key, "VerifyingKey")?;
            if !matches!(pair.signature_algorithm.as_str(), "ed25519" | "mldsa44") {
                return Err(AppError::bad_request("Unsupported signature algorithm"));
            }
        }
        if let Some(state) = &security_state {
            required(&state.security_state, "SecurityState")?;
            if state.security_state.encode_utf16().count() > 10_000 {
                return Err(AppError::bad_request(
                    "The field SecurityState must be a string with a maximum \
                     length of 10000.",
                ));
            }
        }
        let version = match (signed_public_key, signature_key_pair, security_state) {
            (Some(signed), Some(pair), Some(state)) => {
                required(&signed, "SignedPublicKey")?;
                AccountKeyVersion::V2 {
                    signed_public_key: signed,
                    security_state: state,
                    signature_key_pair: pair,
                }
            }
            (None, None, None) => AccountKeyVersion::V1,
            _ => {
                return Err(AppError::bad_request(
                    "Invalid account keys: the signed public key, signature \
                     key pair and security state must either all be present \
                     or all be absent",
                ));
            }
        };
        Ok(Self {
            private_key,
            public_key,
            version,
        })
    }
    // Legacy registration accepts the pair as supplied; callers retain their
    // existing validation rather than imposing newer request rules here.
    pub const fn from_legacy_pair(private_key: String, public_key: String) -> Self {
        Self {
            private_key,
            public_key,
            version: AccountKeyVersion::V1,
        }
    }

    pub fn into_persistence_material(self) -> AppResult<AccountKeyMaterial> {
        let (signed_public_key, security_state, security_version, signature_key_pair) =
            match self.version {
                AccountKeyVersion::V1 => (None, None, None, None),
                AccountKeyVersion::V2 {
                    signed_public_key,
                    security_state,
                    signature_key_pair,
                } => (
                    Some(signed_public_key),
                    Some(security_state.security_state),
                    Some(security_state.security_version),
                    Some(serde_json::to_string(&signature_key_pair).map_err(
                        AppError::internal_json("Failed to serialize signature key pair"),
                    )?),
                ),
            };
        Ok(AccountKeyMaterial {
            private_key: self.private_key,
            public_key: self.public_key,
            signed_public_key,
            security_state,
            security_version,
            signature_key_pair,
        })
    }

    pub const fn is_v2(&self) -> bool {
        matches!(self.version, AccountKeyVersion::V2 { .. })
    }
    pub fn validate_rotation(&self, user: &UserRow) -> AppResult<()> {
        if self.public_key != user.public_key {
            return Err(AppError::bad_request(
                "Changing the asymmetric keypair is not possible during key \
                 rotation",
            ));
        }
        if let AccountKeyVersion::V2 {
            signature_key_pair: pair,
            ..
        } = &self.version
        {
            if self.private_key.split_once('.').map(|(kind, _)| kind) != Some("7")
                || pair
                    .wrapped_signing_key
                    .split_once('.')
                    .map(|(kind, _)| kind)
                    != Some("7")
            {
                return Err(AppError::bad_request(
                    "The provided private keys must be wrapped with \
                     XChaCha20-Poly1305",
                ));
            }
            if crate::service::identity::user::is_v2(user) {
                let old: SignatureKeyPair =
                    serde_json::from_str(user.signature_key_pair.as_deref().ok_or_else(|| {
                        AppError::bad_request("The account is missing its signature key pair")
                    })?)
                    .map_err(AppError::internal_json(
                        "Stored signature key pair is malformed",
                    ))?;
                if pair.verifying_key != old.verifying_key {
                    return Err(AppError::bad_request(
                        "Changing the verifying key is not possible during \
                         key rotation",
                    ));
                }
            }
        } else {
            if crate::service::identity::user::is_v2(user) {
                return Err(AppError::bad_request(
                    "Cannot downgrade an account from v2 to v1 encryption \
                     during key rotation",
                ));
            }
            if self.private_key.split_once('.').map(|(kind, _)| kind) != Some("2") {
                return Err(AppError::bad_request(
                    "The provided account private key was not wrapped with \
                     AES-256-CBC-HMAC",
                ));
            }
        }
        Ok(())
    }
}

// For POST /accounts/key-management/rotate-user-account-keys request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountKeysRequest {
    pub account_unlock_data: AccountUnlockPayload,
    pub account_keys: AccountKeysRequest,
    pub account_data: RotateAccountPayload,
    pub old_master_key_authentication_hash: String,
    #[serde(default)]
    pub old_user_key_id: Option<String>,
    #[serde(default)]
    pub new_user_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUnlockItem {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub encrypted_public_key: Option<String>,
    #[serde(default)]
    pub encrypted_user_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountUnlockPayload {
    pub master_password_unlock_data: RotateMasterPasswordUnlockPayload,
    #[serde(default)]
    pub passkey_unlock_data: Vec<PasskeyUnlockItem>,
    #[serde(default)]
    #[serde(rename = "v2UpgradeToken")]
    pub _v2_upgrade_token: Option<serde_json::Value>,
    #[serde(default)]
    pub emergency_access_unlock_data: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    pub organization_account_recovery_unlock_data: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    pub device_key_unlock_data: Vec<serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateMasterPasswordUnlockPayload {
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateAccountPayload {
    pub ciphers: Vec<crate::service::vault::cipher::CipherRequest>,
    pub folders: Vec<RotateFolderRequest>,
    #[serde(default)]
    pub sends: Vec<crate::service::send::RotateSendRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateFolderRequest {
    // There is a bug in 2024.3.x which adds a `null` item.
    // To bypass this we allow an Option here, but skip it during the updates
    // See: https://github.com/bitwarden/clients/issues/8453
    pub id: Option<String>,
    pub name: String,
}

impl RotateAccountKeysRequest {
    pub(crate) fn validate_rotation_metadata(&self, user: &UserRow) -> AppResult<()> {
        let unlock_data = &self.account_unlock_data.master_password_unlock_data;
        let kdf_matches = user.kdf_type == unlock_data.kdf_type
            && user.kdf_iterations == unlock_data.kdf_iterations
            && user.kdf_memory == unlock_data.kdf_memory
            && user.kdf_parallelism == unlock_data.kdf_parallelism;

        if user.email != unlock_data.email || !kdf_matches {
            log::error!(
                "KDF/email mismatch in rotation request: email_equal={}, \
                 kdf_equal={}",
                user.email == unlock_data.email,
                kdf_matches
            );
            return Err(AppError::Auth(AuthError::InvalidKdf(
                "Changing the kdf variant or email is not supported during \
                 key rotation"
                    .into(),
            )));
        }

        if user.public_key != self.account_keys.account_public_key {
            log::error!("Public key mismatch in rotation request: stored != provided");
            return Err(AppError::Auth(AuthError::InvalidKdf(
                "Changing the asymmetric keypair is not supported during key \
                 rotation"
                    .into(),
            )));
        }

        Ok(())
    }
}

pub fn is_valid_key_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn account_keys_response(user: &UserRow, object_key: &str) -> Value {
    if user.private_key.is_empty() {
        return Value::Null;
    }
    let signature = user
        .signature_key_pair
        .as_deref()
        .and_then(|raw| serde_json::from_str::<SignatureKeyPair>(raw).ok())
        .filter(|_| crate::service::identity::user::is_v2(user));
    json!({
        "publicKeyEncryptionKeyPair": {
            "publicKey": user.public_key,
            "wrappedPrivateKey": user.private_key,
            "signedPublicKey": signature.as_ref().and(user.signed_public_key.as_ref()),
            (object_key): "publicKeyEncryptionKeyPair",
        },
        "signatureKeyPair": signature.as_ref().map(|pair| json!({
            "wrappedSigningKey": pair.wrapped_signing_key,
            "verifyingKey": pair.verifying_key,
            (object_key): "signatureKeyPair",
        })),
        "securityState": signature.as_ref().map(|_| json!({
            "securityState": user.security_state,
            "securityVersion": user.security_version,
        })),
        (object_key): "privateKeys",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::identity::account_keys::AccountSnapshot;

    #[test]
    fn v2_keys_require_complete_material_and_forbid_downgrade() {
        let mut user: UserRow = serde_json::from_value(json!({
            "id": "owner", "email": "owner@example.test", "is_email_verified": 0,
            "master_password_hash": "hash", "key": "wrapped", "private_key": "2.private",
            "public_key": "public", "kdf_type": 0, "kdf_iterations": 600_000,
            "security_stamp": "stamp", "created_at": "now", "updated_at": "now"
        }))
        .expect("user");
        let v2 = json!({
            "userKeyEncryptedAccountPrivateKey": "7.private", "accountPublicKey": "public",
            "publicKeyEncryptionKeyPair": {"wrappedPrivateKey": "7.private", "publicKey": "public", "signedPublicKey": "signed"},
            "signatureKeyPair": {"signatureAlgorithm": "ed25519", "wrappedSigningKey": "7.signing", "verifyingKey": "verify"},
            "securityState": {"securityState": "state", "securityVersion": 2}
        });
        let keys = serde_json::from_value::<AccountKeysRequest>(v2)
            .expect("req")
            .into_validated()
            .expect("v2");
        assert!(keys.validate_rotation(&user).is_ok());
        let material = keys.into_persistence_material().expect("material");
        let before = AccountSnapshot::from_user(&user);
        user.private_key = material.private_key;
        user.signed_public_key = material.signed_public_key;
        user.security_state = material.security_state;
        user.security_version = material.security_version;
        user.signature_key_pair = material.signature_key_pair;
        assert_ne!(before, AccountSnapshot::from_user(&user));
        assert!(
            ValidatedAccountKeys::from_legacy_pair("2.private".into(), "public".into())
                .validate_rotation(&user)
                .is_err()
        );
        assert!(is_valid_key_id("0123456789abcdef0123456789abcdef"));
    }
}
