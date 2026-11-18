use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};
use worker::{
    D1Database,
    query,
};

use super::user::UserDB;
use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::db,
};

pub struct AccountKeysDB;

#[derive(Deserialize)]
pub struct PublicKeyRow {
    pub id:         String,
    pub public_key: String,
}

impl AccountKeysDB {
    pub async fn set_initial_pair(
        db: &D1Database,
        user: &str,
        private: &str,
        public: &str,
    ) -> AppResult<()> {
        let now = crate::infra::time::now_rfc3339();
        let row: Option<String> = db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET private_key=?1, public_key=?2, \
                     updated_at=?3
             WHERE id=?4 AND private_key='' AND public_key='' RETURNING id",
                    private,
                    public,
                    now,
                    user
                )?
                .first(Some("id"))
                .await
            },
            "Failed to initialize account key pair",
        )
        .await?;
        if row.is_none() {
            return Err(AppError::bad_request(
                "Account key pair is already initialized",
            ));
        }
        Ok(())
    }

    pub async fn set_initial_material(
        db: &D1Database,
        user: &str,
        stamp: &str,
        keys: &ValidatedAccountKeys,
        key_id: Option<&str>,
    ) -> AppResult<()> {
        let row: Option<String> = db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET \
                     private_key=?1,public_key=?2,signed_public_key=?3,\
                     security_state=?4,security_version=?5,\
                     signature_key_pair=?6,user_key_id=?7,updated_at=?8 WHERE \
                     id=?9 AND security_stamp=?10 AND private_key='' AND \
                     public_key='' RETURNING id",
                    keys.private_key,
                    keys.public_key,
                    keys.signed_public_key,
                    keys.security_state,
                    keys.security_version,
                    keys.signature_key_pair,
                    key_id,
                    crate::infra::time::now_rfc3339(),
                    user,
                    stamp
                )?
                .first(Some("id"))
                .await
            },
            "Failed to initialize account keys",
        )
        .await?;
        if row.is_none() {
            return Err(AppError::bad_request(
                "Account key pair is already initialized or session changed",
            ));
        }
        Ok(())
    }

    pub async fn set_key_id(
        db: &D1Database,
        user: &str,
        id: &str,
    ) -> AppResult<()> {
        let now = crate::infra::time::now_rfc3339();
        let row: Option<String> = db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET user_key_id=?1, updated_at=?2 WHERE \
                     id=?3
                AND user_key_id IS NULL RETURNING id",
                    id,
                    now,
                    user
                )?
                .first(Some("id"))
                .await
            },
            "Failed to initialize user key ID",
        )
        .await?;
        if row.is_none() {
            return Err(AppError::bad_request(
                "User key ID is already initialized",
            ));
        }
        Ok(())
    }

    pub async fn public_key(
        db: &D1Database,
        user: &str,
    ) -> AppResult<PublicKeyRow> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT id, public_key FROM users WHERE id=?1 AND \
                     public_key<>''",
                    user
                )?
                .first(None)
                .await
            },
            "Failed to fetch public key",
        )
        .await?
        .ok_or_else(|| AppError::not_found("Public key"))
    }
}

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
pub struct AccountKeysData {
    pub user_key_encrypted_account_private_key: String,
    pub account_public_key: String,
    pub public_key_encryption_key_pair: Option<PublicKeyEncryptionKeyPair>,
    pub signature_key_pair: Option<SignatureKeyPair>,
    pub security_state: Option<SecurityState>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEncryptionKeyPair {
    pub wrapped_private_key: String,
    pub public_key:          String,
    pub signed_public_key:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureKeyPair {
    pub signature_algorithm: String,
    pub wrapped_signing_key: String,
    pub verifying_key:       String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityState {
    pub security_state:   String,
    pub security_version: i32,
}

#[derive(Debug, Clone)]
pub struct ValidatedAccountKeys {
    pub private_key:        String,
    pub public_key:         String,
    pub signed_public_key:  Option<String>,
    pub security_state:     Option<String>,
    pub security_version:   Option<i32>,
    pub signature_key_pair: Option<String>,
}

impl AccountKeysData {
    pub fn validate(
        &self,
    ) -> Result<ValidatedAccountKeys, crate::errors::AppError> {
        use crate::errors::AppError;
        required(
            &self.user_key_encrypted_account_private_key,
            "UserKeyEncryptedAccountPrivateKey",
        )?;
        required(&self.account_public_key, "AccountPublicKey")?;
        let (private_key, public_key, signed_public_key) =
            match &self.public_key_encryption_key_pair {
                Some(pair) => {
                    required(&pair.wrapped_private_key, "WrappedPrivateKey")?;
                    required(&pair.public_key, "PublicKey")?;
                    (
                        pair.wrapped_private_key.clone(),
                        pair.public_key.clone(),
                        pair.signed_public_key.clone(),
                    )
                }
                None => (
                    self.user_key_encrypted_account_private_key.clone(),
                    self.account_public_key.clone(),
                    None,
                ),
            };
        if let Some(pair) = &self.signature_key_pair {
            required(&pair.signature_algorithm, "SignatureAlgorithm")?;
            required(&pair.wrapped_signing_key, "WrappedSigningKey")?;
            required(&pair.verifying_key, "VerifyingKey")?;
            if !matches!(
                pair.signature_algorithm.as_str(),
                "ed25519" | "mldsa44"
            ) {
                return Err(AppError::bad_request(
                    "Unsupported signature algorithm",
                ));
            }
        }
        if let Some(state) = &self.security_state {
            required(&state.security_state, "SecurityState")?;
            if state.security_state.encode_utf16().count() > 10_000 {
                return Err(AppError::bad_request(
                    "The field SecurityState must be a string with a maximum \
                     length of 10000.",
                ));
            }
        }
        let (security_state, security_version, signature_key_pair) = match (
            &signed_public_key,
            &self.signature_key_pair,
            &self.security_state,
        ) {
            (Some(signed), Some(pair), Some(state)) => {
                required(signed, "SignedPublicKey")?;
                (
                    Some(state.security_state.clone()),
                    Some(state.security_version),
                    Some(
                        serde_json::to_string(pair)
                            .map_err(|_| AppError::Internal)?,
                    ),
                )
            }
            (None, None, None) => (None, None, None),
            _ => {
                return Err(AppError::bad_request(
                    "Invalid account keys: the signed public key, signature \
                     key pair and security state must either all be present \
                     or all be absent",
                ));
            }
        };
        Ok(ValidatedAccountKeys {
            private_key,
            public_key,
            signed_public_key,
            security_state,
            security_version,
            signature_key_pair,
        })
    }
}

impl ValidatedAccountKeys {
    pub fn is_v2(&self) -> bool {
        self.signed_public_key.is_some() &&
            self.security_state.is_some() &&
            self.security_version.is_some()
    }
    pub fn validate_rotation(
        &self,
        user: &UserDB,
    ) -> Result<(), crate::errors::AppError> {
        use crate::errors::AppError;
        if self.public_key != user.public_key {
            return Err(AppError::bad_request(
                "Changing the asymmetric keypair is not possible during key \
                 rotation",
            ));
        }
        if !self.is_v2() {
            if user.is_v2() {
                return Err(AppError::bad_request(
                    "Cannot downgrade an account from v2 to v1 encryption \
                     during key rotation",
                ));
            }
            if self.private_key.split_once('.').map(|(kind, _)| kind) !=
                Some("2")
            {
                return Err(AppError::bad_request(
                    "The provided account private key was not wrapped with \
                     AES-256-CBC-HMAC",
                ));
            }
        } else {
            let pair: SignatureKeyPair = serde_json::from_str(
                self.signature_key_pair
                    .as_deref()
                    .ok_or(AppError::Internal)?,
            )
            .map_err(|_| AppError::Internal)?;
            if self.private_key.split_once('.').map(|(kind, _)| kind) !=
                Some("7") ||
                pair.wrapped_signing_key
                    .split_once('.')
                    .map(|(kind, _)| kind) !=
                    Some("7")
            {
                return Err(AppError::bad_request(
                    "The provided private keys must be wrapped with \
                     XChaCha20-Poly1305",
                ));
            }
            if user.is_v2() {
                let old: SignatureKeyPair = serde_json::from_str(
                    user.signature_key_pair.as_deref().ok_or_else(|| {
                        AppError::bad_request(
                            "The account is missing its signature key pair",
                        )
                    })?,
                )
                .map_err(|_| AppError::Internal)?;
                if pair.verifying_key != old.verifying_key {
                    return Err(AppError::bad_request(
                        "Changing the verifying key is not possible during \
                         key rotation",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountSnapshot {
    pub key:                String,
    pub user_key_id:        Option<String>,
    pub private_key:        String,
    pub public_key:         String,
    pub signed_public_key:  Option<String>,
    pub security_state:     Option<String>,
    pub security_version:   Option<i32>,
    pub signature_key_pair: Option<String>,
}
impl AccountSnapshot {
    pub fn from_user(user: &UserDB) -> Self {
        Self {
            key:                user.key.clone(),
            user_key_id:        user.user_key_id.clone(),
            private_key:        user.private_key.clone(),
            public_key:         user.public_key.clone(),
            signed_public_key:  user.signed_public_key.clone(),
            security_state:     user.security_state.clone(),
            security_version:   user.security_version,
            signature_key_pair: user.signature_key_pair.clone(),
        }
    }
    pub async fn load(db: &D1Database, user_id: &str) -> AppResult<Self> {
        db::run_query(
            async {
                db.prepare(
                    "SELECT key,user_key_id,private_key,public_key,\
                     signed_public_key,security_state,security_version,\
                     signature_key_pair FROM users WHERE id=?1",
                )
                .bind(&[user_id.into()])?
                .first(None)
                .await
            },
            "Failed to load account encryption state",
        )
        .await?
        .ok_or_else(|| AppError::not_found("Account"))
    }
    pub fn to_json(&self) -> AppResult<String> {
        serde_json::to_string(self).map_err(|_| AppError::Internal)
    }
    pub fn matches_sql(parameter: usize) -> String {
        [
            "key",
            "user_key_id",
            "private_key",
            "public_key",
            "signed_public_key",
            "security_state",
            "security_version",
            "signature_key_pair",
        ]
        .map(|column| {
            format!("{column} IS json_extract(?{parameter}, '$.{column}')")
        })
        .join(" AND ")
    }
}

pub fn is_valid_key_id(value: &str) -> bool {
    value.len() == 32 &&
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn response(user: &UserDB) -> Value {
    if user.private_key.is_empty() {
        return Value::Null;
    }
    let signature = user
        .signature_key_pair
        .as_deref()
        .and_then(|raw| serde_json::from_str::<SignatureKeyPair>(raw).ok())
        .filter(|_| user.is_v2());
    json!({"publicKeyEncryptionKeyPair":{"publicKey":user.public_key,"wrappedPrivateKey":user.private_key,"signedPublicKey":signature.as_ref().and(user.signed_public_key.as_ref()),"object":"publicKeyEncryptionKeyPair"},"signatureKeyPair":signature.as_ref().map(|pair|json!({"wrappedSigningKey":pair.wrapped_signing_key,"verifyingKey":pair.verifying_key,"object":"signatureKeyPair"})),"securityState":signature.as_ref().map(|_|json!({"securityState":user.security_state,"securityVersion":user.security_version})),"object":"privateKeys"})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user() -> UserDB {
        serde_json::from_value(json!({"id":"owner","email":"owner@example.test","email_verified":0,"master_password_hash":"hash","key":"wrapped-user","private_key":"2.private","public_key":"public","kdf_type":0,"kdf_iterations":600000,"security_stamp":"stamp","created_at":"now","updated_at":"now"})).unwrap()
    }
    fn v2() -> Value {
        json!({"userKeyEncryptedAccountPrivateKey":"7.private","accountPublicKey":"public","publicKeyEncryptionKeyPair":{"wrappedPrivateKey":"7.private","publicKey":"public","signedPublicKey":"signed"},"signatureKeyPair":{"signatureAlgorithm":"ed25519","wrappedSigningKey":"7.signing","verifyingKey":"verify"},"securityState":{"securityState":"state","securityVersion":2}})
    }
    #[test]
    fn v2_material_is_complete_or_rejected() {
        let valid: AccountKeysData = serde_json::from_value(v2()).unwrap();
        assert!(valid.validate().unwrap().is_v2());
        for field in ["signatureKeyPair", "securityState"] {
            let mut body = v2();
            body.as_object_mut().unwrap().remove(field);
            let keys: AccountKeysData = serde_json::from_value(body).unwrap();
            assert!(keys.validate().is_err());
        }
        let mut body = v2();
        body["signatureKeyPair"]["signatureAlgorithm"] = json!("unknown");
        assert!(
            serde_json::from_value::<AccountKeysData>(body)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    #[test]
    fn rotation_preserves_public_identity_and_prohibits_downgrade() {
        let keys: AccountKeysData = serde_json::from_value(v2()).unwrap();
        let keys = keys.validate().unwrap();
        let mut user = user();
        assert!(keys.validate_rotation(&user).is_ok());
        user.public_key = "different".into();
        assert!(keys.validate_rotation(&user).is_err());
        user.public_key = "public".into();
        user.signed_public_key = keys.signed_public_key.clone();
        user.security_state = keys.security_state.clone();
        user.security_version = keys.security_version;
        user.signature_key_pair = keys.signature_key_pair.clone();
        let old = ValidatedAccountKeys {
            private_key:        "2.private".into(),
            public_key:         "public".into(),
            signed_public_key:  None,
            security_state:     None,
            security_version:   None,
            signature_key_pair: None,
        };
        assert!(old.validate_rotation(&user).is_err());
        let mut changed = keys.clone();
        let mut pair: SignatureKeyPair = serde_json::from_str(
            changed.signature_key_pair.as_deref().unwrap(),
        )
        .unwrap();
        pair.verifying_key = "replacement".into();
        changed.signature_key_pair =
            Some(serde_json::to_string(&pair).unwrap());
        assert!(changed.validate_rotation(&user).is_err());
    }
    #[test]
    fn snapshot_detects_same_stamp_envelope_changes_and_new_ids_are_hex() {
        let mut user = user();
        let before = AccountSnapshot::from_user(&user);
        user.private_key = "7.upgraded".into();
        assert_ne!(before, AccountSnapshot::from_user(&user));
        assert_eq!(user.security_stamp, "stamp");
        assert!(is_valid_key_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_key_id("00000000-0000-4000-8000-000000000001"));
    }
}
