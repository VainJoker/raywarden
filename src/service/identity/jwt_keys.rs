//! Signing-key loading, envelope encryption and first-use policy.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use worker::{D1Database, Env};

use super::key_envelope::{self, OpenError};
use crate::{
    errors::{AppError, AppResult, ConfigError},
    infra::config::string_binding,
    models::identity::jwt_keys::{self, JwtKeysRow},
};

const CIPHERTEXT_PREFIX: &str = "v1.";
const ACCESS_CONTEXT: &[u8] = b"raywarden/jwt-key-encryption/v1/global/access_secret";
const REFRESH_CONTEXT: &[u8] = b"raywarden/jwt-key-encryption/v1/global/refresh_secret";

struct KeyEncryptionKey([u8; 32]);

impl KeyEncryptionKey {
    fn parse(value: &str) -> AppResult<Self> {
        let invalid = || {
            AppError::from(ConfigError::Invalid(
                "KEY_ENCRYPTION_KEY must be a 32-byte unpadded base64url string",
            ))
        };
        let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_error| invalid())?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(invalid());
        }
        Ok(Self(bytes.try_into().map_err(|_error| invalid())?))
    }

    fn seal_with_nonce(&self, value: &str, context: &[u8], nonce: [u8; 12]) -> AppResult<String> {
        key_envelope::seal(&self.0, CIPHERTEXT_PREFIX, context, value, nonce).map_err(
            AppError::internal_discard("Failed to encrypt JWT signing key"),
        )
    }

    fn seal(&self, value: &str, context: &[u8]) -> AppResult<String> {
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|error| {
            AppError::internal_with_context("JWT nonce generation failed", error)
        })?;
        self.seal_with_nonce(value, context, nonce)
    }

    fn open(&self, value: &str, context: &[u8]) -> AppResult<String> {
        key_envelope::open(&self.0, CIPHERTEXT_PREFIX, context, value).map_err(|error| {
            AppError::internal(match error {
                OpenError::InvalidEnvelope => {
                    "Stored JWT signing keys have an invalid or unsupported envelope"
                }
                OpenError::InvalidCiphertext => {
                    "Failed to decrypt stored JWT signing keys; verify KEY_ENCRYPTION_KEY"
                }
            })
        })
    }

    fn wrap(&self, keys: &JwtKeys) -> AppResult<JwtKeysRow> {
        Ok(JwtKeysRow {
            access_secret: self.seal(&keys.access_secret, ACCESS_CONTEXT)?,
            refresh_secret: self.seal(&keys.refresh_secret, REFRESH_CONTEXT)?,
        })
    }

    fn unwrap(&self, row: &JwtKeysRow) -> AppResult<JwtKeys> {
        let keys = JwtKeys {
            access_secret: self.open(&row.access_secret, ACCESS_CONTEXT)?,
            refresh_secret: self.open(&row.refresh_secret, REFRESH_CONTEXT)?,
        };
        validate_stored_keys(&keys.access_secret, &keys.refresh_secret)?;
        Ok(keys)
    }
}

pub(crate) struct JwtKeys {
    pub access_secret: String,
    pub refresh_secret: String,
}

fn validate_stored_keys(access: &str, refresh: &str) -> AppResult<()> {
    if access.trim().is_empty() || refresh.trim().is_empty() {
        return Err(AppError::internal("Stored JWT keys are empty"));
    }
    Ok(())
}

fn random_secret() -> AppResult<String> {
    let mut bytes = [0; 64];
    getrandom::fill(&mut bytes)
        .map_err(|error| AppError::internal_with_context("JWT key generation failed", error))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The D1 row is authoritative across Workers and Durable Objects.
/// Read errors are fatal; only an absent row on an empty database permits
/// first-time initialization.
pub(crate) async fn load(env: &Env, db: &D1Database) -> AppResult<JwtKeys> {
    let raw_key = string_binding(env, "KEY_ENCRYPTION_KEY")
        .map_err(|_error| ConfigError::Invalid("KEY_ENCRYPTION_KEY must be a readable string"))?
        .ok_or(ConfigError::Missing("KEY_ENCRYPTION_KEY"))?;
    let key = KeyEncryptionKey::parse(&raw_key)?;
    if let Some(row) = jwt_keys::find(db).await? {
        return key.unwrap(&row);
    }
    let wrapped = key.wrap(&JwtKeys {
        access_secret: random_secret()?,
        refresh_secret: random_secret()?,
    })?;
    jwt_keys::initialize_if_empty(db, wrapped).await?;
    let row = jwt_keys::find(db).await?.ok_or_else(|| {
        AppError::internal("JWT keys are missing from a populated database; restore the key row")
    })?;
    key.unwrap(&row)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    #[test]
    fn kek_parses_strict_base64url_and_binds_aad_context() {
        let key = KeyEncryptionKey::parse(TEST_KEY).expect("key");
        assert!(KeyEncryptionKey::parse(&format!("{TEST_KEY}=")).is_err());
        assert!(KeyEncryptionKey::parse(&URL_SAFE_NO_PAD.encode([0; 31])).is_err());

        let orig = JwtKeys {
            access_secret: "access".into(),
            refresh_secret: "refresh".into(),
        };
        let wrapped = key.wrap(&orig).expect("wrap");
        assert_eq!(
            key.unwrap(&wrapped).expect("unwrap").access_secret,
            "access"
        );
        let sealed = key
            .seal_with_nonce("secret", ACCESS_CONTEXT, [7; 12])
            .expect("seal");
        assert!(
            KeyEncryptionKey([9; 32])
                .open(&sealed, ACCESS_CONTEXT)
                .is_err()
        );
        assert!(key.open(&sealed, REFRESH_CONTEXT).is_err());
    }
}
