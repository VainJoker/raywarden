//! Signing-key loading, envelope encryption and first-use policy.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use worker::{D1Database, Env};

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
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(AppError::internal_error)?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(AppError::Internal);
        }
        Ok(Self(bytes.try_into().map_err(AppError::internal_error)?))
    }

    fn seal_with_nonce(&self, value: &str, context: &[u8], nonce: [u8; 12]) -> AppResult<String> {
        let cipher = Aes256Gcm::new_from_slice(&self.0).map_err(AppError::internal_error)?;
        let encrypted = cipher
            .encrypt(&Nonce::from(nonce), Payload {
                msg: value.as_bytes(),
                aad: context,
            })
            .map_err(AppError::internal_error)?;
        let mut packed = nonce.to_vec();
        packed.extend_from_slice(&encrypted);
        Ok(format!(
            "{CIPHERTEXT_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(packed)
        ))
    }

    fn seal(&self, value: &str, context: &[u8]) -> AppResult<String> {
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(AppError::internal_error)?;
        self.seal_with_nonce(value, context, nonce)
    }

    fn open(&self, value: &str, context: &[u8]) -> AppResult<String> {
        let encoded = value
            .strip_prefix(CIPHERTEXT_PREFIX)
            .ok_or(AppError::Internal)?;
        let packed = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(AppError::internal_error)?;
        if packed.len() < 28 || URL_SAFE_NO_PAD.encode(&packed) != encoded {
            return Err(AppError::Internal);
        }
        let nonce: [u8; 12] = packed[..12].try_into().map_err(AppError::internal_error)?;
        let cipher = Aes256Gcm::new_from_slice(&self.0).map_err(AppError::internal_error)?;
        let plaintext = cipher
            .decrypt(&Nonce::from(nonce), Payload {
                msg: &packed[12..],
                aad: context,
            })
            .map_err(AppError::internal_error)?;
        String::from_utf8(plaintext).map_err(AppError::internal_error)
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

impl JwtKeys {
    fn into_row(self) -> JwtKeysRow {
        JwtKeysRow {
            access_secret: self.access_secret,
            refresh_secret: self.refresh_secret,
        }
    }
}

fn validate_stored_keys(access: &str, refresh: &str) -> AppResult<()> {
    if access.trim().is_empty() || refresh.trim().is_empty() {
        return Err(AppError::InternalFailure(
            "Stored JWT keys are empty".into(),
        ));
    }
    Ok(())
}

enum StoredJwtKeys {
    Wrapped(JwtKeysRow),
    Legacy(JwtKeys),
}

impl StoredJwtKeys {
    fn parse(row: JwtKeysRow) -> AppResult<Self> {
        validate_stored_keys(&row.access_secret, &row.refresh_secret)?;
        let access = row.access_secret.starts_with(CIPHERTEXT_PREFIX);
        let refresh = row.refresh_secret.starts_with(CIPHERTEXT_PREFIX);
        if access != refresh {
            return Err(AppError::Internal);
        }
        if access {
            return Ok(Self::Wrapped(row));
        }
        // Reserve version-looking prefixes so unsupported envelopes cannot
        // be mistaken for legacy plaintext and encrypted a second time.
        for value in [&row.access_secret, &row.refresh_secret] {
            if let Some((version, _)) = value.split_once('.')
                && version.strip_prefix('v').is_some_and(|digits| {
                    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
                })
            {
                return Err(AppError::Internal);
            }
        }
        Ok(Self::Legacy(JwtKeys {
            access_secret: row.access_secret,
            refresh_secret: row.refresh_secret,
        }))
    }
}

fn random_secret() -> AppResult<String> {
    let mut bytes = [0; 64];
    getrandom::fill(&mut bytes)
        .map_err(|error| AppError::internal_with_context("JWT key generation failed", error))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn initial_keys(access: Option<String>, refresh: Option<String>) -> AppResult<JwtKeys> {
    match (access, refresh) {
        (None, None) => Ok(JwtKeys {
            access_secret: random_secret()?,
            refresh_secret: random_secret()?,
        }),
        (Some(access_secret), Some(refresh_secret))
            if !access_secret.trim().is_empty() && !refresh_secret.trim().is_empty() =>
        {
            // Preserve the original bytes: the access key also wraps API keys.
            Ok(JwtKeys {
                access_secret,
                refresh_secret,
            })
        }
        _ => Err(ConfigError::Invalid(
            "First JWT initialization requires both nonblank legacy JWT \
             secrets or neither"
                .into(),
        )
        .into()),
    }
}

/// The D1 row is authoritative across Workers and Durable Objects.
/// Read errors are fatal; only an absent row permits first-time initialization.
pub(crate) async fn load(env: &Env, db: &D1Database) -> AppResult<JwtKeys> {
    // This independent Secret is required even while importing legacy rows.
    // Neither a database error nor a missing/wrong external key permits a
    // plaintext or random-key fallback.
    let key = KeyEncryptionKey::parse(
        &string_binding(env, "KEY_ENCRYPTION_KEY")?.ok_or(AppError::Internal)?,
    )?;
    if let Some(row) = jwt_keys::find(db).await? {
        return match StoredJwtKeys::parse(row)? {
            StoredJwtKeys::Wrapped(row) => key.unwrap(&row),
            StoredJwtKeys::Legacy(keys) => {
                let wrapped = key.wrap(&keys)?;
                jwt_keys::wrap_if_current(db, keys.into_row(), wrapped).await?;
                // Read the winner of the guarded write, which may be another
                // Worker. It must already be encrypted.
                let row = jwt_keys::find(db).await?.ok_or(AppError::Internal)?;
                key.unwrap(&row)
            }
        };
    }
    let legacy_key = |name| {
        string_binding(env, name)
            .map_err(|_error| ConfigError::Invalid(format!("{name} must be a readable string")))
    };
    let access = legacy_key("JWT_SECRET")?;
    let refresh = legacy_key("JWT_REFRESH_SECRET")?;
    let importing_legacy = access.is_some() && refresh.is_some();
    let wrapped = key.wrap(&initial_keys(access, refresh)?)?;
    jwt_keys::initialize_if_allowed(db, wrapped, importing_legacy).await?;
    // A concurrent initializer may have won; never use an unpersisted
    // candidate.
    let row = jwt_keys::find(db).await?.ok_or_else(|| {
        // Generating replacement keys here would invalidate persisted API
        // key ciphertext as well as tokens after a partial database
        // restore.
        AppError::InternalFailure(
            "JWT keys are missing from a populated database; restore the key \
             row or import both original legacy secrets"
                .into(),
        )
    })?;
    key.unwrap(&row)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    #[test]
    fn encryption_key_requires_canonical_32_byte_base64url() {
        assert!(KeyEncryptionKey::parse(TEST_KEY).is_ok());
        for value in [
            String::new(),
            format!(" {TEST_KEY}"),
            format!("{TEST_KEY}="),
            URL_SAFE_NO_PAD.encode([0; 31]),
            URL_SAFE_NO_PAD.encode([0; 33]),
            TEST_KEY.replace('8', "9"),
            "+/8=".to_owned(),
        ] {
            assert!(KeyEncryptionKey::parse(&value).is_err());
        }
    }

    #[test]
    fn wrapping_preserves_original_utf8_bytes_with_independent_nonces() {
        let key = KeyEncryptionKey::parse(TEST_KEY).expect("test fixture should be valid");
        let original = JwtKeys {
            access_secret: " access \0bytes-é ".into(),
            refresh_secret: " refresh \r\n ".into(),
        };
        let first = key.wrap(&original).expect("test fixture should be valid");
        let second = key.wrap(&original).expect("test fixture should be valid");
        assert_ne!(first.access_secret, second.access_secret);
        assert_ne!(first.refresh_secret, second.refresh_secret);
        let Ok(StoredJwtKeys::Wrapped(first)) = StoredJwtKeys::parse(first) else {
            panic!("wrapped keys should be recognized");
        };
        let opened = key.unwrap(&first).expect("test fixture should be valid");
        assert_eq!(opened.access_secret, original.access_secret);
        assert_eq!(opened.refresh_secret, original.refresh_secret);
        assert!(matches!(
            StoredJwtKeys::parse(original.into_row()),
            Ok(StoredJwtKeys::Legacy(_))
        ));
    }

    #[test]
    fn wrapping_rejects_wrong_key_tampering_truncation_and_wrong_context() {
        let key = KeyEncryptionKey::parse(TEST_KEY).expect("test fixture should be valid");
        let value = key
            .seal_with_nonce(" original access ", ACCESS_CONTEXT, [7; 12])
            .expect("test fixture should be valid");
        assert_eq!(
            key.open(&value, ACCESS_CONTEXT)
                .expect("test fixture should be valid"),
            " original access "
        );
        assert!(
            KeyEncryptionKey([9; 32])
                .open(&value, ACCESS_CONTEXT)
                .is_err()
        );
        assert!(key.open(&value, REFRESH_CONTEXT).is_err());
        assert!(
            key.open(
                &value,
                b"raywarden/jwt-key-encryption/v1/other/access_secret"
            )
            .is_err()
        );
        let mut packed = URL_SAFE_NO_PAD
            .decode(&value[3..])
            .expect("test fixture should be valid");
        for position in [0, 12, packed.len() - 1] {
            packed[position] ^= 1;
            let tampered = format!("v1.{}", URL_SAFE_NO_PAD.encode(&packed));
            assert!(key.open(&tampered, ACCESS_CONTEXT).is_err());
            packed[position] ^= 1;
        }
        for invalid in [
            "plaintext".to_owned(),
            value.replacen("v1.", "v2.", 1),
            "v1.!".to_owned(),
            format!("v1.{}", URL_SAFE_NO_PAD.encode([0; 27])),
            format!("{value}="),
        ] {
            assert!(key.open(&invalid, ACCESS_CONTEXT).is_err());
        }
    }

    #[test]
    fn mixed_and_unsupported_versions_never_become_legacy_plaintext() {
        for (access, refresh) in [
            ("v1.encrypted", "plain"),
            ("plain", "v1.encrypted"),
            ("v2.encrypted", "v2.encrypted"),
            ("v99.encrypted", "plain"),
        ] {
            assert!(
                StoredJwtKeys::parse(JwtKeysRow {
                    access_secret: access.into(),
                    refresh_secret: refresh.into(),
                })
                .is_err()
            );
        }
    }

    #[test]
    fn missing_legacy_keys_generate_two_independent_secrets() {
        let keys = initial_keys(None, None).expect("test fixture should be valid");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&keys.access_secret)
                .expect("test fixture should be valid")
                .len(),
            64
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&keys.refresh_secret)
                .expect("test fixture should be valid")
                .len(),
            64
        );
        assert_ne!(keys.access_secret, keys.refresh_secret);
    }

    #[test]
    fn legacy_bootstrap_preserves_exact_bytes_and_rejects_partial_configuration() {
        let keys = initial_keys(Some(" access ".into()), Some(" refresh ".into()))
            .expect("test fixture should be valid");
        assert_eq!(keys.access_secret, " access ");
        assert_eq!(keys.refresh_secret, " refresh ");
        for pair in [
            (Some("one".into()), None),
            (None, Some("two".into())),
            (Some(String::new()), Some("two".into())),
            (Some("one".into()), Some(" ".into())),
        ] {
            assert!(matches!(
                initial_keys(pair.0, pair.1),
                Err(AppError::Config(ConfigError::Invalid(_)))
            ));
        }
    }

    #[test]
    fn a_decrypted_blank_jwt_key_is_an_internal_failure() {
        let key = KeyEncryptionKey::parse(TEST_KEY).expect("valid fixture key");
        let row = JwtKeysRow {
            access_secret: key
                .seal_with_nonce(" ", ACCESS_CONTEXT, [1; 12])
                .expect("valid fixture envelope"),
            refresh_secret: key
                .seal_with_nonce("refresh", REFRESH_CONTEXT, [2; 12])
                .expect("valid fixture envelope"),
        };
        assert!(matches!(
            key.unwrap(&row),
            Err(AppError::InternalFailure(_))
        ));
    }
}
