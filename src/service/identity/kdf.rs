use std::borrow::Cow;

use hmac::{Hmac, Mac as _};
use sha2::Sha256;

use crate::{
    errors::{AppError, AppResult, AuthError},
    service::identity::user::KdfParams,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub(crate) enum KdfKind {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl TryFrom<i32> for KdfKind {
    type Error = AppError;

    fn try_from(value: i32) -> AppResult<Self> {
        match value {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            _ => Err(invalid_kdf(
                "Unsupported KDF type. Only PBKDF2 (0) and Argon2id (1) are supported",
            )),
        }
    }
}

pub(crate) enum ValidatedKdfParams {
    Pbkdf2 {
        iterations: i32,
    },
    Argon2id {
        iterations: i32,
        memory_mb: i32,
        parallelism: i32,
    },
}

pub const MIN_PBKDF2_ITERATIONS: i32 = 100_000;
pub const DEFAULT_PBKDF2_ITERATIONS: i32 = 600_000;

/// Common client configurations used only when prelogin finds no account.
///
/// The repeated Argon2 entry preserves the reference distribution. Legacy
/// PBKDF2 settings do not change validation for real account writes.
const UNKNOWN_EMAIL_KDFS: [(KdfKind, i32, Option<i32>, Option<i32>); 7] = [
    (KdfKind::Argon2id, 3, Some(64), Some(4)),
    (KdfKind::Argon2id, 3, Some(64), Some(4)),
    (KdfKind::Pbkdf2, 100_000, None, None),
    (KdfKind::Pbkdf2, 5_000, None, None),
    (KdfKind::Argon2id, 3, Some(64), Some(4)),
    (KdfKind::Argon2id, 6, Some(32), Some(4)),
    (KdfKind::Pbkdf2, DEFAULT_PBKDF2_ITERATIONS, None, None),
];
const PRELOGIN_KDF_CONTEXT: &[u8] = b"raywarden/prelogin-kdf/v1\0";

/// Derive stable decoy settings from the persisted signing key and the already
/// normalized email. Real account parameters must come from their stored row.
/// This reduces a fixed-response fingerprint; it cannot eliminate enumeration.
pub fn unknown_email_kdf(secret: &str, normalized_email: &str) -> AppResult<KdfParams> {
    if secret.trim().is_empty() {
        return Err(AppError::Internal);
    }
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(AppError::internal_error)?;
    mac.update(PRELOGIN_KDF_CONTEXT);
    mac.update(normalized_email.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut first = [0; 8];
    first.copy_from_slice(&digest[..8]);
    // Reduce before converting: usize is 32-bit in the actual Worker.
    let index = (u64::from_be_bytes(first) % UNKNOWN_EMAIL_KDFS.len() as u64) as usize;
    let (kind, iterations, memory, parallelism) = UNKNOWN_EMAIL_KDFS[index];
    Ok(KdfParams {
        kdf_type: kind as i32,
        iterations,
        memory,
        parallelism,
    })
}

pub(crate) fn validate_stored_kdf(params: &KdfParams) -> AppResult<()> {
    if params.kdf_type == KdfKind::Pbkdf2 as i32 {
        // Existing accounts may predate the current write-side minimum.
        return if params.iterations > 0 {
            Ok(())
        } else {
            Err(AppError::InternalFailure(
                "Stored PBKDF2 iterations must be positive".into(),
            ))
        };
    }
    ValidatedKdfParams::try_from(params.clone())
        .map(|_| ())
        .map_err(|error| AppError::internal_with_context("Invalid stored KDF settings", error))
}

impl TryFrom<KdfParams> for ValidatedKdfParams {
    type Error = AppError;

    fn try_from(params: KdfParams) -> AppResult<Self> {
        let iterations = params.iterations;
        match KdfKind::try_from(params.kdf_type)? {
            KdfKind::Pbkdf2 => {
                if iterations < MIN_PBKDF2_ITERATIONS {
                    return Err(invalid_kdf(format!(
                        "PBKDF2 iterations must be at least {MIN_PBKDF2_ITERATIONS}"
                    )));
                }
                Ok(Self::Pbkdf2 { iterations })
            }
            KdfKind::Argon2id => {
                if iterations < 1 {
                    return Err(invalid_kdf("Argon2 KDF iterations must be at least 1"));
                }
                let memory_mb = params
                    .memory
                    .ok_or_else(|| invalid_kdf("Argon2 memory parameter is required"))?;
                if !(15..=1024).contains(&memory_mb) {
                    return Err(invalid_kdf(
                        "Argon2 memory must be between 15 MB and 1024 MB",
                    ));
                }
                let parallelism = params
                    .parallelism
                    .ok_or_else(|| invalid_kdf("Argon2 parallelism parameter is required"))?;
                if !(1..=16).contains(&parallelism) {
                    return Err(invalid_kdf("Argon2 parallelism must be between 1 and 16"));
                }
                Ok(Self::Argon2id {
                    iterations,
                    memory_mb,
                    parallelism,
                })
            }
        }
    }
}

impl From<ValidatedKdfParams> for KdfParams {
    fn from(params: ValidatedKdfParams) -> Self {
        let (kind, iterations, memory, parallelism) = match params {
            ValidatedKdfParams::Pbkdf2 { iterations } => (KdfKind::Pbkdf2, iterations, None, None),
            ValidatedKdfParams::Argon2id {
                iterations,
                memory_mb,
                parallelism,
            } => (
                KdfKind::Argon2id,
                iterations,
                Some(memory_mb),
                Some(parallelism),
            ),
        };
        Self {
            kdf_type: kind as i32,
            iterations,
            memory,
            parallelism,
        }
    }
}

fn invalid_kdf(message: impl Into<Cow<'static, str>>) -> AppError {
    AppError::Auth(AuthError::InvalidKdf(message.into()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn tuple(value: &KdfParams) -> (i32, i32, Option<i32>, Option<i32>) {
        (
            value.kdf_type,
            value.iterations,
            value.memory,
            value.parallelism,
        )
    }

    #[test]
    fn unknown_email_settings_are_stable_and_have_a_cross_target_vector() {
        let secret = "prelogin-test-secret";
        let email = "unknown@example.test";
        let first = unknown_email_kdf(secret, email).expect("valid kdf fixture");
        assert_eq!(
            unknown_email_kdf(secret, email).expect("valid kdf fixture"),
            first
        );
        // The keyed digest starts with 0x410923d625a37e9b. Taking modulo 7
        // before usize conversion must select the same bucket on WASM32.
        assert_eq!(
            tuple(&first),
            (KdfKind::Argon2id as i32, 6, Some(32), Some(4))
        );
    }

    #[test]
    fn unknown_emails_cover_common_settings_without_relaxing_registration() {
        let seen = (0..256)
            .map(|index| {
                tuple(
                    &unknown_email_kdf(
                        "prelogin-test-secret",
                        &format!("unknown-{index}@example.test"),
                    )
                    .expect("valid kdf fixture"),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            seen,
            UNKNOWN_EMAIL_KDFS
                .into_iter()
                .map(|(kind, i, m, p)| (kind as i32, i, m, p))
                .collect()
        );
        assert!(
            ValidatedKdfParams::try_from(KdfParams {
                kdf_type: KdfKind::Pbkdf2 as i32,
                iterations: 5_000,
                memory: None,
                parallelism: None,
            })
            .is_err()
        );
    }

    #[test]
    fn unknown_email_settings_depend_on_the_persisted_key() {
        let settings = |secret| {
            (0..32)
                .map(|index| {
                    tuple(
                        &unknown_email_kdf(secret, &format!("unknown-{index}@example.test"))
                            .expect("valid kdf fixture"),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_ne!(
            settings("prelogin-test-secret"),
            settings("different-persisted-secret")
        );
    }

    #[test]
    fn unknown_email_settings_reject_missing_key_material() {
        for secret in ["", " ", "\n"] {
            assert!(unknown_email_kdf(secret, "unknown@example.test").is_err());
        }
    }
}
