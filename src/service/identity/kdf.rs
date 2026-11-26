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
        return Err(AppError::internal("Prelogin KDF secret is empty"));
    }
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(|error| AppError::internal_debug("Failed to initialize prelogin HMAC", error))?;
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
            Err(AppError::internal(
                "Stored PBKDF2 iterations must be positive",
            ))
        };
    }
    ValidatedKdfParams::try_from(*params)
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
    use super::*;

    #[test]
    fn unknown_email_kdf_has_cross_target_vector_and_enforces_bounds() {
        let first = unknown_email_kdf("prelogin-test-secret", "unknown@example.test").expect("kdf");
        assert_eq!(
            (
                first.kdf_type,
                first.iterations,
                first.memory,
                first.parallelism
            ),
            (KdfKind::Argon2id as i32, 6, Some(32), Some(4))
        );
        let sample = |secret| {
            (0..8)
                .map(|i| unknown_email_kdf(secret, &format!("u{i}@example.test")).expect("kdf"))
                .collect::<Vec<_>>()
        };
        assert_ne!(sample("prelogin-test-secret"), sample("other-secret"));
        assert!(unknown_email_kdf(" ", "unknown@example.test").is_err());
        assert!(
            ValidatedKdfParams::try_from(KdfParams {
                kdf_type: 0,
                iterations: 5_000,
                memory: None,
                parallelism: None
            })
            .is_err()
        );
    }
}
