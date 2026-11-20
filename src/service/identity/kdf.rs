use hmac::{
    Hmac,
    Mac as _,
};
use sha2::Sha256;

use crate::{
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    service::identity::user::KdfParams,
};

pub const KDF_TYPE_PBKDF2: i32 = 0;
pub const KDF_TYPE_ARGON2ID: i32 = 1;

pub const MIN_PBKDF2_ITERATIONS: i32 = 100_000;
pub const DEFAULT_PBKDF2_ITERATIONS: i32 = 600_000;

/// Common client configurations used only when prelogin finds no account.
///
/// The repeated Argon2 entry preserves the reference distribution. Legacy
/// PBKDF2 settings do not change validation for real account writes.
const UNKNOWN_EMAIL_KDFS: [(i32, i32, Option<i32>, Option<i32>); 7] = [
    (KDF_TYPE_ARGON2ID, 3, Some(64), Some(4)),
    (KDF_TYPE_ARGON2ID, 3, Some(64), Some(4)),
    (KDF_TYPE_PBKDF2, 100_000, None, None),
    (KDF_TYPE_PBKDF2, 5_000, None, None),
    (KDF_TYPE_ARGON2ID, 3, Some(64), Some(4)),
    (KDF_TYPE_ARGON2ID, 6, Some(32), Some(4)),
    (KDF_TYPE_PBKDF2, DEFAULT_PBKDF2_ITERATIONS, None, None),
];
const PRELOGIN_KDF_CONTEXT: &[u8] = b"raywarden/prelogin-kdf/v1\0";

/// Derive stable decoy settings from the persisted signing key and the already
/// normalized email. Real account parameters must come from their stored row.
/// This reduces a fixed-response fingerprint; it cannot eliminate enumeration.
pub fn unknown_email_kdf(
    secret: &str,
    normalized_email: &str,
) -> AppResult<KdfParams> {
    if secret.trim().is_empty() {
        return Err(AppError::Internal);
    }
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(
        secret.as_bytes(),
    )
    .map_err(AppError::internal_error)?;
    mac.update(PRELOGIN_KDF_CONTEXT);
    mac.update(normalized_email.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut first = [0; 8];
    first.copy_from_slice(&digest[..8]);
    // Reduce before converting: usize is 32-bit in the actual Worker.
    let index =
        (u64::from_be_bytes(first) % UNKNOWN_EMAIL_KDFS.len() as u64) as usize;
    let (kdf_type, iterations, memory, parallelism) = UNKNOWN_EMAIL_KDFS[index];
    Ok(KdfParams {
        kdf_type,
        iterations,
        memory,
        parallelism,
    })
}

/// Validate KDF parameters coming from client payloads.
///
/// This is used by registration and can be reused elsewhere.
pub fn ensure_supported_kdf(
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> AppResult<()> {
    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            if iterations < MIN_PBKDF2_ITERATIONS {
                return Err(AppError::Auth(AuthError::InvalidKdf(format!(
                    "PBKDF2 iterations must be at least \
                     {MIN_PBKDF2_ITERATIONS}"
                ))));
            }
        }
        KDF_TYPE_ARGON2ID => {
            if iterations < 1 {
                return Err(AppError::Auth(AuthError::InvalidKdf(
                    "Argon2 KDF iterations must be at least 1".to_string(),
                )));
            }

            match memory {
                Some(m) if (15..=1024).contains(&m) => {}
                Some(_) => {
                    return Err(AppError::Auth(AuthError::InvalidKdf(
                        "Argon2 memory must be between 15 MB and 1024 MB"
                            .to_string(),
                    )));
                }
                None => {
                    return Err(AppError::Auth(AuthError::InvalidKdf(
                        "Argon2 memory parameter is required".to_string(),
                    )));
                }
            }

            match parallelism {
                Some(p) if (1..=16).contains(&p) => {}
                Some(_) => {
                    return Err(AppError::Auth(AuthError::InvalidKdf(
                        "Argon2 parallelism must be between 1 and 16"
                            .to_string(),
                    )));
                }
                None => {
                    return Err(AppError::Auth(AuthError::InvalidKdf(
                        "Argon2 parallelism parameter is required".to_string(),
                    )));
                }
            }
        }
        _ => {
            return Err(AppError::Auth(AuthError::InvalidKdf(
                "Unsupported KDF type. Only PBKDF2 (0) and Argon2id (1) are \
                 supported"
                    .to_string(),
            )));
        }
    }

    Ok(())
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
        let first =
            unknown_email_kdf(secret, email).expect("valid kdf fixture");
        assert_eq!(
            unknown_email_kdf(secret, email).expect("valid kdf fixture"),
            first
        );
        // The keyed digest starts with 0x410923d625a37e9b. Taking modulo 7
        // before usize conversion must select the same bucket on WASM32.
        assert_eq!(tuple(&first), (KDF_TYPE_ARGON2ID, 6, Some(32), Some(4)));
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
        assert_eq!(seen, UNKNOWN_EMAIL_KDFS.into_iter().collect());
        assert!(
            ensure_supported_kdf(KDF_TYPE_PBKDF2, 5_000, None, None).is_err()
        );
    }

    #[test]
    fn unknown_email_settings_depend_on_the_persisted_key() {
        let settings = |secret| {
            (0..32)
                .map(|index| {
                    tuple(
                        &unknown_email_kdf(
                            secret,
                            &format!("unknown-{index}@example.test"),
                        )
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
