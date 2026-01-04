use crate::errors::{
    AppError,
    AuthError,
};

pub const KDF_TYPE_PBKDF2: i32 = 0;
pub const KDF_TYPE_ARGON2ID: i32 = 1;

pub const MIN_PBKDF2_ITERATIONS: i32 = 100_000;
pub const DEFAULT_PBKDF2_ITERATIONS: i32 = 600_000;

/// Validate KDF parameters coming from client payloads.
///
/// This is used by registration and can be reused elsewhere.
pub fn ensure_supported_kdf(
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> Result<(), AppError> {
    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            if iterations < MIN_PBKDF2_ITERATIONS {
                return Err(AppError::Auth(AuthError::InvalidKDF(format!(
                    "PBKDF2 iterations must be at least \
                     {MIN_PBKDF2_ITERATIONS}"
                ))));
            }
        }
        KDF_TYPE_ARGON2ID => {
            if iterations < 1 {
                return Err(AppError::Auth(AuthError::InvalidKDF(
                    "Argon2 KDF iterations must be at least 1".to_string(),
                )));
            }

            match memory {
                Some(m) if (15..=1024).contains(&m) => {}
                Some(_) => {
                    return Err(AppError::Auth(AuthError::InvalidKDF(
                        "Argon2 memory must be between 15 MB and 1024 MB"
                            .to_string(),
                    )));
                }
                None => {
                    return Err(AppError::Auth(AuthError::InvalidKDF(
                        "Argon2 memory parameter is required".to_string(),
                    )));
                }
            }

            match parallelism {
                Some(p) if (1..=16).contains(&p) => {}
                Some(_) => {
                    return Err(AppError::Auth(AuthError::InvalidKDF(
                        "Argon2 parallelism must be between 1 and 16"
                            .to_string(),
                    )));
                }
                None => {
                    return Err(AppError::Auth(AuthError::InvalidKDF(
                        "Argon2 parallelism parameter is required".to_string(),
                    )));
                }
            }
        }
        _ => {
            return Err(AppError::Auth(AuthError::InvalidKDF(
                "Unsupported KDF type. Only PBKDF2 (0) and Argon2id (1) are \
                 supported"
                    .to_string(),
            )));
        }
    }

    Ok(())
}

pub fn validate_rotation_metadata(
    user: &crate::models::user::User,
    unlock_data: &crate::models::user::MasterPasswordUnlockData,
    account_public_key: &str,
) -> Result<(), AppError> {
    let kdf_matches = user.kdf_type == unlock_data.kdf_type &&
        user.kdf_iterations == unlock_data.kdf_iterations &&
        user.kdf_memory == unlock_data.kdf_memory &&
        user.kdf_parallelism == unlock_data.kdf_parallelism;

    if user.email != unlock_data.email || !kdf_matches {
        log::error!(
            "KDF/email mismatch in rotation request: email_equal={}, \
             kdf_equal={}",
            user.email == unlock_data.email,
            kdf_matches
        );
        return Err(AppError::Auth(AuthError::InvalidKDF(
            "Changing the kdf variant or email is not supported during key \
             rotation"
                .to_string(),
        )));
    }

    if user.public_key != account_public_key {
        log::error!(
            "Public key mismatch in rotation request: stored != provided"
        );
        return Err(AppError::Auth(AuthError::InvalidKDF(
            "Changing the asymmetric keypair is not supported during key \
             rotation"
                .to_string(),
        )));
    }

    Ok(())
}
