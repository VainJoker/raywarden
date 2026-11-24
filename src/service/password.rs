//! The persisted PBKDF2 verifier format shared by accounts and Send.
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::{
    errors::{AppResult, CryptoError},
    infra::crypto::pbkdf2_sha256,
    utils::constant_time_eq,
};

const DERIVED_KEY_BITS: u32 = 256;

pub(super) async fn hash_password_for_storage(
    password: &str,
    salt: &str,
    iterations: u32,
) -> AppResult<String> {
    if iterations == 0 {
        return Err(CryptoError::Pbkdf2Failed("zero iterations").into());
    }
    let salt_bytes = BASE64
        .decode(salt)
        .map_err(|_error| CryptoError::RandomGenerationFailed("decode persisted salt"))?;

    let derived = pbkdf2_sha256(
        password.as_bytes(),
        &salt_bytes,
        iterations,
        DERIVED_KEY_BITS,
    )
    .await?;

    Ok(BASE64.encode(derived))
}

pub(super) async fn verify_password(
    password: &str,
    stored_hash: &str,
    salt: &str,
    iterations: u32,
) -> AppResult<bool> {
    let computed_hash = hash_password_for_storage(password, salt, iterations).await?;
    Ok(constant_time_eq(
        computed_hash.as_bytes(),
        stored_hash.as_bytes(),
    ))
}
