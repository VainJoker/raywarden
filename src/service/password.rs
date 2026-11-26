//! The persisted PBKDF2 verifier format shared by accounts and Send.
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::{
    errors::{AppResult, CryptoError},
    utils::constant_time_eq,
};

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
        .map_err(|_error| CryptoError::Pbkdf2Failed("decode persisted salt"))?;

    // Use one implementation for all persisted account and Send costs. Workers'
    // Web Crypto PBKDF2 ceiling does not apply to RustCrypto.
    let derived =
        pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(password.as_bytes(), &salt_bytes, iterations);

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
