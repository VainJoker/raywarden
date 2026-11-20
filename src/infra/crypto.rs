use js_sys::Uint8Array;
use wasm_bindgen::{
    JsCast,
    JsValue,
};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Crypto,
    CryptoKey,
    SubtleCrypto,
};
use worker::js_sys;

use crate::errors::{
    AppResult,
    CryptoError,
};

/// Gets the Crypto interface from the global scope.
/// Works in Cloudflare Workers by using `js_sys::Reflect` instead of
/// `WorkerGlobalScope`.
fn web_crypto() -> Result<Crypto, CryptoError> {
    let global = js_sys::global();
    let crypto_value =
        js_sys::Reflect::get(&global, &JsValue::from_str("crypto")).map_err(
            |_error| {
                CryptoError::KeyDerivationFailed("read global crypto property")
            },
        )?;

    crypto_value.dyn_into::<Crypto>().map_err(|_error| {
        CryptoError::KeyDerivationFailed("resolve Web Crypto interface")
    })
}

/// Gets the `SubtleCrypto` interface from the global scope.
fn subtle_crypto() -> Result<SubtleCrypto, CryptoError> {
    Ok(web_crypto()?.subtle())
}

/// Derives a key using PBKDF2-SHA256.
pub async fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length_bits: u32,
) -> AppResult<Vec<u8>> {
    let subtle = subtle_crypto()?;

    // Import the password as a raw key material
    let password_array = Uint8Array::new_from_slice(password);
    let password_buffer = password_array.as_ref();
    let key_material = JsFuture::from(
        subtle
            .import_key_with_str(
                "raw",
                password_buffer,
                "PBKDF2",
                false,
                &js_sys::Array::of1(&JsValue::from_str("deriveBits")),
            )
            .map_err(|_error| CryptoError::Pbkdf2Failed("import key"))?,
    )
    .await
    .map_err(|_error| CryptoError::Pbkdf2Failed("await key import"))?;

    let salt_array = Uint8Array::new_from_slice(salt);
    // Define PBKDF2 parameters
    let params = web_sys::Pbkdf2Params::new(
        "PBKDF2",
        JsValue::from_str("SHA-256").as_ref(),
        iterations,
        salt_array.as_ref(),
    );

    // Derive the bits
    let derived_bits = JsFuture::from(
        subtle
            .derive_bits_with_object(
                params.as_ref(),
                &CryptoKey::from(key_material),
                key_length_bits,
            )
            .map_err(|_error| CryptoError::Pbkdf2Failed("derive bits"))?,
    )
    .await
    .map_err(|_error| CryptoError::Pbkdf2Failed("await bit derivation"))?;

    Ok(js_sys::Uint8Array::new(&derived_bits).to_vec())
}

/// Generate random bytes using the caller's operation-specific error category.
pub fn random_bytes(
    length_bytes: u32,
    failure: impl FnOnce(&'static str) -> CryptoError,
) -> AppResult<Vec<u8>> {
    let crypto = web_crypto()?;
    let bytes = Uint8Array::new_with_length(length_bytes);
    crypto
        .get_random_values_with_array_buffer_view(&bytes)
        .map_err(|_error| failure("get cryptographic random bytes"))?;
    Ok(bytes.to_vec())
}

/// Computes HMAC-SHA1 using Web Crypto API.
pub async fn hmac_sha1(key: &[u8], data: &[u8]) -> AppResult<Vec<u8>> {
    let subtle = subtle_crypto()?;

    // Create algorithm object for HMAC with SHA-1
    let algorithm = js_sys::Object::new();
    js_sys::Reflect::set(
        &algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str("HMAC"),
    )
    .map_err(|_error| CryptoError::HashFailed("set HMAC algorithm name"))?;
    js_sys::Reflect::set(
        &algorithm,
        &JsValue::from_str("hash"),
        &JsValue::from_str("SHA-1"),
    )
    .map_err(|_error| CryptoError::HashFailed("set HMAC hash algorithm"))?;

    // Import the key
    let key_array = Uint8Array::new_from_slice(key);
    let key_usages = js_sys::Array::of1(&JsValue::from_str("sign"));

    let crypto_key = JsFuture::from(
        subtle
            .import_key_with_object(
                "raw",
                &key_array,
                &algorithm,
                false,
                &key_usages,
            )
            .map_err(|_error| CryptoError::HmacFailed("import key"))?,
    )
    .await
    .map_err(|_error| CryptoError::HmacFailed("await key import"))?;

    // Sign the data using sign_with_str_and_buffer_source
    let data_array = Uint8Array::new_from_slice(data);
    let signature = JsFuture::from(
        subtle
            .sign_with_str_and_buffer_source(
                "HMAC",
                &CryptoKey::from(crypto_key),
                &data_array,
            )
            .map_err(|_error| CryptoError::HmacFailed("sign data"))?,
    )
    .await
    .map_err(|_error| CryptoError::HmacFailed("await signature"))?;

    Ok(Uint8Array::new(&signature).to_vec())
}
