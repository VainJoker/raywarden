use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey, SubtleCrypto};
use worker::js_sys;

use crate::errors::{AppResult, CryptoError};

/// Gets the Crypto interface from the global scope.
/// Works in Cloudflare Workers by using `js_sys::Reflect` instead of
/// `WorkerGlobalScope`.
fn web_crypto() -> Result<Crypto, CryptoError> {
    let global = js_sys::global();
    let crypto_value = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|_error| CryptoError::KeyDerivationFailed("read global crypto property"))?;

    crypto_value
        .dyn_into::<Crypto>()
        .map_err(|_error| CryptoError::KeyDerivationFailed("resolve Web Crypto interface"))
}

/// Gets the `SubtleCrypto` interface from the global scope.
fn subtle_crypto() -> Result<SubtleCrypto, CryptoError> {
    Ok(web_crypto()?.subtle())
}

pub fn random_bytes(length_bytes: u32, operation: &'static str) -> AppResult<Vec<u8>> {
    let crypto = web_crypto()?;
    let bytes = Uint8Array::new_with_length(length_bytes);
    crypto
        .get_random_values_with_array_buffer_view(&bytes)
        .map_err(|_error| CryptoError::RandomGenerationFailed(operation))?;
    Ok(bytes.to_vec())
}

/// Computes HMAC-SHA1 using Web Crypto API.
pub async fn hmac_sha1(key: &[u8], data: &[u8]) -> AppResult<Vec<u8>> {
    let subtle = subtle_crypto()?;

    let algorithm = web_sys::HmacImportParams::new_with_str("HMAC", "SHA-1");

    // Import the key
    let key_array = Uint8Array::new_from_slice(key);
    let key_usages = js_sys::Array::of1(&JsValue::from_str("sign"));

    let crypto_key = JsFuture::from(
        subtle
            .import_key_with_object("raw", &key_array, &algorithm, false, &key_usages)
            .map_err(|_error| CryptoError::HmacFailed("import key"))?,
    )
    .await
    .map_err(|_error| CryptoError::HmacFailed("await key import"))?;

    // Sign the data using sign_with_str_and_buffer_source
    let data_array = Uint8Array::new_from_slice(data);
    let signature = JsFuture::from(
        subtle
            .sign_with_str_and_buffer_source("HMAC", &CryptoKey::from(crypto_key), &data_array)
            .map_err(|_error| CryptoError::HmacFailed("sign data"))?,
    )
    .await
    .map_err(|_error| CryptoError::HmacFailed("await signature"))?;

    Ok(Uint8Array::new(&signature).to_vec())
}
