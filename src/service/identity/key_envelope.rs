//! AES-GCM envelopes for persisted signing and API keys.
use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) fn seal(
    key: &[u8; 32],
    prefix: &str,
    context: &[u8],
    value: &str,
    nonce: [u8; 12],
) -> Result<String, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let encrypted = cipher.encrypt(&Nonce::from(nonce), Payload {
        msg: value.as_bytes(),
        aad: context,
    })?;
    let mut packed = nonce.to_vec();
    packed.extend_from_slice(&encrypted);
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(packed)))
}

pub(super) enum OpenError {
    InvalidEnvelope,
    InvalidCiphertext,
}

pub(super) fn open(
    key: &[u8; 32],
    prefix: &str,
    context: &[u8],
    value: &str,
) -> Result<String, OpenError> {
    let encoded = value
        .strip_prefix(prefix)
        .ok_or(OpenError::InvalidEnvelope)?;
    let packed = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_error| OpenError::InvalidEnvelope)?;
    // Twelve nonce bytes and a sixteen-byte authentication tag.
    if packed.len() < 28 {
        return Err(OpenError::InvalidEnvelope);
    }
    let (nonce, ciphertext) = packed.split_at(12);
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_error| OpenError::InvalidEnvelope)?;
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let plaintext = cipher
        .decrypt(&Nonce::from(nonce), Payload {
            msg: ciphertext,
            aad: context,
        })
        .map_err(|_error| OpenError::InvalidCiphertext)?;
    String::from_utf8(plaintext).map_err(|_error| OpenError::InvalidEnvelope)
}
