use aes_gcm::{
    Aes256Gcm,
    KeyInit,
    Nonce,
    aead::{
        Aead,
        Payload,
    },
};
use axum::http::HeaderMap;
use base64::{
    Engine as _,
    engine::general_purpose::URL_SAFE_NO_PAD,
};
use hmac::{
    Hmac,
    Mac,
};
use sha2::{
    Digest,
    Sha256,
};
use uuid::Uuid;

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            rate,
        },
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    infra::crypto::ct_eq,
    models::{
        api_key::ApiKeyDB,
        user::{
            PasswordOrOtpData,
            UserDB,
        },
    },
};

const CIPHERTEXT_PREFIX: &str = "v2.";
const WRAPPING_KEY_CONTEXT: &[u8] = b"raywarden/api-key-encryption/v2";

fn wrapping_key(secret: &str) -> AppResult<Vec<u8>> {
    if secret.is_empty() {
        return Err(AppError::Internal);
    }
    // Domain separation matters for long JWT keys: HMAC normalizes keys over
    // SHA-256's block size with SHA-256, which was also our legacy AES key.
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(
        secret.as_bytes(),
    )
    .map_err(|_| AppError::Internal)?;
    mac.update(WRAPPING_KEY_CONTEXT);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn encrypt_with_nonce(
    secret: &str,
    user: &str,
    value: &str,
    nonce: &[u8; 12],
) -> AppResult<String> {
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key(secret)?)
        .map_err(|_| AppError::Internal)?;
    let cipher_nonce = Nonce::from(*nonce);
    let encrypted = cipher
        .encrypt(&cipher_nonce, Payload {
            msg: value.as_bytes(),
            aad: user.as_bytes(),
        })
        .map_err(|_| AppError::Internal)?;
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&encrypted);
    Ok(format!(
        "{CIPHERTEXT_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    ))
}
fn encrypt(secret: &str, user: &str, value: &str) -> AppResult<String> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|_| AppError::Internal)?;
    encrypt_with_nonce(secret, user, value, &nonce)
}
fn decrypt(secret: &str, user: &str, value: &str) -> AppResult<String> {
    if secret.is_empty() {
        return Err(AppError::Internal);
    }
    let (encoded, key) = match value.strip_prefix(CIPHERTEXT_PREFIX) {
        Some(encoded) => (encoded, wrapping_key(secret)?),
        // Keep existing rows readable without rewriting or rotating them.
        None => (value, Sha256::digest(secret.as_bytes()).to_vec()),
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::Internal)?;
    if bytes.len() < 28 {
        return Err(AppError::Internal);
    }
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| AppError::Internal)?;
    let nonce: [u8; 12] =
        bytes[..12].try_into().map_err(|_| AppError::Internal)?;
    let nonce = Nonce::from(nonce);
    let decrypted = cipher
        .decrypt(&nonce, Payload {
            msg: &bytes[12..],
            aad: user.as_bytes(),
        })
        .map_err(|_| AppError::Internal)?;
    String::from_utf8(decrypted).map_err(|_| AppError::Internal)
}
pub async fn get_or_rotate(
    state: &AppState,
    claims: &Claims,
    proof: &PasswordOrOtpData,
    rotate: bool,
) -> AppResult<(String, String)> {
    crate::api::service::email::verify_password_or_otp(state, claims, proof)
        .await?;
    let db = state.get_db();
    if !rotate && let Some(key) = ApiKeyDB::find(&db, &claims.sub).await? {
        return Ok((
            decrypt(&state.config.jwt_secret, &claims.sub, &key.encrypted_key)?,
            key.updated_at,
        ));
    }
    let value =
        format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let encrypted = encrypt(&state.config.jwt_secret, &claims.sub, &value)?;
    let hash = hex::encode(Sha256::digest(value.as_bytes()));
    ApiKeyDB::replace(&db, &claims.sub, &encrypted, &hash).await?;
    let record = ApiKeyDB::find(&db, &claims.sub)
        .await?
        .ok_or(AppError::Internal)?;
    Ok((
        decrypt(&state.config.jwt_secret, &claims.sub, &record.encrypted_key)?,
        record.updated_at,
    ))
}
pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
    client_secret: &str,
    scope: Option<&str>,
) -> AppResult<(UserDB, String)> {
    rate::check_rate_limit(
        state,
        format!("api-key-ip:{}", rate::client_ip(headers)),
    )
    .await?;
    let user = client_id
        .strip_prefix("user.")
        .filter(|u| Uuid::parse_str(u).is_ok())
        .ok_or_else(|| {
            AppError::Auth(AuthError::InvalidCredentials(
                "Invalid API credentials".into(),
            ))
        })?;
    rate::check_rate_limit(state, format!("api-key:{user}")).await?;
    if client_secret.is_empty() ||
        client_secret.len() > 4096 ||
        scope.is_some_and(|scope| {
            scope
                .split_whitespace()
                .any(|s| s != "api" && s != "offline_access")
        })
    {
        return Err(AuthError::InvalidCredentials(
            "Invalid API credentials or scope".into(),
        )
        .into());
    }
    let key =
        ApiKeyDB::find(&state.get_db(), user)
            .await?
            .ok_or_else(|| {
                AppError::Auth(AuthError::InvalidCredentials(
                    "Invalid API credentials".into(),
                ))
            })?;
    if !ct_eq(
        &key.key_hash,
        &hex::encode(Sha256::digest(client_secret.as_bytes())),
    ) {
        return Err(AuthError::InvalidCredentials(
            "Invalid API credentials".into(),
        )
        .into());
    }
    let user = UserDB::fetch_by_id_with(
        &state.get_db(),
        user,
        "Failed to fetch API client",
        || {
            AuthError::InvalidCredentials("Invalid API credentials".into())
                .into()
        },
    )
    .await?;
    Ok((user, key.key_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn api_secrets_are_encrypted_and_bound_to_owner() {
        let value = encrypt("signing-secret", "owner", "api-secret").unwrap();
        assert_ne!(value, "api-secret");
        assert!(value.starts_with(CIPHERTEXT_PREFIX));
        assert_eq!(
            decrypt("signing-secret", "owner", &value).unwrap(),
            "api-secret"
        );
        assert!(decrypt("signing-secret", "other", &value).is_err());
        assert!(decrypt("other-secret", "owner", &value).is_err());
        let mut bytes = URL_SAFE_NO_PAD
            .decode(value.strip_prefix(CIPHERTEXT_PREFIX).unwrap())
            .unwrap();
        bytes[15] ^= 1;
        assert!(
            decrypt(
                "signing-secret",
                "owner",
                &format!(
                    "{CIPHERTEXT_PREFIX}{}",
                    URL_SAFE_NO_PAD.encode(bytes)
                )
            )
            .is_err()
        );
    }

    #[test]
    fn old_ciphertext_is_readable_and_new_ciphertext_uses_a_separate_key() {
        // Independent Node crypto AES-256-GCM vectors, nonce 000102...0b.
        let legacy = "AAECAwQFBgcICQoL3AV5TKrds7cBaxOBGWyclAyYWxhMJHzl-pc";
        let current = "v2.AAECAwQFBgcICQoLhKqubgYWX3dW7jacgnij2EoOFve4hEwobqw";
        assert_eq!(
            decrypt("signing-secret", "owner", legacy).unwrap(),
            "api-secret"
        );
        assert_eq!(
            decrypt("signing-secret", "owner", current).unwrap(),
            "api-secret"
        );
        assert_eq!(
            encrypt_with_nonce("signing-secret", "owner", "api-secret", &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
            ])
            .unwrap(),
            current
        );
        assert!(decrypt("signing-secret", "other", legacy).is_err());
        assert!(decrypt("wrong-secret", "owner", legacy).is_err());
        assert!(
            decrypt(
                "signing-secret",
                "owner",
                current.strip_prefix(CIPHERTEXT_PREFIX).unwrap()
            )
            .is_err()
        );
        assert!(
            decrypt("signing-secret", "owner", &format!("v2.{legacy}"))
                .is_err()
        );
        assert!(decrypt("signing-secret", "owner", "v3.unknown").is_err());
        let long_secret = URL_SAFE_NO_PAD.encode([7; 64]);
        assert_ne!(
            wrapping_key(&long_secret).unwrap(),
            Sha256::digest(long_secret.as_bytes()).to_vec()
        );
        assert!(encrypt("", "owner", "api-secret").is_err());
        assert!(decrypt("", "owner", legacy).is_err());
    }
}
