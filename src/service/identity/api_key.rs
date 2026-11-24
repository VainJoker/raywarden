use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use worker::{D1Database, Env};

use crate::{
    errors::{AppError, AppResult, AuthError},
    models::identity::{
        api_key::{ApiKeyReplacement, ApiKeyRow},
        device::NewDeviceSession,
        user::UserRow,
    },
    service::{
        identity::{session::Claims, user::AccountVerificationRequest},
        rate_limit,
    },
    utils::constant_time_eq,
};

const CIPHERTEXT_PREFIX: &str = "v2.";
const WRAPPING_KEY_CONTEXT: &[u8] = b"raywarden/api-key-encryption/v2";

fn wrapping_key(secret: &str) -> AppResult<Vec<u8>> {
    if secret.is_empty() {
        return Err(AppError::Internal);
    }
    // Domain separation matters for long JWT keys: HMAC normalizes keys over
    // SHA-256's block size with SHA-256, which was also our legacy AES key.
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(AppError::internal_error)?;
    mac.update(WRAPPING_KEY_CONTEXT);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn encrypt_with_nonce(
    secret: &str,
    user: &str,
    value: &str,
    nonce: &[u8; 12],
) -> AppResult<String> {
    let cipher =
        Aes256Gcm::new_from_slice(&wrapping_key(secret)?).map_err(AppError::internal_error)?;
    let cipher_nonce = Nonce::from(*nonce);
    let encrypted = cipher
        .encrypt(&cipher_nonce, Payload {
            msg: value.as_bytes(),
            aad: user.as_bytes(),
        })
        .map_err(AppError::internal_error)?;
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&encrypted);
    Ok(format!(
        "{CIPHERTEXT_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    ))
}
fn encrypt(secret: &str, user: &str, value: &str) -> AppResult<String> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(AppError::internal_error)?;
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
        .map_err(AppError::internal_error)?;
    if bytes.len() < 28 {
        return Err(AppError::Internal);
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(AppError::internal_error)?;
    let nonce: [u8; 12] = bytes[..12].try_into().map_err(AppError::internal_error)?;
    let nonce = Nonce::from(nonce);
    let decrypted = cipher
        .decrypt(&nonce, Payload {
            msg: &bytes[12..],
            aad: user.as_bytes(),
        })
        .map_err(AppError::internal_error)?;
    String::from_utf8(decrypted).map_err(AppError::internal_error)
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiKeyAction {
    Get,
    Rotate,
}

pub(crate) struct ApiKeyService<'a> {
    pub(crate) db: &'a D1Database,
    pub(crate) env: &'a Env,
    pub(crate) access_secret: &'a str,
}

impl ApiKeyService<'_> {
    pub(crate) async fn get_or_rotate(
        &self,
        claims: &Claims,
        proof: &AccountVerificationRequest,
        action: ApiKeyAction,
    ) -> AppResult<(String, String)> {
        let Self {
            db,
            env,
            access_secret,
        } = *self;
        let user =
            UserRow::fetch_by_id_with(db, &claims.sub, "Failed to fetch API key owner", || {
                AuthError::UserNotFound.into()
            })
            .await?;
        let session = claims.session_snapshot()?;
        let previous = ApiKeyRow::find(db, &claims.sub).await?;
        crate::service::identity::email::verify_password_or_otp(
            db,
            env,
            access_secret,
            claims,
            proof,
        )
        .await?;
        if action == ApiKeyAction::Get
            && let Some(key) = ApiKeyRow::find_current(db, &user, &session).await?
        {
            return Ok((
                decrypt(access_secret, &claims.sub, &key.encrypted_key)?,
                key.updated_at,
            ));
        }
        let value = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let encrypted = encrypt(access_secret, &claims.sub, &value)?;
        let hash = hex::encode(Sha256::digest(value.as_bytes()));
        if let Some(record) = ApiKeyRow::replace(db, &user, &session, ApiKeyReplacement {
            previous: previous.as_ref(),
            encrypted: &encrypted,
            hash: &hash,
        })
        .await?
        {
            return Ok((value, record.updated_at));
        }
        if action == ApiKeyAction::Rotate {
            return Err(AppError::conflict(
                "Account, session or API key changed; retry",
            ));
        }
        let record = ApiKeyRow::find_current(db, &user, &session)
            .await?
            .ok_or_else(|| AppError::conflict("Account, session or API key changed; retry"))?;
        Ok((
            decrypt(access_secret, &claims.sub, &record.encrypted_key)?,
            record.updated_at,
        ))
    }
}

pub async fn authenticate(
    db: &D1Database,
    env: &Env,
    request_ip: &str,
    client_id: &str,
    client_secret: &str,
    scope: Option<&str>,
) -> AppResult<(UserRow, String)> {
    rate_limit::check_auth_attempt(env, format!("api-key-ip:{request_ip}")).await?;
    let user = client_id
        .strip_prefix("user.")
        .filter(|u| Uuid::parse_str(u).is_ok())
        .ok_or_else(AppError::invalid_api_credentials)?;
    rate_limit::check_auth_attempt(env, format!("api-key:{user}")).await?;
    if client_secret.is_empty()
        || client_secret.len() > 4096
        || scope.is_some_and(|scope| {
            scope
                .split_whitespace()
                .any(|s| s != "api" && s != "offline_access")
        })
    {
        return Err(AppError::invalid_credentials(
            "Invalid API credentials or scope",
        ));
    }
    let key = ApiKeyRow::find(db, user)
        .await?
        .ok_or_else(AppError::invalid_api_credentials)?;
    if !constant_time_eq(
        key.key_hash.as_bytes(),
        hex::encode(Sha256::digest(client_secret.as_bytes())).as_bytes(),
    ) {
        return Err(AppError::invalid_api_credentials());
    }
    let user = UserRow::fetch_by_id_with(
        db,
        user,
        "Failed to fetch API client",
        AppError::invalid_api_credentials,
    )
    .await?;
    Ok((user, key.key_hash))
}

pub(crate) async fn start_session(
    db: &D1Database,
    owner: &UserRow,
    session: &NewDeviceSession<'_>,
    key_hash: &str,
) -> AppResult<()> {
    ApiKeyRow::start_session(db, owner, session, key_hash).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn api_secrets_are_encrypted_and_bound_to_owner() {
        let value =
            encrypt("signing-secret", "owner", "api-secret").expect("valid api key fixture");
        assert_ne!(value, "api-secret");
        assert!(value.starts_with(CIPHERTEXT_PREFIX));
        assert_eq!(
            decrypt("signing-secret", "owner", &value).expect("valid api key fixture"),
            "api-secret"
        );
        assert!(decrypt("signing-secret", "other", &value).is_err());
        assert!(decrypt("other-secret", "owner", &value).is_err());
        let mut bytes = URL_SAFE_NO_PAD
            .decode(
                value
                    .strip_prefix(CIPHERTEXT_PREFIX)
                    .expect("valid api key fixture"),
            )
            .expect("valid api key fixture");
        bytes[15] ^= 1;
        assert!(
            decrypt(
                "signing-secret",
                "owner",
                &format!("{CIPHERTEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
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
            decrypt("signing-secret", "owner", legacy).expect("valid api key fixture"),
            "api-secret"
        );
        assert_eq!(
            decrypt("signing-secret", "owner", current).expect("valid api key fixture"),
            "api-secret"
        );
        assert_eq!(
            encrypt_with_nonce("signing-secret", "owner", "api-secret", &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
            ])
            .expect("valid api key fixture"),
            current
        );
        assert!(decrypt("signing-secret", "other", legacy).is_err());
        assert!(decrypt("wrong-secret", "owner", legacy).is_err());
        assert!(
            decrypt(
                "signing-secret",
                "owner",
                current
                    .strip_prefix(CIPHERTEXT_PREFIX)
                    .expect("valid api key fixture")
            )
            .is_err()
        );
        assert!(decrypt("signing-secret", "owner", &format!("v2.{legacy}")).is_err());
        assert!(decrypt("signing-secret", "owner", "v3.unknown").is_err());
        let long_secret = URL_SAFE_NO_PAD.encode([7; 64]);
        assert_ne!(
            wrapping_key(&long_secret).expect("valid api key fixture"),
            Sha256::digest(long_secret.as_bytes()).to_vec()
        );
        assert!(encrypt("", "owner", "api-secret").is_err());
        assert!(decrypt("", "owner", legacy).is_err());
    }
}
