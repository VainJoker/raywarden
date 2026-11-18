use std::sync::{
    Mutex,
    OnceLock,
};

use serde::Deserialize;
use serde_json::{
    Value,
    json,
};
use sha2::{
    Digest as _,
    Sha256,
};
use worker::{
    Env,
    Fetch,
    Method,
    Request,
    RequestInit,
    wasm_bindgen::JsValue,
};

use crate::{
    errors::{
        AppError,
        AppResult,
        ConfigError,
    },
    models::push::{
        PushDB,
        PushDevice,
    },
};

#[derive(Debug, Clone)]
struct PushConfig {
    relay_uri:        String,
    identity_uri:     String,
    installation_id:  String,
    installation_key: String,
}

impl PushConfig {
    fn from_env(env: &Env) -> AppResult<Option<Self>> {
        let enabled = env.var("PUSH_ENABLED").ok().is_some_and(|v| {
            matches!(
                v.to_string().trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
        if !enabled {
            return Ok(None);
        }
        let get_secret = |name: &str| {
            env.secret(name)
                .map(|value| value.to_string())
                .map_err(|_| {
                    AppError::Config(ConfigError::Missing(name.to_string()))
                })
        };
        let relay_uri = env.var("PUSH_RELAY_URI").map_or_else(
            |_| "https://push.bitwarden.com".to_string(),
            |v| v.to_string(),
        );
        let identity_uri = env.var("PUSH_IDENTITY_URI").map_or_else(
            |_| "https://identity.bitwarden.com".to_string(),
            |v| v.to_string(),
        );
        if !relay_uri.starts_with("https://") ||
            !identity_uri.starts_with("https://")
        {
            return Err(AppError::bad_request(
                "Push relay and identity URLs must use HTTPS",
            ));
        }
        let config = Self {
            relay_uri:        relay_uri.trim_end_matches('/').to_string(),
            identity_uri:     identity_uri.trim_end_matches('/').to_string(),
            installation_id:  get_secret("PUSH_INSTALLATION_ID")?,
            installation_key: get_secret("PUSH_INSTALLATION_KEY")?,
        };
        if config.installation_id.is_empty() ||
            config.installation_key.is_empty()
        {
            return Err(AppError::bad_request(
                "Push installation credentials must not be empty",
            ));
        }
        Ok(Some(config))
    }
    fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        for value in [
            &self.identity_uri,
            &self.installation_id,
            &self.installation_key,
        ] {
            hash.update(value.as_bytes());
            hash.update([0]);
        }
        hex::encode(hash.finalize())
    }
}

#[derive(Clone)]
struct CachedToken {
    fingerprint: String,
    token:       String,
    expires_at:  i64,
}
static TOKEN_CACHE: OnceLock<Mutex<Option<CachedToken>>> = OnceLock::new();

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in:   i64,
}

fn form_encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' |
            b'a'..=b'z' |
            b'0'..=b'9' |
            b'-' |
            b'_' |
            b'.' |
            b'~' => result.push(char::from(byte)),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(result, "%{byte:02X}");
            }
        }
    }
    result
}

async fn relay_token(config: &PushConfig) -> AppResult<String> {
    let fingerprint = config.fingerprint();
    let cache = TOKEN_CACHE.get_or_init(|| Mutex::new(None));
    let cached = cache.lock().ok().and_then(|value| value.clone());
    if let Some(cached) = cached &&
        cached.fingerprint == fingerprint &&
        cached.expires_at > crate::infra::time::now_seconds()
    {
        return Ok(cached.token);
    }
    let body = format!(
        "grant_type=client_credentials&scope=api.push&client_id={}&\
         client_secret={}",
        form_encode(&format!("installation.{}", config.installation_id)),
        form_encode(&config.installation_key)
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(JsValue::from_str(&body)));
    let mut request = Request::new_with_init(
        &format!("{}/connect/token", config.identity_uri),
        &init,
    )?;
    request
        .headers_mut()?
        .set("content-type", "application/x-www-form-urlencoded")?;
    let mut response = Fetch::Request(request).send().await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::Internal);
    }
    let token: TokenResponse = response.json().await?;
    if token.access_token.is_empty() || token.expires_in <= 0 {
        return Err(AppError::Internal);
    }
    let expires_at = crate::infra::time::now_seconds()
        .saturating_add(token.expires_in.saturating_sub(30).max(0));
    if let Ok(mut cache) = cache.lock() {
        *cache = Some(CachedToken {
            fingerprint,
            token: token.access_token.clone(),
            expires_at,
        });
    }
    Ok(token.access_token)
}

async fn post(
    config: &PushConfig,
    path: &str,
    payload: Option<&Value>,
) -> AppResult<()> {
    let token = relay_token(config).await?;
    let body = payload
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| AppError::Internal)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(body.as_deref().map(JsValue::from_str));
    let mut request =
        Request::new_with_init(&format!("{}{path}", config.relay_uri), &init)?;
    request
        .headers_mut()?
        .set("authorization", &format!("Bearer {token}"))?;
    request
        .headers_mut()?
        .set("content-type", "application/json")?;
    let response = Fetch::Request(request).send().await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::Internal);
    }
    Ok(())
}

/// Push registration failure is reported to the caller so an enabled but
/// misconfigured relay does not pretend that mobile delivery works.
pub async fn register_device(
    env: &Env,
    user_id: &str,
    identifier: &str,
) -> AppResult<()> {
    let Some(config) = PushConfig::from_env(env)? else {
        return Ok(());
    };
    let db = env.d1("warden-db")?;
    let device = PushDB::find_for_user(&db, user_id, identifier)
        .await?
        .ok_or_else(|| AppError::not_found("Device"))?;
    if !matches!(device.device_type, 0 | 1) {
        return Ok(());
    }
    let Some(token) = device
        .push_token
        .as_deref()
        .filter(|token| !token.is_empty())
    else {
        return Ok(());
    };
    let Some(id) = PushDB::ensure_uuid(&db, user_id, identifier).await? else {
        return Err(AppError::not_found("Device"));
    };
    post(&config,"/push/register",Some(&json!({
        "deviceId":id,"pushToken":token,"userId":user_id,"type":device.device_type,
        "identifier":identifier,"installationId":config.installation_id
    }))).await
}

pub async fn unregister_device(
    env: &Env,
    user_id: &str,
    identifier: &str,
) -> AppResult<()> {
    let Some(config) = PushConfig::from_env(env)? else {
        return Ok(());
    };
    let db = env.d1("warden-db")?;
    let Some(device) = PushDB::find_for_user(&db, user_id, identifier).await?
    else {
        return Ok(());
    };
    unregister(&config, &device).await
}

async fn unregister(config: &PushConfig, device: &PushDevice) -> AppResult<()> {
    if let Some(id) = &device.push_uuid {
        post(config, &format!("/push/delete/{}", form_encode(id)), None)
            .await?;
    }
    Ok(())
}

/// Call before deleting device rows. Relay failure must not prevent local
/// logout/account deletion, so cleanup is best effort and logged.
pub async fn unregister_user(env: &Env, user_id: &str) {
    let result = async {
        let Some(config) = PushConfig::from_env(env)? else {
            return Ok::<(), AppError>(());
        };
        let db = env.d1("warden-db")?;
        for device in PushDB::list_for_user(&db, user_id).await? {
            unregister(&config, &device).await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        log::warn!("Push device cleanup failed: {error}");
    }
}

pub async fn send_update(
    env: &Env,
    user_id: &str,
    update_type: i32,
    payload: &Value,
    context_id: Option<&str>,
) -> AppResult<()> {
    let Some(config) = PushConfig::from_env(env)? else {
        return Ok(());
    };
    let db = env.d1("warden-db")?;
    let devices = PushDB::list_for_user(&db, user_id).await?;
    if !devices.iter().any(|device| {
        device.push_token.is_some() && matches!(device.device_type, 0 | 1)
    }) {
        return Ok(());
    }
    let current = context_id
        .and_then(|id| devices.iter().find(|device| device.identifier == id));
    post(
        &config,
        "/push/send",
        Some(&json!({
            "userId":user_id,"organizationId":null,
            "deviceId":current.and_then(|d|d.push_uuid.as_deref()),
            "identifier":context_id,"type":update_type,"payload":payload,
            "clientType":null,"installationId":null
        })),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oauth_form_values_preserve_secret_characters() {
        assert_eq!(form_encode("a+b&c=汉"), "a%2Bb%26c%3D%E6%B1%89");
    }
}
