use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{D1Database, Env, Fetch, Method, Request, RequestInit};

use crate::{
    errors::{AppError, AppResult},
    infra::jwt,
    models::identity::email,
    service::rate_limit,
};

const COOKIE: &str = "cf_send_pass";
const TTL: i64 = 300;
const REDEMPTION_TTL_SECONDS: i64 = 600;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum TurnstilePurpose {
    #[serde(rename = "send-human-verification")]
    SendHumanVerification,
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize)]
struct HumanPass {
    sub: String,
    purpose: TurnstilePurpose,
    ip: String,
    send_id: String,
    exp: i64,
    nbf: i64,
    iat: i64,
}

pub fn enabled(env: &Env) -> bool {
    crate::infra::config::env_text(env, "TURNSTILE_SITE_KEY").is_some()
        || crate::infra::config::env_text(env, "TURNSTILE_SECRET_KEY").is_some()
}

pub fn configured_site_key(env: &Env) -> AppResult<String> {
    let key = crate::infra::config::env_text(env, "TURNSTILE_SITE_KEY")
        .ok_or_else(|| AppError::bad_request("TURNSTILE_SITE_KEY is not configured"))?;
    if key.len() > 256
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AppError::bad_request("Invalid Turnstile site key"));
    }
    crate::infra::config::env_text(env, "TURNSTILE_SECRET_KEY")
        .ok_or_else(|| AppError::bad_request("TURNSTILE_SECRET_KEY is not configured"))?;
    Ok(key)
}

fn expected_hostname(domain: &str) -> AppResult<String> {
    let uri = domain
        .parse::<axum::http::Uri>()
        .map_err(|_error| AppError::bad_request("Invalid server domain"))?;
    let hostname = uri
        .host()
        .ok_or_else(|| AppError::bad_request("Invalid server domain"))?;
    Ok(hostname.trim_matches(['[', ']']).to_ascii_lowercase())
}

#[derive(Debug, Deserialize)]
pub(crate) struct SiteverifyResponse {
    pub success: bool,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
}

impl SiteverifyResponse {
    pub(crate) fn validate(&self, hostname: &str) -> AppResult<()> {
        if !self.success
            || self.hostname.as_deref() != Some(hostname)
            || self.action.as_deref() != Some("send-access")
        {
            return Err(AppError::bad_request("Turnstile verification failed"));
        }
        Ok(())
    }
}

pub(crate) struct TurnstileVerifier<'a> {
    pub db: &'a D1Database,
    pub env: &'a Env,
    pub domain: &'a str,
    pub access_secret: &'a str,
}

impl TurnstileVerifier<'_> {
    /// Validate with Siteverify and then claim the token hash in D1. Cloudflare
    /// documents that replay detection has a convergence window, so the local
    /// unique claim prevents repeated redemption inside that window.
    pub(crate) async fn issue_send_access(
        &self,
        headers: &HeaderMap,
        response: &str,
        send_id: &str,
    ) -> AppResult<String> {
        let Self {
            db,
            env,
            domain,
            access_secret,
        } = *self;
        configured_site_key(env)?;
        if response.is_empty() || response.len() > 2048 || send_id.len() > 256 {
            return Err(AppError::bad_request("Invalid Turnstile response"));
        }
        let ip = rate_limit::client_ip(headers);
        rate_limit::check_auth_attempt(env, format!("turnstile:{ip}")).await?;
        let secret = crate::infra::config::env_text(env, "TURNSTILE_SECRET_KEY")
            .ok_or(AppError::Internal)?;
        let body = json!({"secret":secret,"response":response,"remoteip":ip});
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        init.with_body(Some(JsValue::from_str(&body.to_string())));
        let mut request = Request::new_with_init(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            &init,
        )?;
        request
            .headers_mut()?
            .set("Content-Type", "application/json")?;
        let mut result = Fetch::Request(request).send().await?;
        if !(200..300).contains(&result.status_code()) {
            return Err(AppError::bad_request("Turnstile service failed"));
        }
        let payload: SiteverifyResponse = result.json().await?;
        payload.validate(&expected_hostname(domain)?)?;
        let now = crate::utils::time::now_seconds();
        let hash = hex::encode(Sha256::digest(response.as_bytes()));
        email::claim_turnstile(db, &hash, now + REDEMPTION_TTL_SECONDS).await?;
        let proof = HumanPass {
            sub: "anonymous-send-reader".into(),
            purpose: TurnstilePurpose::SendHumanVerification,
            ip: ip.into(),
            send_id: send_id.into(),
            exp: now + TTL,
            nbf: now,
            iat: now,
        };
        jwt::encode(&proof, access_secret.as_bytes())
    }
}

pub fn verify_send_access(
    env: &Env,
    access_secret: &str,
    headers: &HeaderMap,
    send_id: &str,
) -> AppResult<()> {
    if !enabled(env) {
        return Ok(());
    }
    configured_site_key(env)?;
    let token = headers
        .get("x-send-access-pass")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get("cookie")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| {
                    value.split(';').find_map(|part| {
                        part.trim()
                            .split_once('=')
                            .filter(|(name, _)| *name == COOKIE)
                            .map(|(_, value)| value)
                    })
                })
        })
        .ok_or_else(|| AppError::Unauthorized {
            message: "Turnstile verification required".into(),
        })?;
    let options = jwt::ValidationOptions {
        leeway_seconds: 0,
        ..Default::default()
    };
    let pass = jwt::decode::<HumanPass>(token, access_secret.as_bytes(), &options)?;
    if pass.purpose != TurnstilePurpose::SendHumanVerification
        || pass.sub != "anonymous-send-reader"
        || pass.ip != rate_limit::client_ip(headers)
        || (!pass.send_id.is_empty() && pass.send_id != send_id)
    {
        return Err(AppError::Unauthorized {
            message: "Invalid Turnstile access proof".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn siteverify_checks_server_result_hostname_and_action() {
        let parse = |value: serde_json::Value| -> SiteverifyResponse {
            serde_json::from_value(value).expect("valid siteverify fixture")
        };
        let result =
            parse(json!({"success":true,"hostname":"vault.example","action":"send-access"}));
        assert!(result.validate("vault.example").is_ok());
        assert!(result.validate("other.example").is_err());
        assert!(
            parse(json!({"success":false,"hostname":"vault.example","action":"send-access"}))
                .validate("vault.example")
                .is_err()
        );
        assert!(
            parse(json!({"success":true,"hostname":"vault.example","action":"other"}))
                .validate("vault.example")
                .is_err()
        );
    }
}
