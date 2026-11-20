use axum::http::HeaderMap;
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};
use sha2::{
    Digest,
    Sha256,
};
use wasm_bindgen::JsValue;
use worker::{
    Fetch,
    Method,
    Request,
    RequestInit,
};

use crate::{
    app::AppContext,
    errors::{
        AppError,
        AppResult,
    },
    infra::jwt,
    models::identity::email::EmailStore,
    service::rate_limit,
};

const PURPOSE: &str = "send-human-verification";
const COOKIE: &str = "cf_send_pass";
const TTL: i64 = 300;
const REDEMPTION_TTL_SECONDS: i64 = 600;

#[derive(Serialize, Deserialize)]
struct HumanPass {
    sub:     String,
    purpose: String,
    ip:      String,
    send_id: String,
    exp:     i64,
    nbf:     i64,
    iat:     i64,
}

pub fn enabled(state: &AppContext) -> bool {
    crate::infra::env::env_text(&state.env, "TURNSTILE_SITE_KEY").is_some() ||
        crate::infra::env::env_text(&state.env, "TURNSTILE_SECRET_KEY")
            .is_some()
}

pub fn configured_site_key(state: &AppContext) -> AppResult<String> {
    let key = crate::infra::env::env_text(&state.env, "TURNSTILE_SITE_KEY")
        .ok_or_else(|| {
            AppError::bad_request("TURNSTILE_SITE_KEY is not configured")
        })?;
    if key.len() > 256 ||
        !key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(AppError::bad_request("Invalid Turnstile site key"));
    }
    crate::infra::env::env_text(&state.env, "TURNSTILE_SECRET_KEY")
        .ok_or_else(|| {
            AppError::bad_request("TURNSTILE_SECRET_KEY is not configured")
        })?;
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

pub fn validate_siteverify(value: &Value, hostname: &str) -> AppResult<()> {
    if value.get("success").and_then(Value::as_bool) != Some(true) ||
        value.get("hostname").and_then(Value::as_str) != Some(hostname) ||
        value.get("action").and_then(Value::as_str) != Some("send-access")
    {
        return Err(AppError::bad_request("Turnstile verification failed"));
    }
    Ok(())
}

/// Validate with Siteverify and then claim the token hash in D1. Cloudflare
/// documents that replay detection has a convergence window, so the local
/// unique claim prevents repeated redemption inside that window.
pub async fn issue_send_access(
    state: &AppContext,
    headers: &HeaderMap,
    response: &str,
    send_id: &str,
) -> AppResult<String> {
    configured_site_key(state)?;
    if response.is_empty() || response.len() > 2048 || send_id.len() > 256 {
        return Err(AppError::bad_request("Invalid Turnstile response"));
    }
    rate_limit::check_auth_attempt(
        state,
        format!("turnstile:{}", rate_limit::client_ip(headers)),
    )
    .await?;
    let secret =
        crate::infra::env::env_text(&state.env, "TURNSTILE_SECRET_KEY")
            .ok_or(AppError::Internal)?;
    let body = json!({"secret":secret,"response":response,"remoteip":rate_limit::client_ip(headers)});
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
    let payload: Value = result.json().await?;
    validate_siteverify(&payload, &expected_hostname(state.domain())?)?;
    let now = crate::utils::time::now_seconds();
    let hash = hex::encode(Sha256::digest(response.as_bytes()));
    EmailStore::claim_turnstile(
        state.database(),
        &hash,
        now + REDEMPTION_TTL_SECONDS,
    )
    .await?;
    let proof = HumanPass {
        sub:     "anonymous-send-reader".into(),
        purpose: PURPOSE.into(),
        ip:      rate_limit::client_ip(headers).into(),
        send_id: send_id.into(),
        exp:     now + TTL,
        nbf:     now,
        iat:     now,
    };
    Ok(jwt::encode(
        &proof,
        state.jwt_keys.access_secret.as_bytes(),
    )?)
}

pub fn verify_send_access(
    state: &AppContext,
    headers: &HeaderMap,
    send_id: &str,
) -> AppResult<()> {
    if !enabled(state) {
        return Ok(());
    }
    configured_site_key(state)?;
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
    let pass = jwt::decode::<HumanPass>(
        token,
        state.jwt_keys.access_secret.as_bytes(),
        &options,
    )?;
    if pass.purpose != PURPOSE ||
        pass.sub != "anonymous-send-reader" ||
        pass.ip != rate_limit::client_ip(headers) ||
        (!pass.send_id.is_empty() && pass.send_id != send_id)
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
        let result = json!({"success":true,"hostname":"vault.example","action":"send-access"});
        assert!(validate_siteverify(&result, "vault.example").is_ok());
        assert!(validate_siteverify(&result, "other.example").is_err());
        assert!(validate_siteverify(&json!({"success":false,"hostname":"vault.example","action":"send-access"}),"vault.example").is_err());
        assert!(validate_siteverify(&json!({"success":true,"hostname":"vault.example","action":"other"}),"vault.example").is_err());
    }
}
