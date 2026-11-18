use serde_json::{
    Value,
    json,
};
use wasm_bindgen::JsValue;
use worker::{
    Env,
    Fetch,
    Method,
    Request,
    RequestInit,
};

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::config::env_text,
};

pub fn mail_configured(env: &Env) -> bool {
    env_text(env, "MAIL_WEBHOOK_URL").is_some()
}

pub(super) async fn post_json(
    url: &str,
    body: Value,
    bearer: Option<&str>,
) -> AppResult<()> {
    // Delivery endpoints carry codes and must use TLS. The URL is never logged.
    if !url.starts_with("https://") {
        return Err(AppError::bad_request(
            "Notification delivery requires an HTTPS URL",
        ));
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(JsValue::from_str(&body.to_string())));
    let mut request = Request::new_with_init(url, &init)?;
    request
        .headers_mut()?
        .set("Content-Type", "application/json")?;
    if let Some(token) = bearer {
        request
            .headers_mut()?
            .set("Authorization", &format!("Bearer {token}"))?;
    }
    let response = Fetch::Request(request).send().await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::bad_request("Notification delivery failed"));
    }
    Ok(())
}

/// Recipient-aware delivery. Global administrative chats never receive codes.
pub async fn deliver_mail(
    env: &Env,
    to: &str,
    purpose: &str,
    subject: &str,
    text: &str,
) -> AppResult<()> {
    let endpoint = env_text(env, "MAIL_WEBHOOK_URL").ok_or_else(|| {
        AppError::bad_request("Email delivery is not configured")
    })?;
    let token = env_text(env, "MAIL_WEBHOOK_TOKEN");
    post_json(
        &endpoint,
        json!({"to":to,"purpose":purpose,"subject":subject,"text":text}),
        token.as_deref(),
    )
    .await
}
