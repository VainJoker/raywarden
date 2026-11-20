//! JSON delivery over HTTPS via the Worker runtime.
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{
    Fetch,
    Method,
    Request,
    RequestInit,
};

use crate::errors::{
    AppError,
    AppResult,
};

pub(crate) async fn post_json(
    url: &str,
    body: Value,
    bearer: Option<&str>,
) -> AppResult<()> {
    // Require HTTPS before sending the body or credentials.
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
