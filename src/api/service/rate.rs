use axum::http::HeaderMap;

use crate::{
    api::AppState,
    errors::AppError,
};

const LOGIN_RATE_LIMITER: &str = "LOGIN_RATE_LIMITER";
const SEND_ACCESS_RATE_LIMITER: &str = "SEND_ACCESS_RATE_LIMITER";

pub fn client_ip(headers: &HeaderMap) -> &str {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
}

pub async fn check_rate_limit(
    state: &AppState,
    rate_limit_key: String,
) -> Result<(), AppError> {
    check_rate_limit_binding(state, rate_limit_key, LOGIN_RATE_LIMITER).await
}

pub async fn check_send_access_rate_limit(
    state: &AppState,
    rate_limit_key: String,
) -> Result<(), AppError> {
    check_rate_limit_binding(state, rate_limit_key, SEND_ACCESS_RATE_LIMITER)
        .await
}

async fn check_rate_limit_binding(
    state: &AppState,
    rate_limit_key: String,
    binding: &str,
) -> Result<(), AppError> {
    let Ok(rate_limiter) = state.env.rate_limiter(binding) else {
        return Ok(());
    };

    if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await &&
        !outcome.success
    {
        return Err(AppError::TooManyRequests {
            message: "Too many login attempts. Please try again later."
                .to_string(),
        });
    }

    Ok(())
}
