use axum::http::HeaderMap;

use crate::{
    errors::AppError,
    warden::AppState,
};

const LOGIN_RATE_LIMITER: &str = "LOGIN_RATE_LIMITER";

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
    let Ok(rate_limiter) = state.env.rate_limiter(LOGIN_RATE_LIMITER) else {
        return Ok(());
    };

    // let rate_limit_key = format!("login:{}", username.to_lowercase());
    if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await &&
        !outcome.success
    {
        return Err(AppError::TooManyRequests(
            "Too many login attempts. Please try again later.".to_string(),
        ));
    }

    Ok(())
}
