//! Bearer authentication for handlers that request `Claims`.
use axum::{
    extract::FromRequestParts,
    http::{
        HeaderMap,
        header,
        request::Parts,
    },
};

use crate::{
    api::AppState,
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    infra::jwt::{
        ValidationOptions,
        decode,
    },
    service::identity::session::Claims,
};

pub(in crate::api) fn request_device_type(
    headers: &HeaderMap,
) -> AppResult<i32> {
    let value = headers
        .get("device-type")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::bad_request("Missing device-type header"))?;
    value
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|value| (0..=40).contains(value))
        .ok_or_else(|| AppError::bad_request("Invalid device-type header"))
}

fn bearer_token(parts: &Parts) -> AppResult<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(AppError::Auth(AuthError::MissingToken))
}

impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    #[worker::send]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let claims = decode::<Self>(
            bearer_token(parts)?,
            state.jwt_keys.access_secret.as_bytes(),
            &ValidationOptions::default(),
        )?;
        claims.validate_session(state.database(), "access").await?;
        Ok(claims)
    }
}
