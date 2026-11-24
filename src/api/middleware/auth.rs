//! Bearer authentication for handlers that request `Claims`.
use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, HeaderValue, header, request::Parts},
    response::{IntoResponse, Response},
};

use crate::{
    api::AppState,
    errors::{AppError, AuthError},
    infra::jwt::{ValidationOptions, decode},
    service::identity::session::{Claims, TokenUse},
    utils::parse_bearer,
};

pub(in crate::api) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_bearer)
}

pub(in crate::api) struct BearerRejection {
    error: AppError,
    challenge: Option<&'static str>,
}

impl BearerRejection {
    pub(in crate::api) const fn missing(error: AppError) -> Self {
        Self {
            error,
            challenge: Some("Bearer"),
        }
    }

    pub(in crate::api) const fn invalid(error: AppError) -> Self {
        Self {
            error,
            challenge: Some("Bearer error=\"invalid_token\""),
        }
    }
}

impl From<AppError> for BearerRejection {
    fn from(error: AppError) -> Self {
        Self {
            error,
            challenge: None,
        }
    }
}

impl IntoResponse for BearerRejection {
    fn into_response(self) -> Response {
        let mut response = self.error.into_response();
        if let Some(challenge) = self.challenge {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        response
    }
}

impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = BearerRejection;

    #[worker::send]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)
            .ok_or_else(|| BearerRejection::missing(AuthError::MissingToken.into()))?;
        let claims = decode::<Self>(
            token,
            state.jwt_keys.access_secret.as_bytes(),
            &ValidationOptions::default(),
        )
        .map_err(|error| BearerRejection::invalid(error.into()))?;
        claims
            .validate_session(state.database(), TokenUse::Access)
            .await
            .map_err(|error| match error {
                AppError::Auth(AuthError::InvalidCredentials(_)) => BearerRejection::invalid(error),
                _ => error.into(),
            })?;
        Ok(claims)
    }
}
