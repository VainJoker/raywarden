use std::{
    collections::HashSet,
    sync::Arc,
};

use axum::{
    extract::FromRequestParts,
    http::{
        header,
        request::Parts,
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use worker::Env;

use crate::{
    api::AppState,
    errors::{
        AppError,
        AuthError,
    },
    infra::{
        ValidationOptions,
        decode,
    },
};

/// Application-specific extension claims
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClaimsExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub premium:        Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name:           Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email:          Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr:            Option<HashSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device:         Option<String>,
}

/// Application-specific claims for authentication (improved version)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    // Required standard claims
    pub sub: String, // User ID
    pub exp: i64,    // Expiration time (Unix timestamp)
    pub nbf: i64,    // Not before time (Unix timestamp)
    pub iat: i64,    // Issued at time (Unix timestamp)

    // Application-specific claims
    #[serde(flatten)]
    pub extensions: ClaimsExtensions,
}

impl Claims {
    /// Creates new claims with the given parameters
    /// Automatically sets iat to current time, nbf to current time, and exp to
    /// current time + duration
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_id: String,
        email: String,
        name: String,
        premium: bool,
        email_verified: bool,
        amr: HashSet<String>,
        device: Option<String>,
        duration_seconds: i64,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            sub:        user_id,
            exp:        now + duration_seconds,
            nbf:        now,
            iat:        now,
            extensions: ClaimsExtensions {
                premium: Some(premium),
                name: Some(name),
                email: Some(email),
                email_verified: Some(email_verified),
                amr: Some(amr),
                device,
            },
        }
    }

    /// Helper getters for backward compatibility
    pub fn email(&self) -> Option<&str> {
        self.extensions.email.as_deref()
    }

    pub fn name(&self) -> Option<&str> {
        self.extensions.name.as_deref()
    }

    pub fn premium(&self) -> bool {
        self.extensions.premium.unwrap_or(false)
    }

    pub fn email_verified(&self) -> bool {
        self.extensions.email_verified.unwrap_or(false)
    }

    /// Returns a reference to the AMR set if present.
    pub const fn amr(&self) -> Option<&HashSet<String>> {
        self.extensions.amr.as_ref()
    }

    /// Returns the device identifier associated with these claims, if any.
    pub fn device(&self) -> Option<&str> {
        self.extensions.device.as_deref()
    }
}

/// `AuthUser` extractor - provides (`user_id`, email) tuple
pub struct AuthUser(pub String, pub String);

// ============================================================================
// Axum Extractors
// ============================================================================

impl FromRequestParts<Arc<Env>> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<Env>,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_value| {
                auth_value
                    .strip_prefix("Bearer ")
                    .map(std::borrow::ToOwned::to_owned)
            })
            .ok_or_else(|| AppError::Auth(AuthError::MissingToken))?;

        let secret = state.secret("JWT_SECRET")?;
        let secret_bytes = secret.to_string();

        // Decode and validate the token (synchronous - no Send issues)
        // Use secret bytes directly to minimize memory exposure
        let token_data = decode::<Self>(
            &token,
            secret_bytes.as_bytes(),
            &ValidationOptions::default(),
        )
        .map_err(AppError::from)?;

        Ok(token_data.claims)
    }
}

impl FromRequestParts<Arc<Env>> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<Env>,
    ) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;
        let email = claims.email().unwrap_or("").to_string();
        Ok(Self(claims.sub, email))
    }
}

// Also allow extracting Claims/AuthUser when the application state is
// `AppState`. This mirrors the Arc<Env> implementations above but reads the Env
// from AppState.
impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_value| {
                auth_value
                    .strip_prefix("Bearer ")
                    .map(std::borrow::ToOwned::to_owned)
            })
            .ok_or_else(|| AppError::Auth(AuthError::MissingToken))?;

        let secret = state.config.jwt_secret.clone();
        let secret_bytes = secret.clone();

        let token_data = decode::<Self>(
            &token,
            secret_bytes.as_bytes(),
            &ValidationOptions::default(),
        )
        .map_err(AppError::from)?;

        Ok(token_data.claims)
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;
        let email = claims.email().unwrap_or("").to_string();
        Ok(Self(claims.sub, email))
    }
}
