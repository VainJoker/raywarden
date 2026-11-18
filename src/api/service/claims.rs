use std::collections::HashSet;

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

use crate::{
    api::AppState,
    errors::{
        AppError,
        AuthError,
    },
    infra::jwt::{
        ValidationOptions,
        decode,
    },
    models::device::{
        DeviceDB,
        SessionSnapshot,
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
    pub sub:           String, // User ID
    pub exp:           i64,    // Expiration time (Unix timestamp)
    pub nbf:           i64,    // Not before time (Unix timestamp)
    pub iat:           i64,    // Issued at time (Unix timestamp)
    #[serde(default)]
    pub sstamp:        String,
    #[serde(default)]
    pub session_token: String,
    #[serde(default)]
    pub token_use:     String,

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
        let now = crate::infra::time::now_seconds();
        Self {
            sub:           user_id,
            // Runtime configuration validates durations before issuance. Keep
            // this constructor safe for any other caller as well.
            exp:           now.checked_add(duration_seconds).unwrap_or(now),
            nbf:           now,
            iat:           now,
            sstamp:        String::new(),
            session_token: String::new(),
            token_use:     String::new(),
            extensions:    ClaimsExtensions {
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

fn bearer_token(parts: &Parts) -> Result<&str, AppError> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(AppError::Auth(AuthError::MissingToken))
}

impl Claims {
    pub fn validate_purpose(&self, purpose: &str) -> Result<(), AppError> {
        if self.token_use != purpose ||
            self.sstamp.is_empty() ||
            self.session_token.is_empty() ||
            self.device().is_none_or(str::is_empty)
        {
            return Err(AppError::Auth(AuthError::InvalidCredentials(
                "Invalid session token".to_string(),
            )));
        }
        Ok(())
    }

    pub fn session_snapshot(&self) -> Result<SessionSnapshot<'_>, AppError> {
        self.validate_purpose("access")?;
        Ok(SessionSnapshot {
            user_id:        &self.sub,
            security_stamp: &self.sstamp,
            device_id:      self.device().unwrap_or_default(),
            session_token:  &self.session_token,
        })
    }

    pub async fn validate_session(
        &self,
        db: &worker::D1Database,
        purpose: &str,
    ) -> Result<(), AppError> {
        self.validate_purpose(purpose)?;
        DeviceDB::validate_session(
            db,
            &self.sub,
            self.device().unwrap_or_default(),
            &self.session_token,
            &self.sstamp,
        )
        .await
    }
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
            state.config.jwt_secret.as_bytes(),
            &ValidationOptions::default(),
        )?
        .claims;
        claims.validate_session(&state.get_db(), "access").await?;
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overflowing_duration_cannot_wrap_or_panic_during_token_issuance() {
        let claims = Claims::new(
            "user".into(),
            "user@example.com".into(),
            "User".into(),
            false,
            false,
            HashSet::new(),
            Some("device".into()),
            i64::MAX,
        );
        assert_eq!(claims.exp, claims.iat);
    }

    #[test]
    fn tokens_are_bound_to_purpose_and_session() {
        let mut claims = Claims::new(
            "user".into(),
            "user@example.com".into(),
            "User".into(),
            true,
            false,
            HashSet::new(),
            Some("device".into()),
            3600,
        );
        assert!(claims.validate_purpose("access").is_err());
        claims.sstamp = "stamp".into();
        claims.session_token = "nonce".into();
        claims.token_use = "access".into();
        assert!(claims.validate_purpose("access").is_ok());
        assert!(claims.validate_purpose("refresh").is_err());
        claims.token_use = "send.access".into();
        assert!(claims.validate_purpose("access").is_err());
    }

    #[test]
    fn session_snapshot_preserves_bindings_and_requires_complete_access_claims()
    {
        let mut claims = Claims::new(
            "user".into(),
            "user@example.com".into(),
            "User".into(),
            false,
            false,
            HashSet::new(),
            Some("device".into()),
            3600,
        );
        assert!(claims.session_snapshot().is_err());
        claims.token_use = "access".into();
        claims.sstamp = "stamp".into();
        claims.session_token = "nonce".into();
        let session = claims.session_snapshot().unwrap();
        assert_eq!(session.user_id, "user");
        assert_eq!(session.security_stamp, "stamp");
        assert_eq!(session.device_id, "device");
        assert_eq!(session.session_token, "nonce");
        for missing in 0..4 {
            let mut invalid = claims.clone();
            match missing {
                0 => invalid.token_use = "refresh".into(),
                1 => invalid.sstamp.clear(),
                2 => invalid.session_token.clear(),
                _ => invalid.extensions.device = None,
            }
            assert!(invalid.session_snapshot().is_err());
        }
    }
}
