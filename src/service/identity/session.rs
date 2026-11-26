//! Signed token claims and server-side device sessions.
use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::D1Database;

use crate::{
    errors::{AppError, AppResult},
    models::identity::device::SessionSnapshot,
};

/// Optional claims serialized alongside the session bindings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClaimsExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "premium")]
    pub is_premium: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "email_verified")]
    pub is_email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<HashSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

/// Purpose of a session-bound JWT. Unknown and missing wire values are rejected
/// by the same session binding check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenUse {
    Access,
    Refresh,
    #[default]
    #[serde(other, rename = "")]
    Unknown,
}

/// Signed claims bound to an account and a device session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    // Required standard claims
    pub sub: String, // User ID
    pub exp: i64,    // Expiration time (Unix timestamp)
    pub nbf: i64,    // Not before time (Unix timestamp)
    pub iat: i64,    // Issued at time (Unix timestamp)
    #[serde(default)]
    pub sstamp: String,
    #[serde(default)]
    pub session_token: String,
    #[serde(default)]
    token_use: TokenUse,

    // Application-specific claims
    #[serde(flatten)]
    pub extensions: ClaimsExtensions,
}

impl Claims {
    pub(super) fn for_session(
        session: &SessionSnapshot<'_>,
        extensions: ClaimsExtensions,
        purpose: TokenUse,
        duration_seconds: i64,
    ) -> Self {
        let now = crate::utils::time::now_seconds();
        Self {
            sub: session.user_id.to_owned(),
            // Runtime configuration validates durations before issuance.
            exp: now.checked_add(duration_seconds).unwrap_or(now),
            nbf: now,
            iat: now,
            sstamp: session.security_stamp.to_owned(),
            session_token: session.session_token.to_owned(),
            token_use: purpose,
            extensions: ClaimsExtensions {
                device: Some(session.device_id.to_owned()),
                ..extensions
            },
        }
    }

    /// Returns the device identifier associated with these claims, if any.
    pub fn device(&self) -> Option<&str> {
        self.extensions.device.as_deref()
    }

    fn bound_session(&self, purpose: TokenUse) -> AppResult<SessionSnapshot<'_>> {
        let invalid = || AppError::invalid_credentials("Invalid session token");
        if purpose == TokenUse::Unknown
            || self.token_use != purpose
            || self.sstamp.is_empty()
            || self.session_token.is_empty()
        {
            return Err(invalid());
        }
        let device_id = self
            .device()
            .filter(|value| !value.is_empty())
            .ok_or_else(invalid)?;
        Ok(SessionSnapshot {
            user_id: &self.sub,
            security_stamp: &self.sstamp,
            device_id,
            session_token: &self.session_token,
        })
    }

    pub fn session_snapshot(&self) -> AppResult<SessionSnapshot<'_>> {
        self.bound_session(TokenUse::Access)
    }

    pub async fn validate_session(&self, db: &D1Database, purpose: TokenUse) -> AppResult<()> {
        validate_session(db, &self.bound_session(purpose)?).await
    }
}

pub(crate) async fn validate_session(
    db: &D1Database,
    expected: &SessionSnapshot<'_>,
) -> AppResult<()> {
    expected.revision(db).await.map(|_| ())
}

pub(crate) fn new_session_token() -> String {
    // Rotating the nonce revokes tokens from earlier logins on this device.
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_claims_bind_purpose_overflow_safely_and_require_all_fields() {
        let snap = SessionSnapshot {
            user_id: "user",
            security_stamp: "stamp",
            device_id: "device",
            session_token: "nonce",
        };
        let overflow = Claims::for_session(
            &snap,
            ClaimsExtensions::default(),
            TokenUse::Access,
            i64::MAX,
        );
        assert_eq!(overflow.exp, overflow.iat);

        let claims = Claims::for_session(
            &snap,
            ClaimsExtensions {
                device: Some("device".into()),
                ..Default::default()
            },
            TokenUse::Access,
            3600,
        );
        assert!(claims.bound_session(TokenUse::Access).is_ok());
        assert!(claims.bound_session(TokenUse::Refresh).is_err());
        assert!(claims.session_snapshot().is_ok());
        let mut missing = claims;
        missing.session_token.clear();
        assert!(missing.session_snapshot().is_err());
    }
}
