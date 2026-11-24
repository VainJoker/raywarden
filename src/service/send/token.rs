//! Purpose-bound Send access, upload and download capabilities.
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use worker::{D1Database, Env};

use super::authorize_anonymous;
use crate::{
    errors::{AppError, AppResult},
    infra::{config::send_file_token_expires_at_seconds, jwt},
    models::send::SendRow,
    service::{identity::session::Claims, send::content::decode_access_id},
};

pub(super) const TOKEN_AUDIENCE: &str = "raywarden.send";
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) enum SendScope {
    #[serde(rename = "send.access")]
    Access,
    #[serde(rename = "send.upload")]
    Upload,
    #[serde(rename = "send.download")]
    Download,
    #[serde(other)]
    Unknown,
}
const ACCESS_TOKEN_TTL_SECONDS: i64 = 300;

/// Upload capabilities carry the owner's session; reader capabilities do not.
#[derive(Clone, Copy)]
pub(super) enum TokenPurpose<'a> {
    Access,
    Upload(&'a Claims),
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SendClaims {
    pub sub: String,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    pub aud: String,
    pub scope: SendScope,
    pub send_id: String,
    pub file_id: Option<String>,
    pub access_stamp: String,
    pub sstamp: Option<String>,
    pub device: Option<String>,
    pub session_token: Option<String>,
}

pub(super) fn decode_file_token(
    secret: &str,
    token: &str,
    scope: SendScope,
    send_id: &str,
    file_id: &str,
) -> AppResult<SendClaims> {
    let claims = jwt::decode::<SendClaims>(token, secret.as_bytes(), &jwt::ValidationOptions {
        leeway_seconds: 0,
        expected_audience: Some(TOKEN_AUDIENCE.into()),
        ..Default::default()
    })?;
    if claims.sub.is_empty()
        || claims.scope != scope
        || claims.send_id != send_id
        || claims.file_id.as_deref() != Some(file_id)
        || (scope == SendScope::Download && claims.sub != send_id)
    {
        return Err(AppError::Unauthorized {
            message: "Invalid Send file token".into(),
        });
    }
    Ok(claims)
}

pub(super) fn encode_token(
    env: &Env,
    access_secret: &str,
    send: &SendRow,
    purpose: TokenPurpose<'_>,
) -> AppResult<String> {
    let (scope, subject, owner) = match purpose {
        TokenPurpose::Access => (SendScope::Access, &send.id, None),
        TokenPurpose::Upload(owner) => (SendScope::Upload, &send.user_id, Some(owner)),
        TokenPurpose::Download => (SendScope::Download, &send.id, None),
    };
    let now_seconds = crate::utils::time::now_seconds();
    let expires_at_seconds = if matches!(scope, SendScope::Upload | SendScope::Download) {
        send_file_token_expires_at_seconds(env, now_seconds)?
    } else {
        now_seconds
            .checked_add(ACCESS_TOKEN_TTL_SECONDS)
            .ok_or(AppError::Internal)?
    };
    let claims = SendClaims {
        sub: subject.clone(),
        exp: expires_at_seconds,
        nbf: now_seconds,
        iat: now_seconds,
        aud: TOKEN_AUDIENCE.into(),
        scope,
        send_id: send.id.clone(),
        file_id: send.file_id.clone(),
        access_stamp: send.access_stamp.clone(),
        sstamp: owner.map(|c| c.sstamp.clone()),
        device: owner.and_then(|c| c.device().map(str::to_owned)),
        session_token: owner.map(|c| c.session_token.clone()),
    };
    jwt::encode(&claims, access_secret.as_bytes())
}

pub(super) fn decode_token(access_secret: &str, token: &str) -> AppResult<SendClaims> {
    let claims =
        jwt::decode::<SendClaims>(token, access_secret.as_bytes(), &jwt::ValidationOptions {
            leeway_seconds: 0,
            expected_audience: Some(TOKEN_AUDIENCE.into()),
            ..Default::default()
        })?;
    if claims.scope != SendScope::Access || claims.sub != claims.send_id {
        return Err(AppError::Unauthorized {
            message: "Invalid Send access token".into(),
        });
    }
    Ok(claims)
}

#[derive(Serialize)]
pub(crate) struct SendAccessTokenResponse {
    access_token: String,
    expires_in: i64,
    token_type: &'static str,
    scope: &'static str,
}

pub(crate) struct SendTokenIssuer<'a> {
    db: &'a D1Database,
    env: &'a Env,
    access_secret: &'a str,
}

impl<'a> SendTokenIssuer<'a> {
    pub(crate) const fn new(db: &'a D1Database, env: &'a Env, access_secret: &'a str) -> Self {
        Self {
            db,
            env,
            access_secret,
        }
    }

    /// Identity's `send_access` grant calls this with `send_id=accessId`
    /// and `password_hash_b64`. Issuance never consumes a content access.
    pub(crate) async fn issue_access_token(
        &self,
        headers: &HeaderMap,
        access_id: &str,
        password: Option<&str>,
    ) -> AppResult<SendAccessTokenResponse> {
        let id = decode_access_id(access_id)?;
        let send = SendRow::fetch_by_id(self.db, &id).await?;
        authorize_anonymous(self.env, self.access_secret, headers, &send, password).await?;
        Ok(SendAccessTokenResponse {
            access_token: encode_token(self.env, self.access_secret, &send, TokenPurpose::Access)?,
            expires_in: ACCESS_TOKEN_TTL_SECONDS,
            token_type: "Bearer",
            scope: "api.send.access",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_claims(scope: SendScope) -> SendClaims {
        let now_seconds = crate::utils::time::now_seconds();
        SendClaims {
            sub: if scope == SendScope::Upload {
                "owner"
            } else {
                "send"
            }
            .into(),
            exp: now_seconds + 300,
            nbf: now_seconds - 1,
            iat: now_seconds,
            aud: TOKEN_AUDIENCE.into(),
            scope,
            send_id: "send".into(),
            file_id: Some("file".into()),
            access_stamp: "stamp".into(),
            sstamp: Some("owner-stamp".into()),
            device: Some("device".into()),
            session_token: Some("session".into()),
        }
    }

    #[test]
    fn file_capabilities_bind_signature_scope_audience_path_and_subject() {
        let secret = "file-capability-unit-test-key";
        for scope in [SendScope::Upload, SendScope::Download] {
            let claims = file_claims(scope);
            let token = jwt::encode(&claims, secret.as_bytes()).expect("sign");
            assert!(decode_file_token(secret, &token, scope, "send", "file").is_ok());
            assert!(decode_file_token("wrong-key", &token, scope, "send", "file").is_err());
            assert!(decode_file_token(secret, &token, SendScope::Access, "send", "file").is_err());
            assert!(decode_file_token(secret, &token, scope, "other-send", "file").is_err());
            assert!(decode_file_token(secret, &token, scope, "send", "other-file").is_err());
            let mut invalid = claims.clone();
            invalid.exp = crate::utils::time::now_seconds() - 1;
            let token = jwt::encode(&invalid, secret.as_bytes()).expect("sign");
            assert!(decode_file_token(secret, &token, scope, "send", "file").is_err());
            invalid = claims;
            invalid.aud = "another-service".into();
            let token = jwt::encode(&invalid, secret.as_bytes()).expect("sign");
            assert!(decode_file_token(secret, &token, scope, "send", "file").is_err());
        }
        let mut wrong_subject = file_claims(SendScope::Download);
        wrong_subject.sub = "other-send".into();
        let token = jwt::encode(&wrong_subject, secret.as_bytes()).expect("sign");
        assert!(decode_file_token(secret, &token, SendScope::Download, "send", "file").is_err());
    }
}
