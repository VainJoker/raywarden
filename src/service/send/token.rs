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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FileTokenScope {
    Upload,
    Download,
}

impl From<FileTokenScope> for SendScope {
    fn from(scope: FileTokenScope) -> Self {
        match scope {
            FileTokenScope::Upload => Self::Upload,
            FileTokenScope::Download => Self::Download,
        }
    }
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

#[derive(Serialize)]
struct SendClaimsRef<'a> {
    sub: &'a str,
    exp: i64,
    nbf: i64,
    iat: i64,
    aud: &'static str,
    scope: SendScope,
    send_id: &'a str,
    file_id: Option<&'a str>,
    access_stamp: &'a str,
    sstamp: Option<&'a str>,
    device: Option<&'a str>,
    session_token: Option<&'a str>,
}

pub(super) fn decode_file_token(
    secret: &str,
    token: &str,
    purpose: FileTokenScope,
    send_id: &str,
    file_id: &str,
) -> AppResult<SendClaims> {
    let scope = SendScope::from(purpose);
    let claims = decode_claims(secret, token)?;
    if claims.sub.is_empty()
        || claims.scope != scope
        || claims.send_id != send_id
        || claims.file_id.as_deref() != Some(file_id)
        || (purpose == FileTokenScope::Download && claims.sub != send_id)
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
        TokenPurpose::Access => (SendScope::Access, send.id.as_str(), None),
        TokenPurpose::Upload(owner) => (SendScope::Upload, send.user_id.as_str(), Some(owner)),
        TokenPurpose::Download => (SendScope::Download, send.id.as_str(), None),
    };
    let now_seconds = crate::utils::time::now_seconds();
    let expires_at_seconds = if matches!(scope, SendScope::Upload | SendScope::Download) {
        send_file_token_expires_at_seconds(env, now_seconds)?
    } else {
        now_seconds
            .checked_add(ACCESS_TOKEN_TTL_SECONDS)
            .ok_or_else(|| AppError::internal("Send access token expiration overflowed"))?
    };
    let claims = SendClaimsRef {
        sub: subject,
        exp: expires_at_seconds,
        nbf: now_seconds,
        iat: now_seconds,
        aud: TOKEN_AUDIENCE,
        scope,
        send_id: &send.id,
        file_id: send.file_id.as_deref(),
        access_stamp: &send.access_stamp,
        sstamp: owner.map(|c| c.sstamp.as_str()),
        device: owner.and_then(Claims::device),
        session_token: owner.map(|c| c.session_token.as_str()),
    };
    jwt::encode(&claims, access_secret.as_bytes())
}

pub(super) fn decode_token(access_secret: &str, token: &str) -> AppResult<SendClaims> {
    let claims = decode_claims(access_secret, token)?;
    if claims.scope != SendScope::Access || claims.sub != claims.send_id {
        return Err(AppError::Unauthorized {
            message: "Invalid Send access token".into(),
        });
    }
    Ok(claims)
}

fn decode_claims(secret: &str, token: &str) -> AppResult<SendClaims> {
    jwt::decode(token, secret.as_bytes(), &jwt::ValidationOptions {
        leeway_seconds: 0,
        expected_audience: Some(TOKEN_AUDIENCE.into()),
        ..Default::default()
    })
    .map_err(AppError::from)
}

#[derive(Serialize)]
pub(crate) struct SendAccessTokenResponse {
    access_token: String,
    expires_in: i64,
    token_type: &'static str,
    scope: &'static str,
}

/// The identity grant supplies `send_id=accessId` and `password_hash_b64`.
/// Issuance never consumes a content access.
pub(crate) async fn issue_access_token(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    headers: &HeaderMap,
    access_id: &str,
    password: Option<&str>,
) -> AppResult<SendAccessTokenResponse> {
    let id = decode_access_id(access_id)?;
    let send = SendRow::fetch_by_id(db, &id).await?;
    authorize_anonymous(env, access_secret, headers, &send, password).await?;
    Ok(SendAccessTokenResponse {
        access_token: encode_token(env, access_secret, &send, TokenPurpose::Access)?,
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        token_type: "Bearer",
        scope: "api.send.access",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_capabilities_bind_signature_scope_audience_and_path() {
        let now = crate::utils::time::now_seconds();
        let claims = SendClaims {
            sub: "send".into(),
            exp: now + 300,
            nbf: now - 1,
            iat: now,
            aud: TOKEN_AUDIENCE.into(),
            scope: SendScope::Download,
            send_id: "send".into(),
            file_id: Some("file".into()),
            access_stamp: "stamp".into(),
            sstamp: None,
            device: None,
            session_token: None,
        };
        let token = jwt::encode(&claims, b"secret").expect("sign");
        assert!(
            decode_file_token("secret", &token, FileTokenScope::Download, "send", "file").is_ok()
        );
        assert!(
            decode_file_token("wrong", &token, FileTokenScope::Download, "send", "file").is_err()
        );
        assert!(
            decode_file_token("secret", &token, FileTokenScope::Upload, "send", "file").is_err()
        );
        assert!(
            decode_file_token("secret", &token, FileTokenScope::Download, "other", "file").is_err()
        );
    }
}
