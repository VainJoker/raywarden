//! Select a `heavydo` shard and execute offloaded requests on the shared app.
use std::borrow::Cow;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use worker::{
    DurableObject, Env, HttpRequest, Method, Request, Response, Result as WorkerResult, State,
    Stub, durable_object,
};

use crate::{
    api::{
        bootstrap::{handle_request, worker_error_response},
        common::response::into_worker_response,
        middleware::cors::CorsContext,
    },
    errors::AppResult,
    infra::config::{env_bool, heavy_shard_count},
    service::identity::oauth::token_shard_key,
    utils::parse_bearer,
};

const SMALL_BODY_MAX_BYTES: usize = 65_536;

/// CPU offload shares the exact application stack, including authentication,
/// body limits, post-commit notifications and CORS.
// The adapter name is also the lowercase Cloudflare class export.
#[allow(non_camel_case_types)]
#[durable_object]
pub struct heavydo {
    env: Env,
}

impl DurableObject for heavydo {
    fn new(_state: State, env: Env) -> Self {
        crate::infra::init(&env);
        Self { env }
    }

    async fn fetch(&self, req: Request) -> WorkerResult<Response> {
        let cors = CorsContext::new(&req, &self.env);
        let http_req: HttpRequest = req.try_into()?;
        match handle_request(http_req, self.env.clone(), cors.policy()).await {
            Ok(response) => into_worker_response(response),
            Err(error) => worker_error_response(error, &cors),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Route {
    Token,
    Registration,
    Standard,
}

impl Route {
    pub(super) fn classify(path: &str, method: &Method) -> Option<Self> {
        // Rust processes upload chunks, so use the existing CPU-offload path
        // for file writes as well. Downloads retain their native stream on the
        // edge.
        if is_file_upload(path, method) {
            return Some(Self::Standard);
        }
        match (path, method) {
            ("/identity/connect/token", Method::Post) => Some(Self::Token),
            (
                "/api/accounts/register"
                | "/identity/accounts/register"
                | "/identity/accounts/register/finish",
                Method::Post,
            ) => Some(Self::Registration),
            ("/api/accounts", Method::Delete)
            | ("/api/two-factor/authenticator", Method::Post | Method::Put | Method::Delete)
            | ("/api/two-factor/disable", Method::Post | Method::Put)
            | (
                "/api/ciphers/import"
                | "/api/accounts/password"
                | "/api/accounts/set-password"
                | "/api/accounts/kdf"
                | "/api/accounts/delete"
                | "/api/ciphers/purge"
                | "/api/accounts/security-stamp"
                | "/api/accounts/key-management/rotate-user-keys"
                | "/api/accounts/key-management/rotate-user-account-keys"
                | "/api/accounts/verify-password"
                | "/accounts/verify-password"
                | "/api/accounts/api-key"
                | "/api/accounts/rotate-api-key"
                | "/api/two-factor/get-authenticator"
                | "/api/two-factor/get-recover"
                | "/api/two-factor/recover",
                Method::Post,
            ) => Some(Self::Standard),
            _ => None,
        }
    }

    pub(super) async fn select_stub(self, request: &Request, env: &Env) -> AppResult<Option<Stub>> {
        if !env_bool(env, "HEAVY_DO_ENABLED", true) {
            return Ok(None);
        }
        let Ok(namespace) = env.durable_object("heavydo") else {
            return Ok(None);
        };
        let bearer = request.headers().get("Authorization")?;
        let mut key = bearer_subject(bearer.as_deref())
            .or(request.headers().get("CF-Connecting-IP")?)
            .unwrap_or_else(|| "anonymous".into());
        match self {
            Self::Token => {
                let Some(body) = read_small_body(request).await? else {
                    return Ok(None);
                };
                let Some(selected) = token_shard_key(&body, &key) else {
                    return Ok(None);
                };
                key = selected;
            }
            Self::Registration => {
                #[derive(Deserialize)]
                struct RegistrationPeek<'a> {
                    #[serde(default, borrow)]
                    email: Option<Cow<'a, str>>,
                }

                let Some(body) = read_small_body(request).await? else {
                    return Ok(None);
                };
                let Ok(peek) = serde_json::from_slice::<RegistrationPeek<'_>>(&body) else {
                    return Ok(None);
                };
                key = peek
                    .email
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .unwrap_or(&key)
                    .trim()
                    .to_lowercase();
            }
            Self::Standard => {}
        }
        Ok(Some(
            namespace
                .id_from_name(&shard_name(&key, heavy_shard_count(env)))?
                .get_stub()?,
        ))
    }
}

fn is_file_upload(path: &str, method: &Method) -> bool {
    if !matches!(method, Method::Post | Method::Put) {
        return false;
    }
    let Some(rest) = path
        .strip_prefix("/api/")
        .or_else(|| path.strip_prefix('/'))
        .map(|subpath| subpath.trim_end_matches('/'))
    else {
        return false;
    };
    let mut s = rest.split('/');
    match (
        method,
        s.next(),
        s.next(),
        s.next(),
        s.next(),
        s.next(),
        s.next(),
    ) {
        (Method::Post, Some("ciphers"), Some(_), Some("attachment"), Some(id), None, None) => {
            id != "v2"
        }
        (Method::Post, Some("sends"), Some(_), Some("file"), Some(_), None, None)
        | (
            Method::Put,
            Some("ciphers"),
            Some(_),
            Some("attachment"),
            Some(_),
            Some("azure-upload"),
            None,
        )
        | (
            Method::Post | Method::Put,
            Some("sends"),
            Some(_),
            Some("file"),
            Some(_),
            Some("azure-upload"),
            None,
        ) => true,
        _ => false,
    }
}

fn shard_name(key: &str, count: usize) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!(
        "heavy:{}",
        usize::from(u16::from_be_bytes([digest[0], digest[1]])) % count
    )
}

// This unverified subject only selects a bounded shard. The DO verifies access.
fn bearer_subject(value: Option<&str>) -> Option<String> {
    #[derive(Deserialize)]
    struct SubjectPeek<'a> {
        #[serde(default, borrow)]
        sub: Option<Cow<'a, str>>,
    }

    let segment = value.and_then(parse_bearer)?.split('.').nth(1)?;
    if segment.len() > 16_384 {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).ok()?;
    let claims: SubjectPeek<'_> = serde_json::from_slice(&decoded).ok()?;
    let subject = claims.sub?;
    (!subject.is_empty() && subject.encode_utf16().count() <= 256).then(|| subject.into_owned())
}

fn has_small_content_length(value: Option<&str>) -> bool {
    value.filter(|v| !v.is_empty()).is_none_or(|v| {
        v.bytes().all(|b| b.is_ascii_digit())
            && v.parse::<usize>().is_ok_and(|n| n <= SMALL_BODY_MAX_BYTES)
    })
}

async fn read_small_body(request: &Request) -> AppResult<Option<Vec<u8>>> {
    if !has_small_content_length(request.headers().get("Content-Length")?.as_deref()) {
        return Ok(None);
    }
    if request.inner().body().is_none() {
        return Ok(Some(Vec::new()));
    }
    // A shard key is optional. Let Axum handle the original body if the peek
    // fails.
    let Ok(mut stream) = request.clone().and_then(|mut clone| clone.stream()) else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return Ok(None);
        };
        if chunk.len() > SMALL_BODY_MAX_BYTES - bytes.len() {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uploads_offload_without_routing_downloads_or_metadata_through_heavy() {
        for (path, method) in [
            ("/api/ciphers/c/attachment/a", Method::Post),
            ("/api/ciphers/c/attachment/a/azure-upload", Method::Put),
            ("/api/sends/s/file/f", Method::Post),
            ("/api/sends/s/file/f/azure-upload", Method::Put),
            ("/api/sends/s/file/f/azure-upload", Method::Post),
            ("/ciphers/c/attachment/a", Method::Post),
            ("/sends/s/file/f", Method::Post),
        ] {
            assert_eq!(
                Route::classify(path, &method),
                Some(Route::Standard),
                "{method} {path}"
            );
        }
        for (path, method) in [
            ("/api/ciphers/c/attachment/v2", Method::Post),
            ("/api/sends/file/v2", Method::Post),
            ("/api/ciphers/c/attachment/a", Method::Delete),
            ("/api/ciphers/c/attachment/a/delete", Method::Post),
            ("/api/ciphers/c/attachment/a/download", Method::Get),
            ("/api/sends/s", Method::Delete),
            ("/api/sends/s/f", Method::Get),
        ] {
            assert_eq!(Route::classify(path, &method), None, "{method} {path}");
        }
    }

    #[test]
    fn offload_selection_keeps_lightweight_grants_and_invalid_bodies_local() {
        for body in [
            "grant_type=refresh_token",
            "grant_type=send_access",
            "grant_type=password&authRequest=id",
            "grant_type=password&authrequest=id",
        ] {
            assert!(token_shard_key(body.as_bytes(), "fallback").is_none());
        }
        assert_eq!(
            token_shard_key(
                b"grant_type=password&username=User%40Example.com&password=opaque",
                "fallback"
            )
            .as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            token_shard_key(
                b"grant_type=client_credentials&client_id=user.test",
                "fallback"
            )
            .as_deref(),
            Some("user.test")
        );
        assert_eq!(
            token_shard_key(b"grant_type=password&authRequest=", "fallback").as_deref(),
            Some("fallback")
        );
        assert_eq!(
            token_shard_key(
                b"GrantType=password&username=first&User_Name=second",
                "fallback"
            )
            .as_deref(),
            Some("first")
        );
        assert_eq!(
            Route::classify("/api/ciphers/import", &Method::Post),
            Some(Route::Standard)
        );
        assert!(Route::classify("/api/ciphers/import", &Method::Get).is_none());
        assert!(Route::classify("/api/sync", &Method::Post).is_none());
        assert_eq!(
            Route::classify("/api/accounts", &Method::Delete),
            Some(Route::Standard)
        );
        let set_password = "/api/accounts/set-password";
        assert_eq!(
            Route::classify(set_password, &Method::Post),
            Some(Route::Standard)
        );
        assert!(Route::classify(set_password, &Method::Get).is_none());
        assert!(Route::classify(set_password, &Method::Delete).is_none());
    }

    #[test]
    fn token_and_registration_routes_only_inspect_post_bodies() {
        for (path, expected) in [
            ("/identity/connect/token", Route::Token),
            ("/api/accounts/register", Route::Registration),
            ("/identity/accounts/register", Route::Registration),
            ("/identity/accounts/register/finish", Route::Registration),
        ] {
            assert_eq!(Route::classify(path, &Method::Post), Some(expected));
            for method in [Method::Get, Method::Put, Method::Delete, Method::Options] {
                assert!(Route::classify(path, &method).is_none(), "{method} {path}");
            }
        }
    }

    #[test]
    fn untrusted_subjects_only_choose_bounded_deterministic_shards() {
        for subject in ["alice", "bob", "arbitrary-third-party-subject", "usér"] {
            let payload = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({"sub":subject}))
                    .expect("test fixture should be valid"),
            );
            let token = format!("Bearer header.{payload}.signature");
            assert_eq!(bearer_subject(Some(&token)).as_deref(), Some(subject));
            assert!(["heavy:0", "heavy:1"].contains(&shard_name(subject, 2).as_str()));
        }
        assert_eq!(shard_name("alice", 16), "heavy:8");
        assert!(bearer_subject(Some("Bearer malformed")).is_none());
        let oversized = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"sub":"x".repeat(257)}))
                .expect("test fixture should be valid"),
        );
        assert!(bearer_subject(Some(&format!("Bearer header.{oversized}.signature"))).is_none());
    }

    #[test]
    fn bounded_reads_reject_invalid_or_oversized_lengths() {
        for value in [None, Some(""), Some("0"), Some("65536")] {
            assert!(has_small_content_length(value));
        }
        for value in [
            Some("65537"),
            Some("-1"),
            Some(" 1"),
            Some("1.5"),
            Some("not-a-number"),
        ] {
            assert!(!has_small_content_length(value));
        }
    }
}
