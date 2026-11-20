//! Select a `HeavyDo` shard for requests eligible for offloading.
use base64::{
    Engine,
    engine::general_purpose::URL_SAFE_NO_PAD,
};
use futures_util::StreamExt;
use serde_json::Value;
use sha2::{
    Digest,
    Sha256,
};
use worker::{
    Env,
    Method,
    Request,
    Stub,
};

use crate::{
    errors::AppResult,
    infra::env::env_bool,
};

const SMALL_BODY_MAX_BYTES: usize = 65_536;
const DEFAULT_SHARD_COUNT: usize = 16;

pub(super) async fn select_stub(
    path: &str,
    request: &Request,
    env: &Env,
) -> AppResult<Option<Stub>> {
    let Some(route) = HeavyRoute::classify(path, &request.method()) else {
        return Ok(None);
    };
    if !env_bool(env, "HEAVY_DO_ENABLED", true) {
        return Ok(None);
    }
    let Ok(namespace) = env.durable_object("HEAVY_DO") else {
        return Ok(None);
    };
    let bearer = request.headers().get("Authorization")?;
    let mut key = bearer_subject(bearer.as_deref())
        .or(request.headers().get("CF-Connecting-IP")?)
        .unwrap_or_else(|| "anonymous".into());
    match route {
        HeavyRoute::Token => {
            let Some(body) = read_small_body(request).await? else {
                return Ok(None);
            };
            let Some(selected) = token_shard_key(&body, &key) else {
                return Ok(None);
            };
            key = selected;
        }
        HeavyRoute::Registration => {
            let Some(body) = read_small_body(request).await? else {
                return Ok(None);
            };
            let Ok(value) = serde_json::from_slice::<Value>(&body) else {
                return Ok(None);
            };
            key = value
                .get("email")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or(&key)
                .trim()
                .to_lowercase();
        }
        HeavyRoute::Other => {}
    }
    let count = env.var("HEAVY_DO_SHARDS").ok().map(|v| v.to_string());
    Ok(Some(
        namespace
            .id_from_name(&shard_name(&key, shard_count(count.as_deref())))?
            .get_stub()?,
    ))
}

#[derive(Debug, PartialEq, Eq)]
enum HeavyRoute {
    Token,
    Registration,
    Other,
}

impl HeavyRoute {
    fn classify(path: &str, method: &Method) -> Option<Self> {
        // Rust processes upload chunks, so use the existing CPU-offload path
        // for file writes as well. Downloads retain their native stream on the
        // edge.
        if is_file_upload(path, method) {
            return Some(Self::Other);
        }
        match (path, method) {
            ("/identity/connect/token", Method::Post) => Some(Self::Token),
            (
                "/api/accounts/register" |
                "/identity/accounts/register" |
                "/identity/accounts/register/finish",
                Method::Post,
            ) => Some(Self::Registration),
            ("/api/accounts", Method::Delete) |
            (
                "/api/two-factor/authenticator",
                Method::Post | Method::Put | Method::Delete,
            ) |
            ("/api/two-factor/disable", Method::Post | Method::Put) |
            (
                "/api/ciphers/import" |
                "/api/accounts/password" |
                "/api/accounts/set-password" |
                "/api/accounts/kdf" |
                "/api/accounts/delete" |
                "/api/ciphers/purge" |
                "/api/accounts/security-stamp" |
                "/api/accounts/key-management/rotate-user-keys" |
                "/api/accounts/key-management/rotate-user-account-keys" |
                "/api/accounts/verify-password" |
                "/accounts/verify-password" |
                "/api/accounts/api-key" |
                "/api/accounts/rotate-api-key" |
                "/api/two-factor/get-authenticator" |
                "/api/two-factor/get-recover" |
                "/api/two-factor/recover",
                Method::Post,
            ) => Some(Self::Other),
            _ => None,
        }
    }
}

fn is_file_upload(path: &str, method: &Method) -> bool {
    if !matches!(method, Method::Post | Method::Put) {
        return false;
    }
    let mut segments = path.trim_matches('/').split('/');
    if !path.starts_with("/ciphers/") &&
        !path.starts_with("/sends/") &&
        segments.next() != Some("api")
    {
        return false;
    }
    let parts: Vec<_> = segments.collect();
    match (method, parts.as_slice()) {
        (Method::Post, ["ciphers", _, "attachment", id]) => *id != "v2",
        (Method::Post, ["sends", _, "file", _]) |
        (Method::Put, ["ciphers", _, "attachment", _, "azure-upload"]) |
        (
            Method::Post | Method::Put,
            ["sends", _, "file", _, "azure-upload"],
        ) => true,
        _ => false,
    }
}

fn shard_count(value: Option<&str>) -> usize {
    value
        .and_then(|v| v.trim().parse().ok())
        .filter(|n| (1..=64).contains(n))
        .unwrap_or(DEFAULT_SHARD_COUNT)
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
    let segment = value?.strip_prefix("Bearer ")?.split('.').nth(1)?;
    if segment.len() > 16_384 {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let subject = claims.get("sub")?.as_str()?;
    (!subject.is_empty() && subject.encode_utf16().count() <= 256)
        .then(|| subject.to_owned())
}

fn token_shard_key(body: &[u8], fallback: &str) -> Option<String> {
    let (mut grant_type, mut auth_request, mut username, mut client_id) =
        (None, None, None, None);
    for (key, value) in url::form_urlencoded::parse(body) {
        let field =
            match crate::service::identity::oauth::normalize_form_key(&key)
                .as_str()
            {
                "granttype" => &mut grant_type,
                "authrequest" => &mut auth_request,
                "username" => &mut username,
                "clientid" => &mut client_id,
                _ => continue,
            };
        field.get_or_insert(value);
    }
    if !grant_type.as_deref().is_some_and(|grant| {
        grant.trim().eq_ignore_ascii_case("password") ||
            grant.trim().eq_ignore_ascii_case("client_credentials")
    }) || auth_request
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return None;
    }
    Some(
        username
            .as_deref()
            .filter(|v| !v.is_empty())
            .or_else(|| client_id.as_deref().filter(|v| !v.is_empty()))
            .unwrap_or(fallback)
            .trim()
            .to_lowercase(),
    )
}

fn has_small_content_length(value: Option<&str>) -> bool {
    value.filter(|v| !v.is_empty()).is_none_or(|v| {
        v.bytes().all(|b| b.is_ascii_digit()) &&
            v.parse::<usize>().is_ok_and(|n| n <= SMALL_BODY_MAX_BYTES)
    })
}

async fn read_small_body(request: &Request) -> AppResult<Option<Vec<u8>>> {
    if !has_small_content_length(
        request.headers().get("Content-Length")?.as_deref(),
    ) {
        return Ok(None);
    }
    if request.inner().body().is_none() {
        return Ok(Some(Vec::new()));
    }
    let mut clone = request.clone()?;
    let mut stream = clone.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
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
    fn file_uploads_offload_without_routing_downloads_or_metadata_through_heavy()
     {
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
                HeavyRoute::classify(path, &method),
                Some(HeavyRoute::Other),
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
            assert_eq!(
                HeavyRoute::classify(path, &method),
                None,
                "{method} {path}"
            );
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
        assert_eq!(token_shard_key(b"grant_type=password&username=User%40Example.com&password=opaque", "fallback").as_deref(), Some("user@example.com"));
        assert_eq!(
            token_shard_key(
                b"grant_type=client_credentials&client_id=user.test",
                "fallback"
            )
            .as_deref(),
            Some("user.test")
        );
        assert_eq!(
            token_shard_key(b"grant_type=password&authRequest=", "fallback")
                .as_deref(),
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
            HeavyRoute::classify("/api/ciphers/import", &Method::Post),
            Some(HeavyRoute::Other)
        );
        assert!(
            HeavyRoute::classify("/api/ciphers/import", &Method::Get).is_none()
        );
        assert!(HeavyRoute::classify("/api/sync", &Method::Post).is_none());
        assert_eq!(
            HeavyRoute::classify("/api/accounts", &Method::Delete),
            Some(HeavyRoute::Other)
        );
        let set_password = "/api/accounts/set-password";
        assert_eq!(
            HeavyRoute::classify(set_password, &Method::Post),
            Some(HeavyRoute::Other)
        );
        assert!(HeavyRoute::classify(set_password, &Method::Get).is_none());
        assert!(HeavyRoute::classify(set_password, &Method::Delete).is_none());
    }

    #[test]
    fn token_and_registration_routes_only_inspect_post_bodies() {
        for (path, expected) in [
            ("/identity/connect/token", HeavyRoute::Token),
            ("/api/accounts/register", HeavyRoute::Registration),
            ("/identity/accounts/register", HeavyRoute::Registration),
            (
                "/identity/accounts/register/finish",
                HeavyRoute::Registration,
            ),
        ] {
            assert_eq!(
                HeavyRoute::classify(path, &Method::Post),
                Some(expected)
            );
            for method in
                [Method::Get, Method::Put, Method::Delete, Method::Options]
            {
                assert!(
                    HeavyRoute::classify(path, &method).is_none(),
                    "{method} {path}"
                );
            }
        }
    }

    #[test]
    fn untrusted_subjects_only_choose_bounded_deterministic_shards() {
        for subject in ["alice", "bob", "arbitrary-third-party-subject", "usér"]
        {
            let payload = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({"sub":subject}))
                    .expect("test fixture should be valid"),
            );
            let token = format!("Bearer header.{payload}.signature");
            assert_eq!(bearer_subject(Some(&token)).as_deref(), Some(subject));
            assert!(
                ["heavy:0", "heavy:1"]
                    .contains(&shard_name(subject, 2).as_str())
            );
        }
        assert_eq!(shard_name("alice", 16), "heavy:8");
        assert!(bearer_subject(Some("Bearer malformed")).is_none());
        let oversized = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"sub":"x".repeat(257)}))
                .expect("test fixture should be valid"),
        );
        assert!(
            bearer_subject(Some(&format!(
                "Bearer header.{oversized}.signature"
            )))
            .is_none()
        );
        assert_eq!(shard_count(Some("2")), 2);
        for value in [None, Some("0"), Some("65"), Some("invalid")] {
            assert_eq!(shard_count(value), DEFAULT_SHARD_COUNT);
        }
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
