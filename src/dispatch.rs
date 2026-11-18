//! Public Durable Object routing before the shared Axum application.
use base64::{
    Engine as _,
    engine::general_purpose::URL_SAFE_NO_PAD,
};
use futures_util::StreamExt;
use serde_json::Value;
use sha2::{
    Digest,
    Sha256,
};
use wasm_bindgen::JsCast;
use worker::{
    Env,
    Method,
    Request,
    Response,
};

use crate::{
    errors::AppResult,
    infra::cors::CorsPolicy,
};

const SMALL_BODY_LIMIT: usize = 65_536;
const DEFAULT_SHARDS: usize = 16;
const NOTIFICATION_METHODS: &str = "GET,POST,OPTIONS";
const ALL_METHODS: &str = "GET,HEAD,POST,PUT,DELETE,OPTIONS";

pub(crate) enum DispatchResult {
    Handled(Response),
    Continue(Request),
}

/// Capture CORS before moving the original streaming request. No D1 lookup.
pub(crate) struct CorsContext {
    allow_origin:      Option<String>,
    requested_headers: String,
}

impl CorsContext {
    pub(crate) fn new(request: &Request, env: &Env) -> Self {
        let origin = request.headers().get("Origin").ok().flatten();
        Self {
            allow_origin:      CorsPolicy::from_env(env)
                .origin(origin.as_deref()),
            requested_headers: request
                .headers()
                .get("Access-Control-Request-Headers")
                .ok()
                .flatten()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| {
                    "authorization,content-type,device-type".into()
                }),
        }
    }

    pub(crate) fn apply(&self, response: Response) -> AppResult<Response> {
        self.apply_methods(response, ALL_METHODS)
    }

    fn apply_methods(
        &self,
        response: Response,
        methods: &str,
    ) -> AppResult<Response> {
        // Preserve the upgrade and its WebSocket without header reconstruction.
        if response.status_code() == 101 {
            return Ok(response);
        }
        let headers = response.headers().clone();
        headers.delete("Access-Control-Allow-Origin")?;
        headers.delete("Access-Control-Allow-Credentials")?;
        if let Some(origin) = &self.allow_origin {
            headers.set("Access-Control-Allow-Origin", origin)?;
        }
        headers.append("Vary", "Origin")?;
        headers.set("Access-Control-Allow-Methods", methods)?;
        headers.set("Access-Control-Allow-Headers", &self.requested_headers)?;
        Ok(response.with_headers(headers))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum NotificationRoute {
    Pass,
    NotFound,
    Options,
    MethodNotAllowed,
    Forward,
}

fn normalized_path(path: &str) -> &str {
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        "/"
    } else {
        normalized
    }
}

fn notification_route(path: &str, method: &Method) -> NotificationRoute {
    if !path.starts_with("/notifications/") {
        return NotificationRoute::Pass;
    }
    let expected = match path {
        "/notifications/hub" | "/notifications/anonymous-hub" => Method::Get,
        "/notifications/hub/negotiate" |
        "/notifications/anonymous-hub/negotiate" => Method::Post,
        _ => return NotificationRoute::NotFound,
    };
    if *method == Method::Options {
        NotificationRoute::Options
    } else if *method == expected {
        NotificationRoute::Forward
    } else {
        NotificationRoute::MethodNotAllowed
    }
}

fn heavy_route(path: &str, method: &Method) -> bool {
    // Rust processes upload chunks, so use the existing CPU-offload path for
    // file writes as well. Downloads retain their native stream on the edge.
    if crate::api::service::mutation::is_file_upload(method.as_ref(), path) {
        return true;
    }
    match path {
        "/api/accounts" => *method == Method::Delete,
        "/api/two-factor/authenticator" => {
            matches!(method, Method::Post | Method::Put | Method::Delete)
        }
        "/api/two-factor/disable" => {
            matches!(method, Method::Post | Method::Put)
        }
        "/api/ciphers/import" |
        "/api/accounts/register" |
        "/identity/accounts/register" |
        "/identity/accounts/register/finish" |
        "/api/accounts/password" |
        "/api/accounts/kdf" |
        "/api/accounts/delete" |
        "/api/ciphers/purge" |
        "/api/accounts/security-stamp" |
        "/api/accounts/key-management/rotate-user-keys" |
        "/api/accounts/key-management/rotate-user-account-keys" |
        "/api/accounts/verify-password" |
        "/api/accounts/api-key" |
        "/api/accounts/rotate-api-key" |
        "/api/two-factor/get-authenticator" |
        "/api/two-factor/get-recover" |
        "/api/two-factor/recover" => *method == Method::Post,
        _ => false,
    }
}

fn heavy_enabled(value: Option<&str>) -> bool {
    !value.is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        )
    })
}

fn shard_count(value: Option<&str>) -> usize {
    value
        .and_then(|v| v.trim().parse().ok())
        .filter(|n| (1..=64).contains(n))
        .unwrap_or(DEFAULT_SHARDS)
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
    let params: Vec<_> = url::form_urlencoded::parse(body).collect();
    let get = |key| {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_ref())
    };
    if !matches!(get("grant_type"), Some("password" | "client_credentials")) ||
        ["authRequest", "authrequest"]
            .iter()
            .any(|key| get(key).is_some_and(|v| !v.is_empty()))
    {
        return None;
    }
    Some(
        get("username")
            .filter(|v| !v.is_empty())
            .or_else(|| get("client_id").filter(|v| !v.is_empty()))
            .unwrap_or(fallback)
            .trim()
            .to_lowercase(),
    )
}

fn small_content_length(value: Option<&str>) -> bool {
    value.filter(|v| !v.is_empty()).is_none_or(|v| {
        v.bytes().all(|b| b.is_ascii_digit()) &&
            v.parse::<usize>().is_ok_and(|n| n <= SMALL_BODY_LIMIT)
    })
}

async fn small_body(request: &Request) -> AppResult<Option<Vec<u8>>> {
    if !small_content_length(
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
        if chunk.len() > SMALL_BODY_LIMIT - bytes.len() {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(bytes))
}

fn normalized_request(request: &Request, path: &str) -> AppResult<Request> {
    let mut url = request.url()?;
    url.set_path(path);
    // Equivalent to new Request(url, original): preserve the original body,
    // headers, method and request options without buffering a stream.
    let init: &web_sys::RequestInit = request.inner().unchecked_ref();
    let normalized =
        web_sys::Request::new_with_str_and_init(url.as_str(), init)
            .map_err(worker::Error::from)?;
    Ok(normalized.into())
}

pub(crate) async fn route(
    request: Request,
    env: &Env,
    cors: &CorsContext,
) -> AppResult<DispatchResult> {
    let raw_path = request.path();
    let path = normalized_path(&raw_path);
    let method = request.method();
    let response = match notification_route(path, &method) {
        NotificationRoute::Pass => None,
        NotificationRoute::NotFound => Some(Response::error("Not found", 404)?),
        NotificationRoute::Options => Some(Response::empty()?.with_status(204)),
        route => match env.durable_object("NOTIFY_DO") {
            Err(_) => {
                Some(Response::error("Notifications are not configured", 503)?)
            }
            Ok(_) if route == NotificationRoute::MethodNotAllowed => {
                Some(Response::error("Method not allowed", 405)?)
            }
            Ok(namespace) => {
                let stub = namespace.id_from_name("global")?.get_stub()?;
                Some(
                    stub.fetch_with_request(normalized_request(
                        &request, path,
                    )?)
                    .await?,
                )
            }
        },
    };
    if let Some(response) = response {
        return Ok(DispatchResult::Handled(
            cors.apply_methods(response, NOTIFICATION_METHODS)?,
        ));
    }
    let enabled = env.var("HEAVY_DO_ENABLED").ok().map(|v| v.to_string());
    if !heavy_enabled(enabled.as_deref()) {
        return Ok(DispatchResult::Continue(request));
    }
    let Ok(namespace) = env.durable_object("HEAVY_DO") else {
        return Ok(DispatchResult::Continue(request));
    };
    let bearer = request.headers().get("Authorization")?;
    let mut key = bearer_subject(bearer.as_deref())
        .or(request.headers().get("CF-Connecting-IP")?)
        .unwrap_or_else(|| "anonymous".into());
    if path == "/identity/connect/token" && method == Method::Post {
        let Some(body) = small_body(&request).await? else {
            return Ok(DispatchResult::Continue(request));
        };
        let Some(selected) = token_shard_key(&body, &key) else {
            return Ok(DispatchResult::Continue(request));
        };
        key = selected;
    } else {
        if !heavy_route(path, &method) {
            return Ok(DispatchResult::Continue(request));
        }
        if matches!(
            path,
            "/api/accounts/register" |
                "/identity/accounts/register" |
                "/identity/accounts/register/finish"
        ) {
            let Some(body) = small_body(&request).await? else {
                return Ok(DispatchResult::Continue(request));
            };
            let Ok(value) = serde_json::from_slice::<Value>(&body) else {
                return Ok(DispatchResult::Continue(request));
            };
            key = value
                .get("email")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or(&key)
                .trim()
                .to_lowercase();
        }
    }
    let count = env.var("HEAVY_DO_SHARDS").ok().map(|v| v.to_string());
    let stub = namespace
        .id_from_name(&shard_name(&key, shard_count(count.as_deref())))?
        .get_stub()?;
    Ok(DispatchResult::Handled(
        stub.fetch_with_request(normalized_request(&request, path)?)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uploads_offload_without_routing_downloads_or_metadata_through_heavy()
     {
        for (path, method) in [
            ("/api/ciphers/c/attachment", Method::Post),
            ("/api/ciphers/c/attachment/a", Method::Post),
            ("/api/ciphers/c/attachment/a/azure-upload", Method::Put),
            ("/api/sends/file", Method::Post),
            ("/api/sends/s/file/f", Method::Post),
            ("/api/sends/s/file/f/azure-upload", Method::Put),
        ] {
            assert!(heavy_route(path, &method), "{method} {path}");
        }
        assert!(!heavy_route("/api/ciphers/c/attachment/v2", &Method::Post));
        assert!(!heavy_route("/api/sends/file/v2", &Method::Post));
        assert!(!heavy_route(
            "/api/ciphers/c/attachment/a/download",
            &Method::Get
        ));
        assert!(!heavy_route("/api/sends/s/f", &Method::Get));
    }

    #[test]
    fn notifications_only_expose_public_hubs_and_negotiate() {
        for path in ["/notifications/hub", "/notifications/anonymous-hub"] {
            assert_eq!(
                notification_route(path, &Method::Get),
                NotificationRoute::Forward
            );
            assert_eq!(
                notification_route(path, &Method::Post),
                NotificationRoute::MethodNotAllowed
            );
            assert_eq!(
                notification_route(path, &Method::Options),
                NotificationRoute::Options
            );
        }
        for path in [
            "/notifications/hub/negotiate",
            "/notifications/anonymous-hub/negotiate",
        ] {
            assert_eq!(
                notification_route(path, &Method::Post),
                NotificationRoute::Forward
            );
            assert_eq!(
                notification_route(path, &Method::Get),
                NotificationRoute::MethodNotAllowed
            );
        }
        for path in [
            "/notifications/internal/fanout",
            "/notifications/internal/file-sync",
            "/notifications/unknown",
        ] {
            assert_eq!(
                notification_route(path, &Method::Post),
                NotificationRoute::NotFound
            );
            assert_eq!(
                notification_route(path, &Method::Options),
                NotificationRoute::NotFound
            );
        }
        assert_eq!(
            notification_route("/api/sync", &Method::Get),
            NotificationRoute::Pass
        );
        assert_eq!(
            normalized_path("/notifications/hub/negotiate///"),
            "/notifications/hub/negotiate"
        );
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
        assert!(heavy_route("/api/ciphers/import", &Method::Post));
        assert!(!heavy_route("/api/ciphers/import", &Method::Get));
        assert!(!heavy_route("/api/sync", &Method::Post));
        assert!(heavy_route("/api/accounts", &Method::Delete));
        for value in ["false", "0", " NO ", "off"] {
            assert!(!heavy_enabled(Some(value)));
        }
        assert!(heavy_enabled(None));
    }

    #[test]
    fn untrusted_subjects_only_choose_bounded_deterministic_shards() {
        for subject in ["alice", "bob", "arbitrary-third-party-subject", "用户"]
        {
            let payload = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({"sub":subject}))
                    .unwrap(),
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
                .unwrap(),
        );
        assert!(
            bearer_subject(Some(&format!(
                "Bearer header.{oversized}.signature"
            )))
            .is_none()
        );
        assert_eq!(shard_count(Some("2")), 2);
        for value in [None, Some("0"), Some("65"), Some("invalid")] {
            assert_eq!(shard_count(value), DEFAULT_SHARDS);
        }
    }

    #[test]
    fn bounded_reads_reject_invalid_or_oversized_lengths() {
        for value in [None, Some(""), Some("0"), Some("65536")] {
            assert!(small_content_length(value));
        }
        for value in [
            Some("65537"),
            Some("-1"),
            Some(" 1"),
            Some("1.5"),
            Some("not-a-number"),
        ] {
            assert!(!small_content_length(value));
        }
    }
}
