//! One CORS policy for Axum, preflight, dispatch errors and Durable Objects.
use axum::http::{HeaderValue, Method};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use worker::{Env, Request, Response};

use crate::{errors::AppResult, infra::config::cors_allowed_origins};

const ALL_METHODS: &str = "GET,HEAD,POST,PUT,DELETE,OPTIONS";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorsPolicy {
    Any,
    Origins(Vec<HeaderValue>),
}

impl CorsPolicy {
    pub fn from_env(env: &Env) -> Self {
        match cors_allowed_origins(env) {
            Ok(origins) => Self::parse(origins.as_deref()),
            Err(_) => Self::Origins(Vec::new()),
        }
    }

    fn parse(origins: Option<&str>) -> Self {
        let value = origins.unwrap_or("").trim();
        if value.is_empty() || value.split(',').any(|v| v.trim() == "*") {
            return Self::Any;
        }
        // An explicitly restrictive but invalid list remains deny-all.
        Self::Origins(value.split(',').filter_map(origin_header).collect())
    }

    fn origin<'a>(&self, origin: Option<&'a str>) -> Option<&'a str> {
        match self {
            Self::Any => Some("*"),
            Self::Origins(allowed) => {
                origin.filter(|value| allowed_origin(allowed, value.as_bytes()))
            }
        }
    }

    pub fn layer(&self) -> CorsLayer {
        let origins = match self {
            Self::Any => AllowOrigin::any(),
            Self::Origins(origins) => {
                let origins = origins.clone();
                AllowOrigin::predicate(move |origin, _| allowed_origin(&origins, origin.as_bytes()))
            }
        };
        // Clients authenticate explicitly with bearer tokens, without cookies.
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(AllowMethods::list([
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ]))
            .allow_headers(AllowHeaders::mirror_request())
    }
}

fn allowed_origin(origins: &[HeaderValue], value: &[u8]) -> bool {
    origins.iter().any(|entry| entry.as_bytes() == value)
}

fn origin_header(value: &str) -> Option<HeaderValue> {
    let value = value.trim();
    if value == "null" {
        return Some(HeaderValue::from_static("null"));
    }
    let url = url::Url::parse(value).ok()?;
    if !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    HeaderValue::from_str(url.as_str().trim_end_matches('/')).ok()
}

/// Capture CORS before moving the original streaming request. No D1 lookup.
pub(crate) struct CorsContext {
    policy: CorsPolicy,
    origin: Option<String>,
    requested_headers: Option<String>,
}

impl CorsContext {
    pub(crate) fn new(request: &Request, env: &Env) -> Self {
        Self {
            policy: CorsPolicy::from_env(env),
            origin: request.headers().get("Origin").ok().flatten(),
            requested_headers: request
                .headers()
                .get("Access-Control-Request-Headers")
                .ok()
                .flatten()
                .filter(|value| !value.is_empty()),
        }
    }

    pub(crate) const fn policy(&self) -> &CorsPolicy {
        &self.policy
    }

    pub(crate) fn apply(&self, response: Response) -> AppResult<Response> {
        self.apply_methods(response, ALL_METHODS)
    }

    pub(crate) fn apply_methods(&self, response: Response, methods: &str) -> AppResult<Response> {
        // Preserve the upgrade and its WebSocket without header reconstruction.
        if response.status_code() == 101 {
            return Ok(response);
        }
        let headers = response.headers().clone();
        headers.delete("Access-Control-Allow-Origin")?;
        headers.delete("Access-Control-Allow-Credentials")?;
        if let Some(origin) = self.policy.origin(self.origin.as_deref()) {
            headers.set("Access-Control-Allow-Origin", origin)?;
        }
        headers.append("Vary", "Origin")?;
        headers.set("Access-Control-Allow-Methods", methods)?;
        headers.set(
            "Access-Control-Allow-Headers",
            self.requested_headers
                .as_deref()
                .unwrap_or("authorization,content-type,device-type"),
        )?;
        Ok(response.with_headers(headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_cors_respects_configured_origins_without_a_database_lookup() {
        assert_eq!(
            CorsPolicy::parse(None).origin(Some("https://client.test")),
            Some("*")
        );
        assert_eq!(CorsPolicy::parse(None).origin(None), Some("*"));
        let policy = CorsPolicy::parse(Some(" https://other.test, https://client.test "));
        assert_eq!(
            policy.origin(Some("https://client.test")),
            Some("https://client.test")
        );
        assert_eq!(policy.origin(Some("https://denied.test")), None);
    }

    #[test]
    fn explicit_invalid_lists_never_become_unrestricted() {
        for value in [
            ",,,",
            "invalid",
            "https://host.test/path",
            "https://user:pass@host.test",
            "https://host.test?q=x",
            "https://host.test#x",
            "\r\ninvalid",
        ] {
            assert_eq!(
                CorsPolicy::parse(Some(value)),
                CorsPolicy::Origins(vec![]),
                "{value:?}"
            );
        }
    }

    #[test]
    fn empty_and_wildcard_lists_allow_any_origin() {
        for value in ["", " * ", "invalid,*"] {
            assert_eq!(CorsPolicy::parse(Some(value)), CorsPolicy::Any);
        }
    }

    #[test]
    fn lists_accept_real_extension_origins_and_normalize_web_origins() {
        let policy = CorsPolicy::parse(Some(
            "https://CLIENT.test/,moz-extension://1234,chrome-extension://abcd",
        ));
        for origin in [
            "https://client.test",
            "moz-extension://1234",
            "chrome-extension://abcd",
        ] {
            assert_eq!(policy.origin(Some(origin)), Some(origin));
        }
    }
}
