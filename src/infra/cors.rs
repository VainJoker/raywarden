//! One CORS policy for Axum, preflight, dispatch errors and Durable Objects.
use axum::http::{
    HeaderValue,
    Method,
};
use tower_http::cors::{
    AllowHeaders,
    AllowMethods,
    AllowOrigin,
    CorsLayer,
};
use worker::Env;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorsPolicy {
    Any,
    Origins(Vec<HeaderValue>),
}

impl CorsPolicy {
    pub fn from_env(env: &Env) -> Self {
        let primary =
            env.var("CORS_ALLOWED_ORIGINS").ok().map(|v| v.to_string());
        let legacy = env.var("ALLOWED_ORIGINS").ok().map(|v| v.to_string());
        Self::parse(primary.as_deref(), legacy.as_deref())
    }

    fn parse(primary: Option<&str>, legacy: Option<&str>) -> Self {
        let value = primary.or(legacy).unwrap_or("").trim();
        if value.is_empty() || value.split(',').any(|v| v.trim() == "*") {
            return Self::Any;
        }
        // An explicitly restrictive but invalid list remains deny-all.
        Self::Origins(value.split(',').filter_map(origin_header).collect())
    }

    pub(crate) fn origin(&self, origin: Option<&str>) -> Option<String> {
        match self {
            Self::Any => Some("*".into()),
            Self::Origins(allowed) => origin
                .filter(|value| {
                    allowed
                        .iter()
                        .any(|entry| entry.as_bytes() == value.as_bytes())
                })
                .map(str::to_owned),
        }
    }

    pub fn layer(&self) -> CorsLayer {
        let origins = match self {
            Self::Any => AllowOrigin::any(),
            Self::Origins(origins) => AllowOrigin::list(origins.clone()),
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

fn origin_header(value: &str) -> Option<HeaderValue> {
    let value = value.trim();
    if value == "null" {
        return Some(HeaderValue::from_static("null"));
    }
    let url = url::Url::parse(value).ok()?;
    if !url.has_host() ||
        !url.username().is_empty() ||
        url.password().is_some() ||
        !matches!(url.path(), "" | "/") ||
        url.query().is_some() ||
        url.fragment().is_some()
    {
        return None;
    }
    HeaderValue::from_str(url.as_str().trim_end_matches('/')).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_cors_respects_configured_origins_without_a_database_lookup() {
        assert_eq!(
            CorsPolicy::parse(None, None)
                .origin(Some("https://client.test"))
                .as_deref(),
            Some("*")
        );
        assert_eq!(
            CorsPolicy::parse(None, None).origin(None).as_deref(),
            Some("*")
        );
        let policy = CorsPolicy::parse(
            Some(" https://other.test, https://client.test "),
            None,
        );
        assert_eq!(
            policy.origin(Some("https://client.test")).as_deref(),
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
                CorsPolicy::parse(Some(value), Some("*")),
                CorsPolicy::Origins(vec![]),
                "{value:?}"
            );
        }
    }

    #[test]
    fn canonical_name_has_precedence_and_legacy_name_remains_supported() {
        let allowed = "https://client.test";
        assert_eq!(
            CorsPolicy::parse(None, Some(allowed))
                .origin(Some(allowed))
                .as_deref(),
            Some(allowed)
        );
        assert_eq!(CorsPolicy::parse(Some(""), Some(allowed)), CorsPolicy::Any);
        assert_eq!(CorsPolicy::parse(Some(" * "), None), CorsPolicy::Any);
        assert_eq!(CorsPolicy::parse(Some("invalid,*"), None), CorsPolicy::Any);
    }

    #[test]
    fn lists_accept_real_extension_origins_and_normalize_web_origins() {
        let policy = CorsPolicy::parse(Some("https://CLIENT.test/,moz-extension://1234,chrome-extension://abcd"), None);
        for origin in [
            "https://client.test",
            "moz-extension://1234",
            "chrome-extension://abcd",
        ] {
            assert_eq!(policy.origin(Some(origin)).as_deref(), Some(origin));
        }
    }
}
