//! Shared defaults for Worker responses and the generated static `_headers`.
//! Explicit handler policies (Turnstile, setup, downloads, CSS validators) win.
use std::{collections::BTreeMap, sync::OnceLock};

use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use serde::{Deserialize, Deserializer, de::Error as _};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityHeaders {
    common: HeaderGroup,
    document: HeaderGroup,
    image: HeaderGroup,
    api: HeaderGroup,
    #[serde(deserialize_with = "parse_cache_header")]
    dynamic_cache: (HeaderName, HeaderValue),
}

#[derive(Deserialize)]
#[serde(transparent)]
struct HeaderGroup(#[serde(deserialize_with = "parse_headers")] Vec<(HeaderName, HeaderValue)>);

fn parse_headers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<(HeaderName, HeaderValue)>, D::Error> {
    BTreeMap::<String, String>::deserialize(deserializer)?
        .into_iter()
        .map(|(name, value)| {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(D::Error::custom)?;
            let value = HeaderValue::from_str(&value).map_err(D::Error::custom)?;
            Ok((name, value))
        })
        .collect()
}

fn parse_cache_header<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<(HeaderName, HeaderValue), D::Error> {
    let value = String::deserialize(deserializer)?;
    HeaderValue::from_str(&value)
        .map(|value| (header::CACHE_CONTROL, value))
        .map_err(D::Error::custom)
}

fn policy() -> &'static SecurityHeaders {
    static POLICY: OnceLock<SecurityHeaders> = OnceLock::new();
    POLICY.get_or_init(|| {
        serde_json::from_str(include_str!("../../../static/security-headers.json"))
            .expect("compiled security headers must be valid")
    })
}

fn is_connector(path: &str) -> bool {
    path.trim_end_matches('/').ends_with("connector.html")
}

fn defaults(
    connector: bool,
    content_type: &str,
) -> impl Iterator<Item = &'static (HeaderName, HeaderValue)> + use<> {
    let policy = policy();
    let specific = if connector {
        None
    } else if content_type.starts_with("image/") {
        Some(&policy.image)
    } else if content_type.starts_with("text/html") {
        Some(&policy.document)
    } else {
        Some(&policy.api)
    };
    policy
        .common
        .0
        .iter()
        .chain(specific.into_iter().flat_map(|group| &group.0))
        .chain(std::iter::once(&policy.dynamic_cache))
}

/// Also runs in `heavydo` before converting the native streaming response.
pub(crate) fn apply_http(path: &str, response: &mut axum::response::Response) {
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return;
    }
    let connector = is_connector(path);
    let headers = response.headers_mut();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    for (name, value) in defaults(connector, content_type) {
        headers.entry(name).or_insert_with(|| value.clone());
    }
    if connector {
        headers.remove(header::CONTENT_SECURITY_POLICY);
        headers.remove(header::X_FRAME_OPTIONS);
    }
}

/// Covers dispatch failures, DO responses and initialization failures outside
/// Axum. Reuses the original body/stream; never reconstructs an upgrade.
pub(crate) fn apply_worker(
    path: &str,
    response: worker::Response,
) -> worker::Result<worker::Response> {
    if response.status_code() == 101 {
        return Ok(response);
    }
    let connector = is_connector(path);
    let content_type = response.headers().get("Content-Type")?.unwrap_or_default();
    let headers = response.headers().clone();
    for (name, value) in defaults(connector, &content_type) {
        if !headers.has(name.as_str())? {
            let value = value.to_str().expect("compiled header value must be ASCII");
            headers.set(name.as_str(), value)?;
        }
    }
    if connector {
        headers.delete("Content-Security-Policy")?;
        headers.delete("X-Frame-Options")?;
    }
    Ok(response.with_headers(headers))
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, response::Response};

    use super::*;

    #[test]
    fn images_are_inert_without_corp_and_connectors_remain_embeddable() {
        let mut image = Response::builder()
            .header(header::CONTENT_TYPE, "image/svg+xml")
            .body(Body::empty())
            .expect("test fixture should be valid");
        apply_http("/icons/example.test/icon.png", &mut image);
        assert!(
            image.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .expect("test fixture should be valid")
                .contains("script-src 'none'")
        );
        assert!(!image.headers().contains_key("cross-origin-resource-policy"));
        let mut page = Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::empty())
            .expect("test fixture should be valid");
        apply_http("/webauthn-connector.html", &mut page);
        assert!(!page.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        assert!(!page.headers().contains_key(header::X_FRAME_OPTIONS));
        assert_eq!(page.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    #[test]
    fn upgrade_is_not_modified() {
        let mut response = Response::builder()
            .status(101)
            .header("upgrade", "websocket")
            .body(Body::empty())
            .expect("test fixture should be valid");
        let before = response.headers().clone();
        apply_http("/notifications/hub", &mut response);
        assert_eq!(response.headers(), &before);
    }
}
