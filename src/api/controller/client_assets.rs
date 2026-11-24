use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use futures_util::StreamExt as _;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    api::common::response::ApiResponse,
    errors::AppResult,
    infra::config::{env_bool, registration_disabled},
    service::web_vault_ui,
};

const MAX_ICON_BYTES: usize = 5 * 1024 * 1024;

#[worker::send]
pub(in crate::api) async fn icon(
    State(env): State<worker::Env>,
    Path(path): Path<String>,
) -> AppResult<Response> {
    let domain = path.strip_suffix("/icon.png").unwrap_or(&path);
    if !is_valid_icon_domain(domain) || env_bool(&env, "DISABLE_ICON_DOWNLOAD", false) {
        return Ok(icon_not_found());
    }
    let Some((kind, bytes)) = fetch_icon(domain).await? else {
        return Ok(icon_not_found());
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, kind.as_str()),
            (header::CACHE_CONTROL, "public, max-age=604800, immutable"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    )
        .into_response())
}

async fn fetch_icon(domain: &str) -> AppResult<Option<(String, Vec<u8>)>> {
    let url = format!("https://vault.bitwarden.com/icons/{domain}/icon.png");
    let request = worker::Request::new(&url, worker::Method::Get)?;
    let mut upstream = worker::Fetch::Request(request).send().await?;
    if upstream.status_code() != 200 {
        return Ok(None);
    }
    let kind = upstream.headers().get("content-type")?.unwrap_or_default();
    if !is_valid_icon_content_type(&kind)
        || upstream
            .headers()
            .get("content-length")?
            .and_then(|value| value.trim().parse::<usize>().ok())
            .is_some_and(|length| length > MAX_ICON_BYTES)
    {
        return Ok(None);
    }
    Ok(collect_icon_body(upstream.stream()?)
        .await?
        .map(|bytes| (kind, bytes)))
}

fn icon_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Body::empty(),
    )
        .into_response()
}

fn is_valid_icon_content_type(value: &str) -> bool {
    let kind = value.split_once(';').map_or(value, |(kind, _)| kind).trim();
    [
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/bmp",
        "image/avif",
        "image/x-icon",
        "image/vnd.microsoft.icon",
    ]
    .iter()
    .any(|allowed| kind.eq_ignore_ascii_case(allowed))
}

async fn collect_icon_body(
    stream: impl futures_util::Stream<Item = worker::Result<Vec<u8>>>,
) -> worker::Result<Option<Vec<u8>>> {
    futures_util::pin_mut!(stream);
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > MAX_ICON_BYTES - bytes.len() {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(bytes))
}

fn is_valid_icon_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[worker::send]
pub(in crate::api) async fn stylesheet(
    State(env): State<worker::Env>,
    headers: HeaderMap,
) -> Response {
    let css = web_vault_ui::stylesheet(&env, registration_disabled(&env));
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(css.as_bytes())));
    let mut response = if matches_etag(&headers, &etag) {
        (StatusCode::NOT_MODIFIED, Body::empty()).into_response()
    } else {
        ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], css).into_response()
    };
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, no-cache"),
    );
    response
}

fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|tag| {
            let tag = tag.trim();
            tag == "*" || tag.trim_start_matches("W/") == etag
        })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use futures_util::{FutureExt as _, StreamExt as _, stream};

    use super::{
        MAX_ICON_BYTES, collect_icon_body, is_valid_icon_content_type, is_valid_icon_domain,
    };
    #[test]
    fn icons_cannot_escape_the_fixed_upstream_path() {
        assert!(is_valid_icon_domain("vault.example.com"));
        for bad in [
            "",
            "../admin",
            "example.com?token=x",
            "a%2fb",
            "a@b",
            "-a.test",
        ] {
            assert!(!is_valid_icon_domain(bad));
        }
    }

    #[test]
    fn icons_only_accept_known_raster_content_types() {
        for value in [
            "image/png",
            "IMAGE/JPEG; charset=binary",
            " image/webp ",
            "image/x-icon",
        ] {
            assert!(is_valid_icon_content_type(value));
        }
        for value in [
            "",
            "image/svg+xml",
            "image/unknown",
            "text/html",
            "application/octet-stream",
        ] {
            assert!(!is_valid_icon_content_type(value));
        }
    }

    #[test]
    fn icon_reads_accept_the_limit_and_stop_on_the_first_excess_chunk() {
        let exact = stream::iter([Ok(vec![0; MAX_ICON_BYTES - 1]), Ok(vec![1])]);
        assert_eq!(
            collect_icon_body(exact)
                .now_or_never()
                .expect("valid presentation fixture")
                .expect("valid presentation fixture")
                .expect("valid presentation fixture")
                .len(),
            MAX_ICON_BYTES
        );
        let reads = Cell::new(0);
        let excess = stream::iter([Ok(vec![0; MAX_ICON_BYTES]), Ok(vec![1]), Ok(vec![2])])
            .inspect(|_| reads.set(reads.get() + 1));
        assert!(
            collect_icon_body(excess)
                .now_or_never()
                .expect("valid presentation fixture")
                .expect("valid presentation fixture")
                .is_none()
        );
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn interrupted_icon_reads_never_publish_partial_content() {
        let interrupted = stream::iter([
            Ok(vec![0]),
            Err(worker::Error::RustError("interrupted".into())),
        ]);
        assert!(
            collect_icon_body(interrupted)
                .now_or_never()
                .expect("valid presentation fixture")
                .is_err()
        );
    }
}

#[worker::send]
pub(in crate::api) async fn client_script() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, no-cache"),
        ],
        include_str!("../../../static/overrides/raywarden.js"),
    )
        .into_response()
}

#[worker::send]
pub(in crate::api) async fn demo_page(State(env): State<worker::Env>) -> Response {
    let mut response = if env_bool(&env, "DEMO_PAGE_ENABLED", false) {
        Html(include_str!("../../../static/demo.html")).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src \
             'self' 'unsafe-inline'; img-src 'self' data:; connect-src \
             'self'; frame-ancestors 'self'; form-action 'self'; base-uri \
             'self'; object-src 'none'",
        ),
    );
    response
}

#[derive(Serialize)]
pub(in crate::api) struct AppleAppSiteAssociation {
    webcredentials: AppleWebCredentials,
}

#[derive(Serialize)]
struct AppleWebCredentials {
    apps: [&'static str; 2],
}

#[worker::send]
pub(in crate::api) async fn apple_app_site_association() -> ApiResponse<AppleAppSiteAssociation> {
    ApiResponse(AppleAppSiteAssociation {
        webcredentials: AppleWebCredentials {
            apps: [
                "LTZ2PFU5D6.com.8bit.bitwarden",
                "LTZ2PFU5D6.com.8bit.bitwarden.beta",
            ],
        },
    })
}
