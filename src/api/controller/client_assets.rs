use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    api::common::{extract::Path, response::ApiResponse},
    errors::AppResult,
    infra::config::{env_bool, registration_disabled},
    service::web_vault_ui,
    utils::collect_bounded,
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
    Ok(collect_bounded(upstream.stream()?, MAX_ICON_BYTES)
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
    use futures_util::{FutureExt as _, stream};

    use super::{
        MAX_ICON_BYTES, collect_bounded, is_valid_icon_content_type, is_valid_icon_domain,
    };

    #[test]
    fn icons_validate_domain_mime_and_bounded_reads() {
        assert!(is_valid_icon_domain("vault.example.com"));
        for bad in ["", "../admin", "example.com?x=1", "a%2fb", "-a.test"] {
            assert!(!is_valid_icon_domain(bad));
        }
        assert!(is_valid_icon_content_type("IMAGE/JPEG; charset=binary"));
        assert!(!is_valid_icon_content_type("image/svg+xml"));

        let excess = stream::iter([Ok::<_, ()>(vec![0; MAX_ICON_BYTES]), Ok(vec![1])]);
        assert!(
            collect_bounded(excess, MAX_ICON_BYTES)
                .now_or_never()
                .expect("ready")
                .expect("ok")
                .is_none()
        );
        let interrupted = stream::iter([Ok(vec![0]), Err(worker::Error::RustError("err".into()))]);
        assert!(
            collect_bounded(interrupted, MAX_ICON_BYTES)
                .now_or_never()
                .expect("ready")
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
pub(in crate::api) async fn apple_app_site_association() -> ApiResponse<Value> {
    ApiResponse(json!({
        "webcredentials": {
            "apps": [
                "LTZ2PFU5D6.com.8bit.bitwarden",
                "LTZ2PFU5D6.com.8bit.bitwarden.beta",
            ],
        },
    }))
}
