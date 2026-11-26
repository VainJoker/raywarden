//! File download HTTP semantics shared by attachments and Send.
use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header, response::Builder},
    response::Response,
};

use super::response::set_native_stream;
use crate::{
    errors::{AppError, AppResult},
    infra::storage::{ObjectMetadata, Storage},
};

/// A single inclusive byte interval. Numeric values must remain exact when
/// passed to the Workers runtime's JavaScript APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    const fn length(self) -> u64 {
        self.end - self.start + 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InvalidRange;

fn invalid_range_response(size: u64) -> AppResult<Response> {
    download_builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::CONTENT_RANGE, format!("bytes */{size}"))
        .body(Body::empty())
        .map_err(|error| AppError::internal_debug("Failed to build range response", error))
}

const MAX_SAFE_JS_INTEGER: u64 = (1 << 53) - 1;

fn parse_byte_range(value: Option<&str>, size: u64) -> Result<Option<ByteRange>, InvalidRange> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let spec = value.trim().strip_prefix("bytes=").ok_or(InvalidRange)?;
    let (start, end) = spec.split_once('-').ok_or(InvalidRange)?;
    if size == 0 || size > MAX_SAFE_JS_INTEGER {
        return Err(InvalidRange);
    }
    let number = |text: &str| -> Result<u64, InvalidRange> {
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(InvalidRange);
        }
        text.parse::<u64>()
            .ok()
            .filter(|value| *value <= MAX_SAFE_JS_INTEGER)
            .ok_or(InvalidRange)
    };
    let range = if start.is_empty() {
        let suffix = number(end)?;
        if suffix == 0 {
            return Err(InvalidRange);
        }
        ByteRange {
            start: size.saturating_sub(suffix),
            end: size - 1,
        }
    } else {
        let start = number(start)?;
        let end = if end.is_empty() {
            size - 1
        } else {
            number(end)?
        };
        if start >= size || start > end {
            return Err(InvalidRange);
        }
        ByteRange {
            start,
            end: end.min(size - 1),
        }
    };
    Ok(Some(range))
}

const DOWNLOAD_CSP: &str = "default-src 'none'; sandbox";

/// Apply HTTP validators and response policy without consuming R2 streams on
/// HEAD or invalid ranges.
pub async fn download(
    storage: &Storage,
    key: &str,
    headers: &HeaderMap,
    head: bool,
) -> AppResult<Response> {
    let file = storage
        .open(key)
        .await?
        .ok_or_else(|| AppError::not_found("File"))?;
    let range = match selected_range(headers, &file.metadata) {
        Ok(range) => range,
        Err(InvalidRange) => return invalid_range_response(file.metadata.size_bytes),
    };
    let mut response = download_response(&file.metadata, range)?;
    if !head {
        let interval = range.map(|range| range.start..=range.end);
        let stream = file
            .read(interval)
            .await?
            .ok_or_else(|| AppError::not_found("File"))?;
        set_native_stream(&mut response, stream);
    }
    Ok(response)
}

fn selected_range(
    headers: &HeaderMap,
    object: &ObjectMetadata,
) -> Result<Option<ByteRange>, InvalidRange> {
    if let Some(condition) = headers.get(header::IF_RANGE)
        && condition.as_bytes() != object.http_etag.as_bytes()
    {
        return Ok(None);
    }
    let value = headers
        .get(header::RANGE)
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_error| InvalidRange)?;
    parse_byte_range(value, object.size_bytes)
}

fn download_response(object: &ObjectMetadata, range: Option<ByteRange>) -> AppResult<Response> {
    let mut builder = download_builder()
        .status(if range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(header::ETAG, &object.http_etag)
        .header(
            header::CONTENT_LENGTH,
            range.map_or(object.size_bytes, ByteRange::length),
        );
    if let Some(range) = range {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", range.start, range.end, object.size_bytes),
        );
    }
    builder
        .body(Body::empty())
        .map_err(|error| AppError::internal_debug("Failed to build download response", error))
}

fn download_builder() -> Builder {
    // Stored MIME metadata predates this policy and remains untrusted. Apply
    // the same inert attachment policy to every backend and byte range without
    // changing ciphertext or routing native R2 streams through a body adapter.
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, "attachment")
        .header(header::CONTENT_SECURITY_POLICY, DOWNLOAD_CSP)
        .header(header::CACHE_CONTROL, "private, no-store")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::ACCEPT_RANGES, "bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_ranges_if_range_and_sandbox_headers_follow_rfc9110() {
        let object = ObjectMetadata {
            size_bytes: 10,
            http_etag: "\"etag\"".into(),
        };
        for (hdr, start, end) in [
            ("bytes=1-3", 1, 3),
            ("bytes=5-", 5, 9),
            ("bytes=-3", 7, 9),
            ("bytes=0-999", 0, 9),
        ] {
            assert_eq!(
                parse_byte_range(Some(hdr), 10),
                Ok(Some(ByteRange { start, end }))
            );
        }
        for bad in [
            "bytes=",
            "bytes=-0",
            "bytes=10-",
            "bytes=5-3",
            "bytes=0-1,3-4",
            "items=0-1",
        ] {
            assert!(parse_byte_range(Some(bad), 10).is_err(), "{bad}");
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=2-5".parse().expect("range"));
        headers.insert(header::IF_RANGE, "\"other\"".parse().expect("if-range"));
        assert_eq!(selected_range(&headers, &object), Ok(None));
        headers.insert(header::IF_RANGE, "\"etag\"".parse().expect("if-range"));
        assert_eq!(
            selected_range(&headers, &object),
            Ok(Some(ByteRange { start: 2, end: 5 }))
        );

        let resp = download_response(&object, Some(ByteRange { start: 2, end: 5 })).expect("resp");
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()[header::CONTENT_SECURITY_POLICY],
            DOWNLOAD_CSP
        );
        assert_eq!(resp.headers()[header::CONTENT_DISPOSITION], "attachment");
    }
}
