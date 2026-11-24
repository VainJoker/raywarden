//! File download HTTP semantics shared by attachments and Send.
use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header, response::Builder},
    response::Response,
};

use super::response::set_native_stream;
use crate::{
    errors::{AppError, AppResult},
    infra::storage::{ObjectBody, ObjectMetadata, Storage},
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
struct InvalidRange(u64);

impl InvalidRange {
    fn into_response(self, builder: Builder) -> AppResult<Response> {
        let Self(size) = self;
        builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{size}"))
            .body(Body::empty())
            .map_err(AppError::internal_error)
    }
}

const MAX_SAFE_JS_INTEGER: u64 = (1 << 53) - 1;

fn parse_byte_range(value: Option<&str>, size: u64) -> Result<Option<ByteRange>, InvalidRange> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let invalid = InvalidRange(size);
    let spec = value.trim().strip_prefix("bytes=").ok_or(invalid)?;
    let (start, end) = spec.split_once('-').ok_or(invalid)?;
    if size == 0 || size > MAX_SAFE_JS_INTEGER {
        return Err(invalid);
    }
    let number = |text: &str| -> Result<u64, InvalidRange> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid);
        }
        text.parse::<u64>()
            .ok()
            .filter(|value| *value <= MAX_SAFE_JS_INTEGER)
            .ok_or(invalid)
    };
    let range = if start.is_empty() {
        let suffix = number(end)?;
        if suffix == 0 {
            return Err(invalid);
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
            return Err(invalid);
        }
        ByteRange {
            start,
            end: end.min(size - 1),
        }
    };
    Ok(Some(range))
}

const DOWNLOAD_CSP: &str = "default-src 'none'; sandbox";

/// Apply HTTP validators and response policy without consuming R2 streams or
/// reading a KV object twice. HEAD and invalid ranges never read an R2 body.
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
        Err(error) => return error.into_response(download_builder()),
    };
    let mut response = download_response(&file.metadata, range)?;
    if !head {
        let interval = range.map(|range| range.start..=range.end);
        match file
            .read(interval)
            .await?
            .ok_or_else(|| AppError::not_found("File"))?
        {
            ObjectBody::Stream(stream) => {
                set_native_stream(&mut response, stream);
            }
            ObjectBody::Bytes(bytes) => {
                *response.body_mut() = Body::from(bytes);
            }
        }
    }
    Ok(response)
}

fn selected_range(
    headers: &HeaderMap,
    object: &ObjectMetadata,
) -> Result<Option<ByteRange>, InvalidRange> {
    if let Some(condition) = headers.get(header::IF_RANGE)
        && object
            .http_etag
            .as_ref()
            .is_none_or(|etag| condition.as_bytes() != etag.as_bytes())
    {
        return Ok(None);
    }
    let value = headers
        .get(header::RANGE)
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_error| InvalidRange(object.size_bytes))?;
    parse_byte_range(value, object.size_bytes)
}

fn download_response(object: &ObjectMetadata, range: Option<ByteRange>) -> AppResult<Response> {
    let mut builder = download_builder()
        .status(if range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
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
    if let Some(etag) = &object.http_etag {
        builder = builder.header(header::ETAG, etag);
    }
    builder
        .body(Body::empty())
        .map_err(AppError::internal_error)
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
    fn range_validators_choose_full_or_partial_download_without_touching_storage() {
        let object = ObjectMetadata {
            size_bytes: 10,
            http_etag: Some("\"etag\"".into()),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::RANGE,
            "bytes=2-5".parse().expect("test fixture should be valid"),
        );
        assert_eq!(
            selected_range(&headers, &object).expect("test fixture should be valid"),
            Some(ByteRange { start: 2, end: 5 })
        );
        headers.insert(
            header::IF_RANGE,
            "\"other\"".parse().expect("test fixture should be valid"),
        );
        assert_eq!(
            selected_range(&headers, &object).expect("test fixture should be valid"),
            None
        );
        headers.insert(
            header::IF_RANGE,
            "\"etag\"".parse().expect("test fixture should be valid"),
        );
        assert_eq!(
            selected_range(&headers, &object).expect("test fixture should be valid"),
            Some(ByteRange { start: 2, end: 5 })
        );
        headers.insert(
            header::RANGE,
            "bytes=10-".parse().expect("test fixture should be valid"),
        );
        let response = selected_range(&headers, &object)
            .expect_err("range starts beyond the end of the file")
            .into_response(download_builder())
            .expect("test fixture should be valid");
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes */10");
    }

    #[test]
    fn response_headers_preserve_range_size_and_etag_with_inert_download_policy() {
        let object = ObjectMetadata {
            size_bytes: 10,
            http_etag: Some("\"etag\"".into()),
        };
        let response = download_response(&object, Some(ByteRange { start: 2, end: 5 }))
            .expect("test fixture should be valid");
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
        assert_download_policy(&response);
        assert_eq!(response.headers()[header::ETAG], "\"etag\"");
    }

    fn assert_download_policy(response: &Response) {
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment"
        );
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            DOWNLOAD_CSP
        );
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
    }

    #[test]
    fn full_partial_and_invalid_range_downloads_keep_sandbox_after_defaults() {
        let object = ObjectMetadata {
            size_bytes: 10,
            http_etag: None,
        };
        for range in [None, Some(ByteRange { start: 2, end: 5 })] {
            let mut response =
                download_response(&object, range).expect("test fixture should be valid");
            crate::api::middleware::headers::apply_http(
                "/api/ciphers/cipher/attachment/file/download",
                &mut response,
            );
            assert_download_policy(&response);
        }
        let mut response = InvalidRange(10)
            .into_response(download_builder())
            .expect("test fixture should be valid");
        crate::api::middleware::headers::apply_http(
            "/api/ciphers/cipher/attachment/file/download",
            &mut response,
        );
        assert_download_policy(&response);
    }
}

#[cfg(test)]
mod range_tests {
    use super::*;

    #[test]
    fn single_ranges_preserve_closed_open_suffix_and_clamping() {
        for (header, start, end) in [
            ("bytes=1-3", 1, 3),
            ("bytes=5-", 5, 9),
            ("bytes=-3", 7, 9),
            ("bytes=0-999", 0, 9),
            ("bytes=-99", 0, 9),
        ] {
            let range = parse_byte_range(Some(header), 10)
                .expect("test fixture should be valid")
                .expect("test fixture should be valid");
            assert_eq!(range, ByteRange { start, end });
            assert_eq!(range.length(), end - start + 1);
        }
        assert_eq!(parse_byte_range(None, 0), Ok(None));
    }

    #[test]
    fn malformed_multiple_unsafe_and_unsatisfiable_ranges_fail() {
        for header in [
            "bytes=",
            "bytes=-0",
            "bytes=10-",
            "bytes=5-3",
            "bytes=0-1,3-4",
            "bytes=0-9007199254740992",
            "bytes=1-x",
            "bytes=+1-3",
            "items=0-1",
            "bytes=0--1",
        ] {
            assert!(parse_byte_range(Some(header), 10).is_err(), "{header}");
        }
        assert!(parse_byte_range(Some("bytes=0-"), 0).is_err());
    }
}
