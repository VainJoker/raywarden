pub mod cleanup;
pub mod range;

use std::fmt::Display;

use axum::{
    body::{
        Body,
        Bytes,
    },
    http::{
        HeaderMap,
        StatusCode,
        header,
    },
    response::Response,
};
use futures_util::{
    Stream,
    StreamExt,
};
use serde_json::{
    Value,
    json,
};
use worker::{
    Bucket,
    Env,
    HttpMetadata,
    MultipartUpload,
    Range,
};

#[derive(Clone)]
struct NativeStream(worker::send::SendWrapper<web_sys::ReadableStream>);

/// Keep native download streams outside `http_body`'s per-chunk WASM adapter.
/// Axum still applies headers and CORS before this final response conversion.
pub fn into_worker_response(
    mut response: Response,
) -> worker::Result<worker::Response> {
    if let Some(NativeStream(stream)) =
        response.extensions_mut().remove::<NativeStream>()
    {
        let headers = worker::Headers::new();
        for (name, value) in response.headers() {
            headers.append(
                name.as_str(),
                value.to_str().map_err(|error| {
                    worker::Error::RustError(error.to_string())
                })?,
            )?;
        }
        Ok(
            worker::Response::from_body(worker::ResponseBody::Stream(
                stream.0,
            ))?
            .with_status(response.status().as_u16())
            .with_headers(headers),
        )
    } else {
        response.try_into()
    }
}

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::storage::range::{
        ByteRange,
        InvalidRange,
        parse_byte_range,
    },
};

pub const KV_MAX_BYTES: usize = 25 * 1024 * 1024;
const PART_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct StoredObject {
    pub size:         u64,
    pub content_type: Option<String>,
    pub http_etag:    Option<String>,
}

/// R2 streams are preferred. KV keeps the existing raw-byte object format and
/// is buffered only within its 25 MiB backend limit.
#[derive(Clone)]
pub struct Storage {
    env: Env,
}

fn kv_error(error: impl Display) -> AppError {
    AppError::Worker(worker::Error::RustError(format!(
        "KV operation failed: {error}"
    )))
}

fn next_size(current: u64, chunk: usize, maximum: u64) -> AppResult<u64> {
    current
        .checked_add(chunk as u64)
        .filter(|size| *size <= maximum)
        .ok_or_else(|| AppError::bad_request("File size exceeds limit"))
}

fn metadata(content_type: Option<&str>) -> HttpMetadata {
    HttpMetadata {
        content_type: content_type.map(str::to_owned),
        ..Default::default()
    }
}

fn selected_range(
    headers: &HeaderMap,
    object: &StoredObject,
) -> Result<Option<ByteRange>, InvalidRange> {
    if let Some(condition) = headers.get(header::IF_RANGE) &&
        object
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
        .map_err(|_| InvalidRange)?;
    parse_byte_range(value, object.size)
}

fn download_response(
    object: &StoredObject,
    range: Option<ByteRange>,
    body: Body,
) -> AppResult<Response> {
    let mut builder = Response::builder()
        .status(if range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(header::ACCEPT_RANGES, "bytes")
        .header(
            header::CONTENT_TYPE,
            object
                .content_type
                .as_deref()
                .unwrap_or("application/octet-stream"),
        )
        .header(
            header::CONTENT_LENGTH,
            range.map_or(object.size, ByteRange::length),
        )
        .header(header::CACHE_CONTROL, "private, no-store")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    if let Some(range) = range {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", range.start, range.end, object.size),
        );
    }
    if let Some(etag) = &object.http_etag {
        builder = builder.header(header::ETAG, etag);
    }
    builder.body(body).map_err(|_error| AppError::Internal)
}

fn invalid_range_response(size: u64) -> AppResult<Response> {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::CONTENT_RANGE, format!("bytes */{size}"))
        .header(header::ACCEPT_RANGES, "bytes")
        .body(Body::empty())
        .map_err(|_error| AppError::Internal)
}

impl Storage {
    pub fn enabled(env: &Env) -> bool {
        env.bucket("ATTACHMENTS_BUCKET").is_ok() ||
            env.kv("ATTACHMENTS_KV").is_ok()
    }

    pub fn from_env(env: &Env) -> AppResult<Self> {
        if !Self::enabled(env) {
            return Err(AppError::bad_request("File storage is not enabled"));
        }
        Ok(Self { env: env.clone() })
    }

    fn r2(&self) -> Option<Bucket> {
        self.env.bucket("ATTACHMENTS_BUCKET").ok()
    }

    pub fn max_bytes(env: &Env) -> Option<usize> {
        if env.bucket("ATTACHMENTS_BUCKET").is_ok() {
            None
        } else {
            Some(KV_MAX_BYTES)
        }
    }

    /// Accept borrowed multipart fields as well as request bodies. No full-file
    /// collection occurs for R2: only the current incoming chunk and an 8 MiB
    /// part are retained. Errors abort an unfinished multipart upload.
    pub async fn put_stream<S, E>(
        &self,
        key: &str,
        stream: S,
        max_bytes: u64,
        content_type: Option<&str>,
    ) -> AppResult<u64>
    where
        S: Stream<Item = Result<Bytes, E>>,
        E: Display,
    {
        let Some(bucket) = self.r2() else {
            return self
                .put_kv_stream(key, stream, max_bytes, content_type)
                .await;
        };
        futures_util::pin_mut!(stream);

        let mut upload: Option<MultipartUpload> = None;
        let result = async {
            let mut size = 0;
            let mut part = Vec::with_capacity(PART_BYTES);
            let mut uploaded = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| {
                    AppError::bad_request(format!(
                        "Upload stream failed: {error}"
                    ))
                })?;
                size = next_size(size, chunk.len(), max_bytes)?;
                let mut remaining = chunk.as_ref();
                while !remaining.is_empty() {
                    let count = remaining.len().min(PART_BYTES - part.len());
                    part.extend_from_slice(&remaining[..count]);
                    remaining = &remaining[count..];
                    if part.len() == PART_BYTES {
                        if upload.is_none() {
                            upload = Some(
                                bucket
                                    .create_multipart_upload(key)
                                    .http_metadata(metadata(content_type))
                                    .execute()
                                    .await?,
                            );
                        }
                        let number = u16::try_from(uploaded.len() + 1)
                            .map_err(|_error| {
                                AppError::bad_request("Too many upload parts")
                            })?;
                        if number > 10_000 {
                            return Err(AppError::bad_request(
                                "Too many upload parts",
                            ));
                        }
                        let bytes = std::mem::replace(
                            &mut part,
                            Vec::with_capacity(PART_BYTES),
                        );
                        uploaded.push(
                            upload
                                .as_ref()
                                .ok_or(AppError::Internal)?
                                .upload_part(number, bytes)
                                .await?,
                        );
                    }
                }
            }
            if let Some(upload) = &upload {
                if !part.is_empty() {
                    let number = u16::try_from(uploaded.len() + 1).map_err(
                        |_error| AppError::bad_request("Too many upload parts"),
                    )?;
                    if number > 10_000 {
                        return Err(AppError::bad_request(
                            "Too many upload parts",
                        ));
                    }
                    uploaded.push(upload.upload_part(number, part).await?);
                }
                // Completing a resumed handle preserves the original handle so
                // any failed completion can still be aborted below.
                let id = upload.upload_id().await;
                bucket
                    .resume_multipart_upload(key, &id)?
                    .complete(uploaded)
                    .await?;
            } else {
                bucket
                    .put(key, part)
                    .http_metadata(metadata(content_type))
                    .execute()
                    .await?;
            }
            Ok(size)
        }
        .await;
        if result.is_err() &&
            let Some(upload) = upload &&
            let Err(error) = upload.abort().await
        {
            log::warn!("Failed to abort file upload: {error}");
        }
        result
    }

    async fn put_kv_stream<S, E>(
        &self,
        key: &str,
        stream: S,
        max_bytes: u64,
        content_type: Option<&str>,
    ) -> AppResult<u64>
    where
        S: Stream<Item = Result<Bytes, E>>,
        E: Display,
    {
        futures_util::pin_mut!(stream);
        let maximum = max_bytes.min(KV_MAX_BYTES as u64);
        let mut data = Vec::new();
        let mut size = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                AppError::bad_request(format!("Upload stream failed: {error}"))
            })?;
            size = next_size(size, chunk.len(), maximum)?;
            data.extend_from_slice(&chunk);
        }
        self.env.kv("ATTACHMENTS_KV")?.put_bytes(key, &data).map_err(kv_error)?
            .metadata(json!({"size":size,"httpMetadata":{"contentType":content_type}})).map_err(kv_error)?
            .execute().await.map_err(kv_error)?;
        Ok(size)
    }

    pub async fn head(&self, key: &str) -> AppResult<Option<StoredObject>> {
        if let Some(bucket) = self.r2() {
            return Ok(bucket.head(key).await?.map(|object| StoredObject {
                size:         object.size(),
                content_type: object.http_metadata().content_type,
                http_etag:    Some(object.http_etag()),
            }));
        }
        let (bytes, metadata) = self
            .env
            .kv("ATTACHMENTS_KV")?
            .get(key)
            .bytes_with_metadata::<Value>()
            .await
            .map_err(kv_error)?;
        Ok(bytes.map(|bytes| StoredObject {
            size:         bytes.len() as u64,
            content_type: metadata
                .as_ref()
                .and_then(|value| {
                    value.get("httpMetadata")?.get("contentType")?.as_str()
                })
                .map(str::to_owned),
            http_etag:    None,
        }))
    }

    /// Return the native R2 `ReadableStream` without routing every download
    /// chunk through Rust/WASM. KV alone uses its bounded in-memory byte
    /// buffer.
    pub async fn download(
        &self,
        key: &str,
        headers: &HeaderMap,
        head: bool,
    ) -> AppResult<Response> {
        if let Some(bucket) = self.r2() {
            let object = bucket
                .head(key)
                .await?
                .ok_or_else(|| AppError::not_found("File"))?;
            let metadata = StoredObject {
                size:         object.size(),
                content_type: object.http_metadata().content_type,
                http_etag:    Some(object.http_etag()),
            };
            let range = match selected_range(headers, &metadata) {
                Ok(range) => range,
                Err(InvalidRange) => {
                    return invalid_range_response(metadata.size);
                }
            };
            let mut response =
                download_response(&metadata, range, Body::empty())?;
            if !head {
                let get = bucket.get(key);
                let get = if let Some(range) = range {
                    get.range(Range::OffsetWithLength {
                        offset: range.start,
                        length: range.length(),
                    })
                } else {
                    get
                };
                let object = get
                    .execute()
                    .await?
                    .ok_or_else(|| AppError::not_found("File"))?;
                let worker::ResponseBody::Stream(stream) =
                    object.body().ok_or(AppError::Internal)?.response_body()?
                else {
                    return Err(AppError::Internal);
                };
                response.extensions_mut().insert(NativeStream(
                    worker::send::SendWrapper::new(stream),
                ));
            }
            return Ok(response);
        }
        let (bytes, metadata) = self
            .env
            .kv("ATTACHMENTS_KV")?
            .get(key)
            .bytes_with_metadata::<Value>()
            .await
            .map_err(kv_error)?;
        let bytes = bytes.ok_or_else(|| AppError::not_found("File"))?;
        let object = StoredObject {
            size:         bytes.len() as u64,
            content_type: metadata
                .as_ref()
                .and_then(|value| {
                    value.get("httpMetadata")?.get("contentType")?.as_str()
                })
                .map(str::to_owned),
            http_etag:    None,
        };
        let range = match selected_range(headers, &object) {
            Ok(range) => range,
            Err(InvalidRange) => return invalid_range_response(object.size),
        };
        let body = if head {
            Body::empty()
        } else {
            let bytes = Bytes::from(bytes);
            Body::from(if let Some(range) = range {
                bytes.slice(range.start as usize..=range.end as usize)
            } else {
                bytes
            })
        };
        download_response(&object, range, body)
    }

    pub async fn delete_many(&self, keys: &[String]) -> AppResult<()> {
        if let Some(bucket) = self.r2() {
            for batch in keys.chunks(1000) {
                bucket
                    .delete_multiple(batch.iter().map(String::as_str).collect())
                    .await?;
            }
            return Ok(());
        }
        for key in keys {
            self.env
                .kv("ATTACHMENTS_KV")?
                .delete(key)
                .await
                .map_err(kv_error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_budget_rejects_overflow_before_the_offending_chunk_is_written() {
        assert_eq!(next_size(24, 1, 25).unwrap(), 25);
        assert!(next_size(25, 1, 25).is_err());
        assert!(next_size(u64::MAX, 1, u64::MAX).is_err());
    }

    #[test]
    fn range_validators_choose_full_or_partial_download_without_touching_storage()
     {
        let object = StoredObject {
            size:         10,
            content_type: None,
            http_etag:    Some("\"etag\"".into()),
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=2-5".parse().unwrap());
        assert_eq!(
            selected_range(&headers, &object).unwrap(),
            Some(ByteRange { start: 2, end: 5 })
        );
        headers.insert(header::IF_RANGE, "\"other\"".parse().unwrap());
        assert_eq!(selected_range(&headers, &object).unwrap(), None);
        headers.insert(header::IF_RANGE, "\"etag\"".parse().unwrap());
        assert_eq!(
            selected_range(&headers, &object).unwrap(),
            Some(ByteRange { start: 2, end: 5 })
        );
        headers.insert(header::RANGE, "bytes=10-".parse().unwrap());
        assert!(selected_range(&headers, &object).is_err());
        assert_eq!(
            invalid_range_response(10).unwrap().headers()
                [header::CONTENT_RANGE],
            "bytes */10"
        );
    }

    #[test]
    fn response_headers_preserve_range_size_type_and_etag_for_head_or_get() {
        let object = StoredObject {
            size:         10,
            content_type: Some("application/test".into()),
            http_etag:    Some("\"etag\"".into()),
        };
        let response = download_response(
            &object,
            Some(ByteRange { start: 2, end: 5 }),
            Body::empty(),
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/test"
        );
        assert_eq!(response.headers()[header::ETAG], "\"etag\"");
    }
}
