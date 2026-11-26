//! R2 object storage with multipart uploads and native streaming reads.
use std::ops::RangeInclusive;

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use wasm_bindgen::JsValue;
use worker::{Bucket, Env, EnvBinding, HttpMetadata, MultipartUpload, Range, UploadedPart};

use crate::errors::{AppError, AppResult, ConfigError};

const MULTIPART_PART_BYTES: usize = 8 * 1024 * 1024;
const MAX_MULTIPART_PARTS: u16 = 10_000;
const R2_BINDING: &str = "ATTACHMENTS_BUCKET";

#[derive(Debug)]
pub struct ObjectMetadata {
    pub size_bytes: u64,
    pub http_etag: String,
}

/// An opened R2 object holding metadata and a lazy content handle.
pub struct OpenedObject {
    pub metadata: ObjectMetadata,
    bucket: Bucket,
    key: String,
}

impl OpenedObject {
    /// Read a selected inclusive byte interval, or the full object. A missing
    /// R2 object can disappear after opening; callers decide its HTTP meaning.
    pub async fn read(
        self,
        range: Option<RangeInclusive<u64>>,
    ) -> AppResult<Option<web_sys::ReadableStream>> {
        if let Some(range) = &range
            && (range.is_empty() || *range.end() >= self.metadata.size_bytes)
        {
            return Err(AppError::internal(
                "Invalid byte range for object storage read",
            ));
        }
        let get = self.bucket.get(&self.key);
        let get = if let Some(range) = range {
            get.range(Range::OffsetWithLength {
                offset: *range.start(),
                length: *range.end() - *range.start() + 1,
            })
        } else {
            get
        };
        let Some(object) = get.execute().await.map_err(AppError::r2_error)? else {
            return Ok(None);
        };
        let worker::ResponseBody::Stream(stream) = object
            .body()
            .ok_or_else(|| AppError::internal("Object storage returned no readable body stream"))?
            .response_body()
            .map_err(AppError::r2_error)?
        else {
            return Err(AppError::internal(
                "Object storage returned a non-streaming body",
            ));
        };
        Ok(Some(stream))
    }
}

pub struct Storage(Bucket);

pub(crate) enum StorageWriteError {
    Incomplete(AppError),
    // The final backend write was sent, but its outcome is unknown.
    Unconfirmed(AppError),
}

impl From<AppError> for StorageWriteError {
    fn from(error: AppError) -> Self {
        Self::Incomplete(error)
    }
}

struct R2MultipartUpload<'a> {
    bucket: &'a Bucket,
    key: &'a str,
    upload: MultipartUpload,
    parts: Vec<UploadedPart>,
}

impl<'a> R2MultipartUpload<'a> {
    async fn start(
        bucket: &'a Bucket,
        key: &'a str,
        content_type: Option<&str>,
    ) -> AppResult<Self> {
        let upload = bucket
            .create_multipart_upload(key)
            .http_metadata(metadata(content_type))
            .execute()
            .await
            .map_err(AppError::r2_error)?;
        Ok(Self {
            bucket,
            key,
            upload,
            parts: Vec::new(),
        })
    }

    async fn push(&mut self, bytes: Vec<u8>) -> AppResult<()> {
        let number = u16::try_from(self.parts.len() + 1)
            .ok()
            .filter(|&number| number <= MAX_MULTIPART_PARTS)
            .ok_or_else(|| AppError::bad_request("Too many upload parts"))?;
        self.parts.push(
            self.upload
                .upload_part(number, bytes)
                .await
                .map_err(AppError::r2_error)?,
        );
        Ok(())
    }

    async fn complete(&mut self, final_part: Vec<u8>) -> Result<(), StorageWriteError> {
        if !final_part.is_empty() {
            self.push(final_part).await?;
        }
        // Keep the original handle available for abort if completion fails.
        let id = self.upload.upload_id().await;
        self.bucket
            .resume_multipart_upload(self.key, &id)
            .map_err(AppError::r2_error)?
            .complete(std::mem::take(&mut self.parts))
            .await
            .map_err(|error| StorageWriteError::Unconfirmed(AppError::r2_error(error)))?;
        Ok(())
    }

    async fn abort(self) {
        if let Err(error) = self.upload.abort().await {
            log::warn!("Failed to abort file upload: {error}");
        }
    }
}

fn checked_upload_size_bytes(current: u64, chunk: usize, maximum: u64) -> AppResult<u64> {
    u64::try_from(chunk)
        .ok()
        .and_then(|chunk| current.checked_add(chunk))
        .filter(|size| *size <= maximum)
        .ok_or_else(|| AppError::bad_request("File size exceeds limit"))
}

struct PartAccumulator {
    bytes: Vec<u8>,
}

impl PartAccumulator {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn append(&mut self, remaining: &mut &[u8]) -> Option<Vec<u8>> {
        let take = remaining.len().min(MULTIPART_PART_BYTES - self.bytes.len());
        let (prefix, rest) = remaining.split_at(take);
        let needed = self.bytes.len() + prefix.len();
        if needed > self.bytes.capacity() {
            let target = if self.bytes.is_empty() && rest.is_empty() {
                needed
            } else {
                self.bytes
                    .capacity()
                    .max(64 * 1024)
                    .saturating_mul(2)
                    .max(needed)
                    .min(MULTIPART_PART_BYTES)
            };
            self.bytes.reserve_exact(target - self.bytes.len());
        }
        self.bytes.extend_from_slice(prefix);
        *remaining = rest;
        (self.bytes.len() == MULTIPART_PART_BYTES).then(|| std::mem::take(&mut self.bytes))
    }
}

fn metadata(content_type: Option<&str>) -> HttpMetadata {
    HttpMetadata {
        content_type: content_type.map(str::to_owned),
        ..Default::default()
    }
}

impl Storage {
    /// Binding errors also indicate configured storage.
    pub fn is_configured(env: &Env) -> bool {
        !matches!(Self::binding(env), Ok(None))
    }

    pub fn from_env(env: &Env) -> AppResult<Self> {
        Self::binding(env)?.ok_or_else(|| AppError::bad_request("File storage is not enabled"))
    }

    fn binding(env: &Env) -> AppResult<Option<Self>> {
        let r2: JsValue =
            js_sys::Reflect::get(env, &R2_BINDING.into()).map_err(|_error| invalid_binding())?;
        if r2.is_undefined() {
            return Ok(None);
        }
        let constructor =
            js_sys::Reflect::get(&r2, &"constructor".into()).map_err(|_error| invalid_binding())?;
        if !constructor.is_function() {
            return Err(invalid_binding());
        }
        <Bucket as EnvBinding>::get(r2)
            .map(|bucket| Some(Self(bucket)))
            .map_err(|_error| invalid_binding())
    }

    /// Accept borrowed multipart fields as well as request bodies. No full-file
    /// collection occurs: only the current incoming chunk and an 8 MiB part are
    /// retained. Errors abort an unfinished multipart upload.
    pub(crate) async fn put_stream<S>(
        &self,
        key: &str,
        stream: S,
        max_bytes: u64,
        content_type: Option<&str>,
    ) -> Result<u64, StorageWriteError>
    where
        S: Stream<Item = AppResult<Bytes>>,
    {
        let bucket = &self.0;
        futures_util::pin_mut!(stream);

        let mut multipart = None;
        let result = async {
            let mut size = 0;
            let mut part = PartAccumulator::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                size = checked_upload_size_bytes(size, chunk.len(), max_bytes)?;
                let mut remaining = chunk.as_ref();
                while !remaining.is_empty() {
                    if let Some(bytes) = part.append(&mut remaining) {
                        let upload = match &mut multipart {
                            Some(upload) => upload,
                            slot @ None => slot
                                .insert(R2MultipartUpload::start(bucket, key, content_type).await?),
                        };
                        upload.push(bytes).await?;
                    }
                }
            }
            if let Some(upload) = &mut multipart {
                upload.complete(part.bytes).await?;
            } else {
                bucket
                    .put(key, part.bytes)
                    .http_metadata(metadata(content_type))
                    .execute()
                    .await
                    .map_err(|error| StorageWriteError::Unconfirmed(AppError::r2_error(error)))?;
            }
            Ok(size)
        }
        .await;
        if result.is_err()
            && let Some(upload) = multipart
        {
            upload.abort().await;
        }
        result
    }

    /// Open an object without consuming its R2 body.
    pub async fn open(&self, key: &str) -> AppResult<Option<OpenedObject>> {
        let bucket = &self.0;
        Ok(bucket
            .head(key)
            .await
            .map_err(AppError::r2_error)?
            .map(|object| OpenedObject {
                metadata: ObjectMetadata {
                    size_bytes: object.size(),
                    http_etag: object.http_etag(),
                },
                bucket: bucket.clone(),
                key: key.to_owned(),
            }))
    }

    pub async fn delete_batch(&self, keys: Vec<&str>) -> AppResult<()> {
        self.0
            .delete_multiple(keys)
            .await
            .map_err(AppError::r2_error)
    }
}

fn invalid_binding() -> AppError {
    ConfigError::Invalid("File storage binding ATTACHMENTS_BUCKET is invalid").into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_budget_rejects_overflow_before_the_offending_chunk_is_written() {
        assert_eq!(
            checked_upload_size_bytes(24, 1, 25).expect("test fixture should be valid"),
            25
        );
        assert!(checked_upload_size_bytes(25, 1, 25).is_err());
        assert!(checked_upload_size_bytes(u64::MAX, 1, u64::MAX).is_err());
    }
}
