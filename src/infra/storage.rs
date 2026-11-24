//! R2 and bounded KV object storage, including native streaming reads.
use std::ops::RangeInclusive;

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{
    Bucket, Env, EnvBinding, HttpMetadata, MultipartUpload, Range, UploadedPart, kv::KvStore,
};

use crate::errors::{AppError, AppResult, ConfigError};

pub const KV_MAX_BYTES: usize = 25 * 1024 * 1024;
const MULTIPART_PART_BYTES: usize = 8 * 1024 * 1024;
const MAX_MULTIPART_PARTS: u16 = 10_000;
const R2_BINDING: &str = "ATTACHMENTS_BUCKET";
const KV_BINDING: &str = "ATTACHMENTS_KV";

#[derive(Debug)]
pub struct ObjectMetadata {
    pub size_bytes: u64,
    pub http_etag: Option<String>,
}

/// An opened object: R2 holds a lazy content source, KV holds its bounded read.
pub struct OpenedObject {
    pub metadata: ObjectMetadata,
    source: ObjectSource,
}

enum ObjectSource {
    R2 { bucket: Bucket, key: String },
    Kv(Bytes),
}

pub enum ObjectBody {
    Stream(web_sys::ReadableStream),
    Bytes(Bytes),
}

impl OpenedObject {
    /// Read a selected inclusive byte interval, or the full object. A missing
    /// R2 object can disappear after opening; callers decide its HTTP meaning.
    pub async fn read(self, range: Option<RangeInclusive<u64>>) -> AppResult<Option<ObjectBody>> {
        if let Some(range) = &range
            && (range.is_empty() || *range.end() >= self.metadata.size_bytes)
        {
            return Err(AppError::Internal);
        }
        match self.source {
            ObjectSource::R2 { bucket, key } => {
                let get = bucket.get(&key);
                let get = if let Some(range) = range {
                    get.range(Range::OffsetWithLength {
                        offset: *range.start(),
                        length: *range.end() - *range.start() + 1,
                    })
                } else {
                    get
                };
                let Some(object) = get.execute().await? else {
                    return Ok(None);
                };
                let worker::ResponseBody::Stream(stream) =
                    object.body().ok_or(AppError::Internal)?.response_body()?
                else {
                    return Err(AppError::Internal);
                };
                Ok(Some(ObjectBody::Stream(stream)))
            }
            ObjectSource::Kv(bytes) => Ok(Some(ObjectBody::Bytes(if let Some(range) = range {
                bytes.slice(*range.start() as usize..=*range.end() as usize)
            } else {
                bytes
            }))),
        }
    }
}

/// R2 streams are preferred. KV keeps the existing raw-byte object format and
/// is buffered only within its 25 MiB backend limit.
pub enum Storage {
    R2(Bucket),
    Kv(KvStore),
}

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
            .await?;
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
        self.parts
            .push(self.upload.upload_part(number, bytes).await?);
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
            .map_err(AppError::from)?
            .complete(std::mem::take(&mut self.parts))
            .await
            .map_err(|error| StorageWriteError::Unconfirmed(error.into()))?;
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
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(MULTIPART_PART_BYTES),
        }
    }

    fn append(&mut self, remaining: &mut &[u8]) -> Option<Vec<u8>> {
        let take = remaining.len().min(MULTIPART_PART_BYTES - self.bytes.len());
        let (prefix, rest) = remaining.split_at(take);
        self.bytes.extend_from_slice(prefix);
        *remaining = rest;
        (self.bytes.len() == MULTIPART_PART_BYTES)
            .then(|| std::mem::replace(&mut self.bytes, Vec::with_capacity(MULTIPART_PART_BYTES)))
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
        let r2 = binding_value(env, R2_BINDING)?;
        if !r2.is_undefined() {
            let constructor = js_sys::Reflect::get(&r2, &"constructor".into())
                .map_err(|_error| invalid_storage_binding(R2_BINDING))?;
            if !constructor.is_function() {
                return Err(invalid_storage_binding(R2_BINDING));
            }
            return <Bucket as EnvBinding>::get(r2)
                .map(|bucket| Some(Self::R2(bucket)))
                .map_err(|_error| invalid_storage_binding(R2_BINDING));
        }

        let kv = binding_value(env, KV_BINDING)?;
        if kv.is_undefined() {
            return Ok(None);
        }
        // The SDK wraps these properties without checking that they are
        // callable.
        for method in ["get", "getWithMetadata", "put", "list", "delete"] {
            if !js_sys::Reflect::get(&kv, &method.into()).is_ok_and(|value| value.is_function()) {
                return Err(invalid_storage_binding(KV_BINDING));
            }
        }
        env.kv(KV_BINDING)
            .map(|store| Some(Self::Kv(store)))
            .map_err(|_error| invalid_storage_binding(KV_BINDING))
    }

    pub const fn max_bytes(&self) -> Option<usize> {
        match self {
            Self::R2(_) => None,
            Self::Kv(_) => Some(KV_MAX_BYTES),
        }
    }

    /// Accept borrowed multipart fields as well as request bodies. No full-file
    /// collection occurs for R2: only the current incoming chunk and an 8 MiB
    /// part are retained. Errors abort an unfinished multipart upload.
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
        let bucket = match self {
            Self::R2(bucket) => bucket,
            Self::Kv(kv) => {
                return Self::put_kv_stream(kv, key, stream, max_bytes, content_type).await;
            }
        };
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
                    .map_err(|error| StorageWriteError::Unconfirmed(error.into()))?;
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

    async fn put_kv_stream<S>(
        kv: &KvStore,
        key: &str,
        stream: S,
        max_bytes: u64,
        content_type: Option<&str>,
    ) -> Result<u64, StorageWriteError>
    where
        S: Stream<Item = AppResult<Bytes>>,
    {
        futures_util::pin_mut!(stream);
        let maximum = max_bytes.min(KV_MAX_BYTES as u64);
        let mut data = Vec::new();
        let mut size = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            size = checked_upload_size_bytes(size, chunk.len(), maximum)?;
            data.extend_from_slice(&chunk);
        }
        kv.put_bytes(key, &data)
            .map_err(AppError::kv_error)?
            .metadata(json!({
                "size": size,
                "httpMetadata": { "contentType": content_type },
            }))
            .map_err(AppError::kv_error)?
            .execute()
            .await
            .map_err(|error| StorageWriteError::Unconfirmed(AppError::kv_error(error)))?;
        Ok(size)
    }

    /// Open an object without consuming its R2 body. KV keeps the bytes from
    /// this one bounded read so callers can inspect metadata before reading.
    pub async fn open(&self, key: &str) -> AppResult<Option<OpenedObject>> {
        match self {
            Self::R2(bucket) => Ok(bucket.head(key).await?.map(|object| OpenedObject {
                metadata: ObjectMetadata {
                    size_bytes: object.size(),
                    http_etag: Some(object.http_etag()),
                },
                source: ObjectSource::R2 {
                    bucket: bucket.clone(),
                    key: key.to_owned(),
                },
            })),
            Self::Kv(kv) => {
                let bytes = kv.get(key).bytes().await.map_err(AppError::kv_error)?;
                Ok(bytes.map(|bytes| OpenedObject {
                    metadata: ObjectMetadata {
                        size_bytes: bytes.len() as u64,
                        http_etag: None,
                    },
                    source: ObjectSource::Kv(Bytes::from(bytes)),
                }))
            }
        }
    }

    pub async fn delete_many(&self, keys: &[&str]) -> (usize, Option<AppError>) {
        let mut completed = 0usize;
        match self {
            Self::R2(bucket) => {
                for batch in keys.chunks(1000) {
                    if let Err(error) = bucket.delete_multiple(batch.to_vec()).await {
                        return (completed, Some(error.into()));
                    }
                    completed += batch.len();
                }
            }
            Self::Kv(kv) => {
                for key in keys {
                    if let Err(error) = kv.delete(key).await.map_err(AppError::kv_error) {
                        return (completed, Some(error));
                    }
                    completed += 1;
                }
            }
        }
        (completed, None)
    }
}

fn binding_value(env: &Env, name: &str) -> AppResult<JsValue> {
    js_sys::Reflect::get(env, &name.into()).map_err(|_error| invalid_storage_binding(name))
}

fn invalid_storage_binding(name: &str) -> AppError {
    ConfigError::Invalid(format!("File storage binding {name}")).into()
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
