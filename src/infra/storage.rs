//! R2 and bounded KV object storage, including native streaming reads.
use std::{
    fmt::Display,
    ops::RangeInclusive,
};

use bytes::Bytes;
use futures_util::{
    Stream,
    StreamExt,
};
use serde_json::json;
use worker::{
    Bucket,
    Env,
    HttpMetadata,
    MultipartUpload,
    Range,
    UploadedPart,
    kv::KvStore,
};

use crate::errors::{
    AppError,
    AppResult,
};

pub const KV_MAX_BYTES: usize = 25 * 1024 * 1024;
const MULTIPART_PART_BYTES: usize = 8 * 1024 * 1024;
const MAX_MULTIPART_PARTS: u16 = 10_000;

#[derive(Debug)]
pub struct ObjectMetadata {
    pub size_bytes: u64,
    pub http_etag:  Option<String>,
}

/// An opened object: R2 holds a lazy content source, KV holds its bounded read.
pub struct OpenedObject {
    pub metadata: ObjectMetadata,
    source:       ObjectSource,
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
    pub async fn read(
        self,
        range: Option<RangeInclusive<u64>>,
    ) -> AppResult<Option<ObjectBody>> {
        if let Some(range) = &range &&
            (range.is_empty() || *range.end() >= self.metadata.size_bytes)
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
            ObjectSource::Kv(bytes) => {
                Ok(Some(ObjectBody::Bytes(if let Some(range) = range {
                    bytes.slice(*range.start() as usize..=*range.end() as usize)
                } else {
                    bytes
                })))
            }
        }
    }
}

/// R2 streams are preferred. KV keeps the existing raw-byte object format and
/// is buffered only within its 25 MiB backend limit.
pub enum Storage {
    R2(Bucket),
    Kv(KvStore),
}

struct R2MultipartUpload<'a> {
    bucket: &'a Bucket,
    key:    &'a str,
    upload: MultipartUpload,
    parts:  Vec<UploadedPart>,
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

    async fn complete(&mut self, final_part: Vec<u8>) -> AppResult<()> {
        if !final_part.is_empty() {
            self.push(final_part).await?;
        }
        // Keep the original handle available for abort if completion fails.
        let id = self.upload.upload_id().await;
        self.bucket
            .resume_multipart_upload(self.key, &id)?
            .complete(std::mem::take(&mut self.parts))
            .await?;
        Ok(())
    }

    async fn abort(self) {
        if let Err(error) = self.upload.abort().await {
            log::warn!("Failed to abort file upload: {error}");
        }
    }
}

fn checked_upload_size_bytes(
    current: u64,
    chunk: usize,
    maximum: u64,
) -> AppResult<u64> {
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

impl Storage {
    pub fn enabled(env: &Env) -> bool {
        Self::binding(env).is_some()
    }

    pub fn from_env(env: &Env) -> AppResult<Self> {
        Self::binding(env)
            .ok_or_else(|| AppError::bad_request("File storage is not enabled"))
    }

    fn binding(env: &Env) -> Option<Self> {
        env.bucket("ATTACHMENTS_BUCKET")
            .map(Self::R2)
            .or_else(|_| env.kv("ATTACHMENTS_KV").map(Self::Kv))
            .ok()
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
        let bucket = match self {
            Self::R2(bucket) => bucket,
            Self::Kv(kv) => {
                return Self::put_kv_stream(
                    kv,
                    key,
                    stream,
                    max_bytes,
                    content_type,
                )
                .await;
            }
        };
        futures_util::pin_mut!(stream);

        let mut multipart = None;
        let result = async {
            let mut size = 0;
            let mut part = Vec::with_capacity(MULTIPART_PART_BYTES);
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(AppError::upload_stream_error)?;
                size = checked_upload_size_bytes(size, chunk.len(), max_bytes)?;
                let mut remaining = chunk.as_ref();
                while !remaining.is_empty() {
                    let count =
                        remaining.len().min(MULTIPART_PART_BYTES - part.len());
                    part.extend_from_slice(&remaining[..count]);
                    remaining = &remaining[count..];
                    if part.len() == MULTIPART_PART_BYTES {
                        let upload = match &mut multipart {
                            Some(upload) => upload,
                            slot @ None => slot.insert(
                                R2MultipartUpload::start(
                                    bucket,
                                    key,
                                    content_type,
                                )
                                .await?,
                            ),
                        };
                        let bytes = std::mem::replace(
                            &mut part,
                            Vec::with_capacity(MULTIPART_PART_BYTES),
                        );
                        upload.push(bytes).await?;
                    }
                }
            }
            if let Some(upload) = &mut multipart {
                upload.complete(part).await?;
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
            let Some(upload) = multipart
        {
            upload.abort().await;
        }
        result
    }

    async fn put_kv_stream<S, E>(
        kv: &KvStore,
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
            let chunk = chunk.map_err(AppError::upload_stream_error)?;
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
            .map_err(AppError::kv_error)?;
        Ok(size)
    }

    /// Open an object without consuming its R2 body. KV keeps the bytes from
    /// this one bounded read so callers can inspect metadata before reading.
    pub async fn open(&self, key: &str) -> AppResult<Option<OpenedObject>> {
        match self {
            Self::R2(bucket) => {
                Ok(bucket.head(key).await?.map(|object| OpenedObject {
                    metadata: ObjectMetadata {
                        size_bytes: object.size(),
                        http_etag:  Some(object.http_etag()),
                    },
                    source:   ObjectSource::R2 {
                        bucket: bucket.clone(),
                        key:    key.to_owned(),
                    },
                }))
            }
            Self::Kv(kv) => {
                let bytes =
                    kv.get(key).bytes().await.map_err(AppError::kv_error)?;
                Ok(bytes.map(|bytes| OpenedObject {
                    metadata: ObjectMetadata {
                        size_bytes: bytes.len() as u64,
                        http_etag:  None,
                    },
                    source:   ObjectSource::Kv(Bytes::from(bytes)),
                }))
            }
        }
    }

    pub async fn delete_many(&self, keys: &[&str]) -> AppResult<()> {
        match self {
            Self::R2(bucket) => {
                for batch in keys.chunks(1000) {
                    bucket.delete_multiple(batch.to_vec()).await?;
                }
            }
            Self::Kv(kv) => {
                for key in keys {
                    kv.delete(key).await.map_err(AppError::kv_error)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_budget_rejects_overflow_before_the_offending_chunk_is_written() {
        assert_eq!(
            checked_upload_size_bytes(24, 1, 25)
                .expect("test fixture should be valid"),
            25
        );
        assert!(checked_upload_size_bytes(25, 1, 25).is_err());
        assert!(checked_upload_size_bytes(u64::MAX, 1, u64::MAX).is_err());
    }
}
