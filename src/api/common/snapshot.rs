//! Encode owner collections in chunks before their final snapshot check.
use std::{
    convert::Infallible,
    io::{self, Write},
};

use axum::{
    body::Body,
    http::header,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::Serialize;
use worker::D1Database;

use crate::{
    errors::{AppError, AppResult, AuthError},
    models::identity::{account_keys::AccountSnapshot, user::UserRow},
    service::identity::session::{Claims, TokenUse},
};

pub(in crate::api) struct ReadSnapshot {
    account: AccountSnapshot,
    revision: String,
}

impl ReadSnapshot {
    pub(in crate::api) fn from_user(user: &UserRow) -> Self {
        Self {
            account: AccountSnapshot::from_user(user),
            revision: user.updated_at.clone(),
        }
    }

    pub(in crate::api) async fn capture(db: &D1Database, claims: &Claims) -> AppResult<Self> {
        Ok(Self::from_user(
            &Self::user(db, claims, "Failed to open vault snapshot").await?,
        ))
    }

    pub(in crate::api) async fn user(
        db: &D1Database,
        claims: &Claims,
        context: &'static str,
    ) -> AppResult<UserRow> {
        UserRow::fetch_by_id_with(db, &claims.sub, context, || {
            AppError::Auth(AuthError::UserNotFound)
        })
        .await
    }

    pub(in crate::api) async fn verify(&self, db: &D1Database, claims: &Claims) -> AppResult<()> {
        let current = Self::user(db, claims, "Failed to verify vault snapshot").await?;
        if !self.account.matches_user(&current) || self.revision != current.updated_at {
            return Err(AppError::conflict(
                "Account or vault changed during sync. Retry sync.",
            ));
        }
        claims.validate_session(db, TokenUse::Access).await?;
        Ok(())
    }
}

// Workers have a 128 MiB isolate limit. Retain at most half of it as encoded
// response bytes, leaving room for the current D1 page and the runtime.
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const CHUNK_BYTES: usize = 256 * 1024;

pub(in crate::api) struct SnapshotJson {
    output: ChunkBuffer,
    empty: bool,
}

pub(in crate::api) enum ListOrder {
    ObjectFirst,
    ContinuationFirst,
}

impl SnapshotJson {
    pub(in crate::api) async fn list(
        db: &D1Database,
        claims: &Claims,
        order: ListOrder,
        write: impl AsyncFnOnce(&mut SnapshotArray<'_>) -> AppResult<()>,
    ) -> AppResult<Response> {
        let snapshot = ReadSnapshot::capture(db, claims).await?;
        let mut response = Self::new();
        response.write_array("data", write).await?;
        let mut metadata = [("object", Some("list")), ("continuationToken", None)];
        if matches!(order, ListOrder::ContinuationFirst) {
            metadata.swap(0, 1);
        }
        for (key, value) in metadata {
            response.field(key, &value)?;
        }
        let response = response.finish()?;
        snapshot.verify(db, claims).await?;
        Ok(response)
    }

    pub(in crate::api) fn new() -> Self {
        let mut current = Vec::with_capacity(CHUNK_BYTES);
        current.push(b'{');
        Self {
            output: ChunkBuffer {
                chunks: Vec::new(),
                current,
                written: 1,
            },
            empty: true,
        }
    }

    fn key(&mut self, key: &str) -> AppResult<()> {
        if !self.empty {
            self.output.literal(b",")?;
        }
        self.empty = false;
        self.output.value(key)?;
        self.output.literal(b":")
    }

    pub(in crate::api) fn field<T: Serialize + ?Sized>(
        &mut self,
        key: &str,
        value: &T,
    ) -> AppResult<()> {
        self.key(key)?;
        self.output.value(value)
    }

    pub(in crate::api) async fn write_array(
        &mut self,
        key: &str,
        write: impl AsyncFnOnce(&mut SnapshotArray<'_>) -> AppResult<()>,
    ) -> AppResult<()> {
        self.key(key)?;
        self.output.literal(b"[")?;
        let mut array = SnapshotArray {
            output: &mut self.output,
            empty: true,
        };
        write(&mut array).await?;
        self.output.literal(b"]")
    }

    pub(in crate::api) fn finish(mut self) -> AppResult<Response> {
        self.output.literal(b"}")?;
        self.output.chunks.push(Bytes::from(self.output.current));
        let chunks = self.output.chunks.into_iter().map(Ok::<Bytes, Infallible>);
        Ok((
            [(header::CONTENT_TYPE, "application/json")],
            Body::from_stream(futures_util::stream::iter(chunks)),
        )
            .into_response())
    }
}

pub(in crate::api) struct SnapshotArray<'a> {
    output: &'a mut ChunkBuffer,
    empty: bool,
}

impl SnapshotArray<'_> {
    pub(in crate::api) fn push<T: Serialize>(&mut self, value: &T) -> AppResult<()> {
        if !self.empty {
            self.output.literal(b",")?;
        }
        self.empty = false;
        self.output.value(value)
    }
}

struct ChunkBuffer {
    chunks: Vec<Bytes>,
    current: Vec<u8>,
    written: usize,
}

impl ChunkBuffer {
    fn literal(&mut self, bytes: &[u8]) -> AppResult<()> {
        self.write_all(bytes).map_err(|_error| oversized_snapshot())
    }

    fn value<T: Serialize + ?Sized>(&mut self, value: &T) -> AppResult<()> {
        serde_json::to_writer(self, value).map_err(|error| {
            if error.io_error_kind() == Some(io::ErrorKind::FileTooLarge) {
                oversized_snapshot()
            } else {
                AppError::internal_json("Failed to encode vault response")(error)
            }
        })
    }
}

impl Write for ChunkBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_SNAPSHOT_BYTES - self.written {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            if self.current.len() == CHUNK_BYTES {
                let chunk = std::mem::replace(&mut self.current, Vec::with_capacity(CHUNK_BYTES));
                self.chunks.push(Bytes::from(chunk));
            }
            let take = remaining.len().min(CHUNK_BYTES - self.current.len());
            self.current.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn oversized_snapshot() -> AppError {
    AppError::PayloadTooLarge {
        message: "Vault response exceeds the server size limit".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_limit_rejects_excess_bytes_before_writing_them() {
        let mut output = ChunkBuffer {
            chunks: Vec::new(),
            current: Vec::new(),
            written: MAX_SNAPSHOT_BYTES - 1,
        };
        output.literal(b"x").expect("the last byte fits");
        assert!(matches!(
            output.literal(b"y"),
            Err(AppError::PayloadTooLarge { .. })
        ));
        assert_eq!(output.current, b"x");
    }
}
