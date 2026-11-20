//! Streaming file writes and publication under the captured account/session.
use std::fmt::Display;

use bytes::Bytes;
use futures_util::{
    Stream,
    StreamExt as _,
    stream,
};
use serde::Serialize;
use worker::{
    D1Database,
    D1PreparedStatement,
    Env,
};

use super::{
    content,
    notify_update,
    token::{
        TokenPurpose,
        UPLOAD_SCOPE,
        decode_file_token,
        encode_token,
    },
};
use crate::{
    app::AppContext,
    config::files::{
        DEFAULT_SEND_MAX_BYTES,
        send_file_token_expires_at_seconds,
        send_max_bytes,
    },
    errors::{
        AppError,
        AppResult,
    },
    infra::storage::Storage,
    models::{
        identity::device::SessionSnapshot,
        mutation::{
            account_snapshot_guard,
            commit_session,
        },
        send::{
            SendRow,
            upload_guard,
        },
    },
    service::{
        identity::session::{
            Claims,
            validate_session,
        },
        notifications,
    },
};

/// Identity captured before an upload and rechecked atomically at publication.
pub(crate) struct UploadSession {
    user_id:        String,
    security_stamp: String,
    device_id:      String,
    session_token:  String,
}

impl UploadSession {
    pub(crate) fn from_claims(claims: &Claims) -> AppResult<Self> {
        let session = claims.session_snapshot()?;
        Ok(Self {
            user_id:        session.user_id.to_owned(),
            security_stamp: session.security_stamp.to_owned(),
            device_id:      session.device_id.to_owned(),
            session_token:  session.session_token.to_owned(),
        })
    }

    pub(crate) async fn authorize_token_upload(
        state: &AppContext,
        token: &str,
        send_id: &str,
        file_id: &str,
    ) -> AppResult<(Self, SendRow)> {
        let claims = decode_file_token(
            &state.jwt_keys.access_secret,
            token,
            UPLOAD_SCOPE,
            send_id,
            file_id,
        )?;
        let session = Self {
            user_id:        claims.sub,
            security_stamp: claims.sstamp.unwrap_or_default(),
            device_id:      claims.device.unwrap_or_default(),
            session_token:  claims.session_token.unwrap_or_default(),
        };
        if session.security_stamp.is_empty() ||
            session.device_id.is_empty() ||
            session.session_token.is_empty()
        {
            return Err(AppError::Unauthorized {
                message: "A user session is required".into(),
            });
        }
        let db = state.database();
        session.validate(db).await?;
        let send = SendRow::fetch_by_id(db, send_id).await?;
        if !session.can_upload(&send, file_id) ||
            send.access_stamp != claims.access_stamp
        {
            return Err(AppError::send_unavailable());
        }
        Ok((session, send))
    }

    pub(crate) async fn fetch_uploadable_send(
        &self,
        state: &AppContext,
        send_id: &str,
        file_id: &str,
    ) -> AppResult<SendRow> {
        let send = SendRow::fetch_by_id(state.database(), send_id).await?;
        if !self.can_upload(&send, file_id) {
            return Err(AppError::not_found("Pending Send not found"));
        }
        Ok(send)
    }

    fn can_upload(&self, send: &SendRow, file_id: &str) -> bool {
        send.user_id == self.user_id &&
            matches!(send.upload_state, 0 | 1) &&
            send.file_id.as_deref() == Some(file_id)
    }

    async fn validate(&self, db: &D1Database) -> AppResult<()> {
        validate_session(db, &self.snapshot()).await
    }

    const fn snapshot(&self) -> SessionSnapshot<'_> {
        SessionSnapshot {
            user_id:        self.user_id.as_str(),
            security_stamp: self.security_stamp.as_str(),
            device_id:      self.device_id.as_str(),
            session_token:  self.session_token.as_str(),
        }
    }
}

/// The final error is yielded before Storage completes its multipart upload.
fn checked_upload_stream<S, E>(
    stream: S,
    exact_bytes: u64,
) -> impl Stream<Item = AppResult<Bytes>>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: Display,
{
    stream::try_unfold(
        (Box::pin(stream), 0_u64),
        move |(mut stream, total)| async move {
            let Some(chunk) = stream.next().await else {
                if total != exact_bytes {
                    return Err(AppError::bad_request(
                        "Send file size does not match fileLength",
                    ));
                }
                return Ok(None);
            };
            let chunk = chunk.map_err(|error| {
                AppError::bad_request(format!("Invalid upload body: {error}"))
            })?;
            let total =
                total.checked_add(chunk.len() as u64).ok_or_else(|| {
                    AppError::bad_request("Send file is too large")
                })?;
            Ok(Some((chunk, (stream, total))))
        },
    )
}

/// One staged upload, bound to the captured session and Send snapshot.
/// Callers explicitly commit or abort: remote cleanup cannot run in Drop.
#[must_use = "An upload must be committed or explicitly aborted"]
pub(crate) struct SendUpload<'a> {
    state:          &'a AppContext,
    send:           &'a SendRow,
    session:        SessionSnapshot<'a>,
    staged_key:     String,
    key_guard:      D1PreparedStatement,
    expected_bytes: u64,
    written_bytes:  Option<u64>,
}

impl<'a> SendUpload<'a> {
    pub(crate) async fn prepare(
        state: &'a AppContext,
        send: &'a SendRow,
        owner: &'a UploadSession,
    ) -> AppResult<Self> {
        send_file_token_expires_at_seconds(
            &state.env,
            crate::utils::time::now_seconds(),
        )?;
        let db = state.database();
        owner.validate(db).await?;
        let session = owner.snapshot();
        let (_, key_guard) =
            account_snapshot_guard(db, session.user_id).await?;
        let expected_bytes =
            u64::try_from(send.file_size_bytes).map_err(|_error| {
                AppError::bad_request("Invalid Send file size")
            })?;
        let staged_key = format!(
            "sends/{}/{}/{}",
            send.id,
            send.file_id
                .as_deref()
                .ok_or_else(AppError::send_unavailable)?,
            uuid::Uuid::new_v4()
        );
        Ok(Self {
            state,
            send,
            session,
            staged_key,
            key_guard,
            expected_bytes,
            written_bytes: None,
        })
    }

    pub(crate) const fn expected_bytes(&self) -> u64 {
        self.expected_bytes
    }

    pub(crate) async fn write<S, E>(&mut self, stream: S) -> AppResult<()>
    where
        S: Stream<Item = Result<Bytes, E>>,
        E: Display,
    {
        if self.written_bytes.is_some() {
            return Err(AppError::Internal);
        }
        let maximum = self
            .expected_bytes
            .min(max_file_size_bytes(&self.state.env) as u64);
        let size = Storage::from_env(&self.state.env)?
            .put_stream(
                &self.staged_key,
                checked_upload_stream(stream, self.expected_bytes),
                maximum,
                Some("application/octet-stream"),
            )
            .await?;
        self.written_bytes = Some(size);
        Ok(())
    }

    /// Publish once, cleaning the staged key on any failed commit. Referenced
    /// objects survive a lost D1 acknowledgement through the cleanup outbox.
    pub(crate) async fn commit(self) -> AppResult<()> {
        let Self {
            state,
            send,
            session,
            staged_key,
            key_guard,
            written_bytes,
            ..
        } = self;
        let result = async {
            let size = written_bytes.ok_or(AppError::Internal)?;
            if send.user_id != session.user_id {
                return Err(AppError::send_unavailable());
            }
            let size = i64::try_from(size).map_err(|_error| {
                AppError::bad_request("Send file is too large")
            })?;
            let now = crate::utils::time::now_rfc3339();
            let db = state.database();
            let revision = commit_session(
                db,
                &session,
                vec![key_guard, upload_guard(db, send)?],
                vec![send.finalize_upload_statement(
                    db,
                    size,
                    &staged_key,
                    &now,
                )?],
            )
            .await?;
            notify_update(
                state,
                send,
                notifications::UpdateType::SyncSendUpdate,
                Some(session.device_id),
                &revision,
            )
            .await;
            if let Err(error) =
                crate::service::storage_cleanup::process_batch(&state.env, db)
                    .await
            {
                log::warn!("Send replaced-object cleanup deferred: {error}");
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            discard_staged_file(state, &staged_key).await;
        }
        result
    }

    pub(crate) async fn abort(self) {
        discard_staged_file(self.state, &self.staged_key).await;
    }
}

async fn discard_staged_file(state: &AppContext, key: &str) {
    crate::service::storage_cleanup::discard_staged_object(
        &state.env,
        state.database(),
        key,
    )
    .await;
}

pub(super) fn max_file_size_bytes(env: &Env) -> i64 {
    let backend_max =
        Storage::max_bytes(env).map_or(DEFAULT_SEND_MAX_BYTES, |n| n as i64);
    send_max_bytes(env).min(backend_max)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendFileUploadResponse {
    object:           &'static str,
    file_upload_type: u8,
    url:              String,
    send_response:    content::SendResponse,
}

pub(super) fn upload_response(
    state: &AppContext,
    send: SendRow,
    claims: &Claims,
) -> AppResult<SendFileUploadResponse> {
    let token = encode_token(state, &send, TokenPurpose::Upload(claims))?;
    let file_id = send.file_id.as_deref().ok_or(AppError::Internal)?;
    Ok(SendFileUploadResponse {
        object:           "send-fileUpload",
        file_upload_type: 1,
        url:              format!(
            "{}/api/sends/{}/file/{file_id}/azure-upload?token={token}",
            state.domain().trim_end_matches('/'),
            send.id
        ),
        send_response:    content::send_response(send),
    })
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt as _;

    use super::*;

    #[test]
    fn checked_upload_stream_preserves_binary_chunks() {
        let chunks = stream::iter([
            Ok::<_, &str>(Bytes::from_static(&[0, 255, 128])),
            Ok(Bytes::from_static(b"abc")),
        ]);
        let result = checked_upload_stream(chunks, 6)
            .collect::<Vec<_>>()
            .now_or_never()
            .expect("ready input");
        let bytes: Vec<u8> = result
            .into_iter()
            .flat_map(|chunk| chunk.expect("valid chunk"))
            .collect();
        assert_eq!(bytes, [0, 255, 128, b'a', b'b', b'c']);
    }

    #[test]
    fn checked_upload_stream_rejects_wrong_length_and_input_errors_before_commit()
     {
        for exact in [2, 4] {
            let chunks =
                stream::iter([Ok::<_, &str>(Bytes::from_static(b"abc"))]);
            let result = checked_upload_stream(chunks, exact)
                .collect::<Vec<_>>()
                .now_or_never()
                .expect("ready input");
            assert!(result.last().expect("length error").is_err());
        }
        let chunks = stream::iter([Err::<Bytes, _>("broken request stream")]);
        let result = checked_upload_stream(chunks, 6)
            .collect::<Vec<_>>()
            .now_or_never()
            .expect("ready input");
        assert!(result[0].is_err());
        let empty = stream::empty::<Result<Bytes, &str>>();
        assert!(
            checked_upload_stream(empty, 0)
                .collect::<Vec<_>>()
                .now_or_never()
                .expect("ready input")
                .is_empty()
        );
    }
}
