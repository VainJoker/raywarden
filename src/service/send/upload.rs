//! Streaming file writes and publication under the captured account/session.
use bytes::Bytes;
use futures_util::{Stream, StreamExt as _, stream};
use serde::Serialize;
use worker::{D1Database, D1PreparedStatement, Env};

use super::{
    content::{self, SendUploadState},
    notify_update,
    token::{FileTokenScope, TokenPurpose, decode_file_token, encode_token},
};
use crate::{
    errors::{AppError, AppResult},
    infra::{
        config::{send_file_token_expires_at_seconds, send_max_bytes, send_quota_bytes},
        storage::Storage,
    },
    models::{
        identity::device::SessionSnapshot,
        mutation::{account_snapshot_guard, commit_session},
        send::SendRow,
    },
    service::{
        identity::session::{Claims, validate_session},
        notifications,
        storage_cleanup::{self, StagedObject},
    },
};

pub(crate) enum UploadAuthorization<'a> {
    Session(&'a Claims),
    Capability { secret: &'a str, token: &'a str },
}

/// Identity captured before an upload and rechecked atomically at publication.
struct UploadSession {
    user_id: String,
    security_stamp: String,
    device_id: String,
    session_token: String,
}

impl UploadSession {
    fn from_claims(claims: &Claims) -> AppResult<Self> {
        let session = claims.session_snapshot()?;
        Ok(Self {
            user_id: session.user_id.to_owned(),
            security_stamp: session.security_stamp.to_owned(),
            device_id: session.device_id.to_owned(),
            session_token: session.session_token.to_owned(),
        })
    }

    const fn snapshot(&self) -> SessionSnapshot<'_> {
        SessionSnapshot {
            user_id: self.user_id.as_str(),
            security_stamp: self.security_stamp.as_str(),
            device_id: self.device_id.as_str(),
            session_token: self.session_token.as_str(),
        }
    }
}

/// The final error is yielded before Storage completes its multipart upload.
fn checked_upload_stream<S, E>(stream: S, exact_bytes: u64) -> impl Stream<Item = AppResult<Bytes>>
where
    S: Stream<Item = Result<Bytes, E>>,
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
            let chunk = chunk.map_err(|_error| AppError::bad_request("Invalid upload body"))?;
            let total = total
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| AppError::bad_request("Send file is too large"))?;
            Ok(Some((chunk, (stream, total))))
        },
    )
}

/// One staged upload, bound to the captured session and Send snapshot.
/// Callers explicitly commit or abort: remote cleanup cannot run in Drop.
#[must_use = "An upload must be finished"]
pub(crate) struct SendUpload<'a> {
    db: &'a D1Database,
    env: &'a Env,
    send: SendRow,
    session: UploadSession,
    staged: StagedObject<'a>,
    key_guard: D1PreparedStatement,
    expected_bytes: u64,
}

impl<'a> SendUpload<'a> {
    pub(crate) async fn prepare(
        db: &'a D1Database,
        env: &'a Env,
        send_id: &str,
        file_id: &str,
        authorization: UploadAuthorization<'_>,
    ) -> AppResult<Self> {
        let (session, access_stamp) = match authorization {
            UploadAuthorization::Session(claims) => (UploadSession::from_claims(claims)?, None),
            UploadAuthorization::Capability { secret, token } => {
                let claims =
                    decode_file_token(secret, token, FileTokenScope::Upload, send_id, file_id)?;
                let (Some(security_stamp), Some(device_id), Some(session_token)) =
                    (claims.sstamp, claims.device, claims.session_token)
                else {
                    return Err(AppError::Unauthorized {
                        message: "A user session is required".into(),
                    });
                };
                if security_stamp.is_empty() || device_id.is_empty() || session_token.is_empty() {
                    return Err(AppError::Unauthorized {
                        message: "A user session is required".into(),
                    });
                }
                let session = UploadSession {
                    user_id: claims.sub,
                    security_stamp,
                    device_id,
                    session_token,
                };
                validate_session(db, &session.snapshot()).await?;
                (session, Some(claims.access_stamp))
            }
        };
        let send = SendRow::fetch_by_id(db, send_id).await?;
        if send.user_id != session.user_id
            || !matches!(
                SendUploadState::try_from(send.upload_state),
                Ok(SendUploadState::Ready | SendUploadState::Pending)
            )
            || send.file_id.as_deref() != Some(file_id)
            || access_stamp
                .as_deref()
                .is_some_and(|stamp| stamp != send.access_stamp)
        {
            return Err(if access_stamp.is_some() {
                AppError::send_unavailable()
            } else {
                AppError::not_found("Pending Send not found")
            });
        }
        send_file_token_expires_at_seconds(env, crate::utils::time::now_seconds())?;
        send_quota_bytes(env)?;
        validate_session(db, &session.snapshot()).await?;
        let (_, key_guard) = account_snapshot_guard(db, &session.user_id).await?;
        let expected_bytes = u64::try_from(send.file_size_bytes)
            .map_err(|_error| AppError::bad_request("Invalid Send file size"))?;
        let staged = StagedObject::new(db, env, "sends", &send.id, file_id);
        Ok(Self {
            db,
            env,
            send,
            session,
            staged,
            key_guard,
            expected_bytes,
        })
    }

    pub(crate) const fn send(&self) -> &SendRow {
        &self.send
    }

    pub(crate) const fn expected_bytes(&self) -> u64 {
        self.expected_bytes
    }

    pub(crate) async fn write<S, E>(&mut self, stream: S) -> AppResult<()>
    where
        S: Stream<Item = Result<Bytes, E>>,
    {
        self.staged.ensure_unwritten()?;
        let storage = Storage::from_env(self.env)?;
        let maximum = self.expected_bytes.min(send_max_bytes(self.env) as u64);
        self.staged
            .write(
                &storage,
                checked_upload_stream(stream, self.expected_bytes),
                maximum,
                Some("application/octet-stream"),
            )
            .await
    }

    pub(crate) async fn finish(self, received: AppResult<()>) -> AppResult<()> {
        let Self {
            db,
            env,
            send,
            session,
            staged,
            key_guard,
            ..
        } = self;
        let session = session.snapshot();
        let revision = staged
            .publish(
                async |object| {
                    received?;
                    let size = i64::try_from(object.size()?)
                        .map_err(|_error| AppError::bad_request("Send file is too large"))?;
                    let now = crate::utils::time::now_rfc3339();
                    Ok((vec![key_guard, send.upload_guard(db)?], vec![
                        send.finalize_upload_statement(db, size, object.key(), &now)?,
                    ]))
                },
                async |guards, writes| commit_session(db, &session, guards, writes).await,
            )
            .await?;
        notify_update(
            env,
            &send,
            notifications::UpdateType::SyncSendUpdate,
            Some(session.device_id),
            &revision,
        )
        .await;
        if let Err(error) = storage_cleanup::process_batch(env, db).await {
            log::warn!("Send replaced-object cleanup deferred: {error:?}");
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendFileUploadResponse {
    object: &'static str,
    file_upload_type: u8,
    url: String,
    send_response: content::SendResponse,
}

pub(super) fn upload_response(
    env: &Env,
    domain: &str,
    access_secret: &str,
    send: SendRow,
    claims: &Claims,
) -> AppResult<SendFileUploadResponse> {
    let token = encode_token(env, access_secret, &send, TokenPurpose::Upload(claims))?;
    let file_id = send
        .file_id
        .as_deref()
        .ok_or_else(|| AppError::internal("File Send is missing its file ID"))?;
    Ok(SendFileUploadResponse {
        object: "send-fileUpload",
        file_upload_type: 1,
        url: format!(
            "{}/api/sends/{}/file/{file_id}/azure-upload?token={token}",
            domain.trim_end_matches('/'),
            send.id
        ),
        send_response: content::send_response(send),
    })
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt as _;

    use super::*;

    #[test]
    fn checked_upload_stream_enforces_exact_length_and_propagates_errors() {
        let ok =
            checked_upload_stream(stream::iter([Ok::<_, &str>(Bytes::from_static(b"abc"))]), 3)
                .collect::<Vec<_>>()
                .now_or_never()
                .expect("ready");
        assert_eq!(ok[0].as_ref().expect("chunk").as_ref(), b"abc");
        let short =
            checked_upload_stream(stream::iter([Ok::<_, &str>(Bytes::from_static(b"abc"))]), 4)
                .collect::<Vec<_>>()
                .now_or_never()
                .expect("ready");
        assert!(short.last().expect("err").is_err());
    }
}
