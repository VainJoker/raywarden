//! Streaming file writes and publication under the captured account/session.
use std::fmt::Display;

use bytes::Bytes;
use futures_util::{
    Stream,
    StreamExt as _,
    stream,
};
use serde_json::{
    Value,
    json,
};
use worker::{
    D1PreparedStatement,
    Env,
};

use super::{
    mutation::{
        insert,
        notify_update,
        upload_guard,
    },
    token::{
        TOKEN_TTL,
        UPLOAD_SCOPE,
        decode_file_token,
        encode_token,
    },
};
use crate::{
    api::{
        AppState,
        service::{
            cipher_mutation,
            claims::Claims,
            notifications,
        },
    },
    errors::AppError,
    infra::storage::Storage,
    models::device::DeviceDB,
    send::types::{
        MAX_FILE_BYTES,
        SendDB,
        SendRequestData,
        inaccessible,
        now_string,
    },
};

/// Identity captured before an upload and rechecked atomically at publication.
pub(super) struct UploadSession {
    pub user_id:   String,
    stamp:         String,
    device:        String,
    session_token: String,
}

impl UploadSession {
    pub(super) fn from_claims(claims: &Claims) -> Result<Self, AppError> {
        claims.validate_purpose("access")?;
        Ok(Self {
            user_id:       claims.sub.clone(),
            stamp:         claims.sstamp.clone(),
            device:        claims.device().unwrap_or_default().to_string(),
            session_token: claims.session_token.clone(),
        })
    }
}

pub(super) async fn upload_session(
    state: &AppState,
    token: &str,
    send_id: &str,
    file_id: &str,
) -> Result<(UploadSession, String), AppError> {
    let claims = decode_file_token(
        &state.config.jwt_secret,
        token,
        UPLOAD_SCOPE,
        send_id,
        file_id,
    )?;
    let session = UploadSession {
        user_id:       claims.sub,
        stamp:         claims.sstamp.unwrap_or_default(),
        device:        claims.device.unwrap_or_default(),
        session_token: claims.session_token.unwrap_or_default(),
    };
    if session.stamp.is_empty() ||
        session.device.is_empty() ||
        session.session_token.is_empty()
    {
        return Err(AppError::Unauthorized {
            message: "A user session is required".into(),
        });
    }
    DeviceDB::validate_session(
        &state.get_db(),
        &session.user_id,
        &session.device,
        &session.session_token,
        &session.stamp,
    )
    .await?;
    Ok((session, claims.access_stamp))
}

/// The final error is yielded before Storage completes its multipart upload.
fn checked_upload_stream<S, E>(
    stream: S,
    exact_bytes: Option<u64>,
) -> impl Stream<Item = Result<Bytes, AppError>>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: Display,
{
    stream::try_unfold(
        (Box::pin(stream), 0_u64),
        move |(mut stream, total)| async move {
            if let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| {
                    AppError::bad_request(format!(
                        "Invalid upload body: {error}"
                    ))
                })?;
                let total =
                    total.checked_add(chunk.len() as u64).ok_or_else(|| {
                        AppError::bad_request("Send file is too large")
                    })?;
                Ok(Some((chunk, (stream, total))))
            } else {
                if exact_bytes.is_some_and(|expected| total != expected) {
                    return Err(AppError::bad_request(
                        "Send file size does not match fileLength",
                    ));
                }
                Ok(None)
            }
        },
    )
}

pub(super) async fn write_file<S, E>(
    state: &AppState,
    send: &SendDB,
    stream: S,
    exact_bytes: Option<u64>,
    staged_key: &str,
) -> Result<u64, AppError>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: Display,
{
    let maximum = u64::try_from(send.file_size.min(file_max_bytes(&state.env)))
        .map_err(|_error| AppError::bad_request("Invalid Send file size"))?;
    Storage::from_env(&state.env)?
        .put_stream(
            staged_key,
            checked_upload_stream(stream, exact_bytes),
            maximum,
            Some("application/octet-stream"),
        )
        .await
}

fn upload_claims(owner: &UploadSession) -> Claims {
    let now = crate::infra::time::now_seconds();
    Claims {
        sub:           owner.user_id.clone(),
        exp:           now + TOKEN_TTL,
        nbf:           now - 1,
        iat:           now,
        sstamp:        owner.stamp.clone(),
        session_token: owner.session_token.clone(),
        token_use:     "access".into(),
        extensions:    crate::api::service::claims::ClaimsExtensions {
            device: Some(owner.device.clone()),
            ..Default::default()
        },
    }
}

pub(super) async fn upload_key_guard(
    state: &AppState,
    owner: &UploadSession,
) -> Result<D1PreparedStatement, AppError> {
    cipher_mutation::account_key_guard(&state.get_db(), &upload_claims(owner))
        .await
}

pub(super) fn staged_file_key(send: &SendDB) -> Result<String, AppError> {
    Ok(format!(
        "sends/{}/{}/{}",
        send.id,
        send.file_id.as_deref().ok_or_else(inaccessible)?,
        uuid::Uuid::new_v4()
    ))
}

pub(super) async fn finish_file_upload(
    state: &AppState,
    send: &mut SendDB,
    size: u64,
    owner: &UploadSession,
    staged_key: &str,
    key_guard: D1PreparedStatement,
) -> Result<(), AppError> {
    if send.user_id != owner.user_id {
        return Err(inaccessible());
    }
    let size = i64::try_from(size)
        .map_err(|_| AppError::bad_request("Send file is too large"))?;
    let now = now_string();
    let db = state.get_db();
    let revision = cipher_mutation::commit(
        &db,
        &upload_claims(owner),
        vec![key_guard, upload_guard(&db, send)?],
        vec![send.finalize_upload_statement(&db, size, staged_key, &now)?],
    )
    .await?;
    send.file_size = size;
    send.updated_at = now;
    send.storage_key = Some(staged_key.to_string());
    send.pending = 0;
    notify_update(
        state,
        send,
        notifications::UpdateType::SyncSendUpdate,
        Some(&owner.device),
        &revision,
    )
    .await;
    if let Err(error) =
        crate::infra::storage::cleanup::drain(&state.env, &db).await
    {
        log::warn!("Send replaced-object cleanup deferred: {error}");
    }
    Ok(())
}

pub(super) async fn discard_staged_file(state: &AppState, key: &str) {
    crate::infra::storage::cleanup::discard_staged_object(
        &state.env,
        &state.get_db(),
        key,
    )
    .await;
}

pub(super) fn file_max_bytes(env: &Env) -> i64 {
    let backend_max = crate::infra::storage::Storage::max_bytes(env)
        .map_or(MAX_FILE_BYTES, |n| n as i64);
    env.var("SEND_MAX_BYTES")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(MAX_FILE_BYTES)
        .min(backend_max)
}

pub(super) fn user_quota_bytes(env: &Env) -> Option<i64> {
    env.var("USER_SEND_LIMIT_KB")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .and_then(|n| n.checked_mul(1024))
}

pub(super) async fn create_pending_file(
    state: &AppState,
    claims: &Claims,
    payload: &SendRequestData,
) -> Result<SendDB, AppError> {
    let key_guard =
        cipher_mutation::account_key_guard(&state.get_db(), claims).await?;
    if !crate::infra::storage::Storage::enabled(&state.env) {
        return Err(AppError::bad_request("File storage is not enabled"));
    }
    if payload.send_type != 1 {
        return Err(AppError::bad_request("Send must contain a file"));
    }
    let size = payload
        .file_length
        .as_ref()
        .ok_or_else(|| AppError::bad_request("fileLength is required"))?
        .value()?;
    if size < 0 || size > file_max_bytes(&state.env) {
        return Err(AppError::bad_request(
            "Send file size exceeds the configured limit",
        ));
    }
    let mut send = SendDB::new(claims.sub.clone(), payload)?;
    send.file_id = Some(uuid::Uuid::new_v4().to_string());
    send.file_size = size;
    send.pending = 1;
    send.set_password(payload.password.as_deref()).await?;
    insert(
        &state.get_db(),
        &send,
        user_quota_bytes(&state.env),
        claims,
        key_guard,
    )
    .await?;
    Ok(send)
}

pub(super) async fn upload_response(
    state: &AppState,
    send: &SendDB,
    claims: &Claims,
) -> Result<Value, AppError> {
    let token = encode_token(state, send, UPLOAD_SCOPE, Some(claims))?;
    let file_id = send.file_id.as_deref().ok_or(AppError::Internal)?;
    Ok(json!({"object": "send-fileUpload", "fileUploadType": 1,
        "url": format!("{}/api/sends/{}/file/{file_id}/azure-upload?token={token}", state.get_domain().trim_end_matches('/'), send.id),
        "sendResponse": send.to_json()}))
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt as _;

    use super::*;

    #[test]
    fn checked_upload_stream_preserves_binary_chunks_and_allows_unknown_length()
    {
        for exact in [None, Some(6)] {
            let chunks = stream::iter([
                Ok::<_, &str>(Bytes::from_static(&[0, 255, 128])),
                Ok(Bytes::from_static(b"abc")),
            ]);
            let result = checked_upload_stream(chunks, exact)
                .collect::<Vec<_>>()
                .now_or_never()
                .expect("ready input");
            let bytes: Vec<u8> = result
                .into_iter()
                .flat_map(|chunk| chunk.expect("valid chunk"))
                .collect();
            assert_eq!(bytes, [0, 255, 128, b'a', b'b', b'c']);
        }
    }

    #[test]
    fn checked_upload_stream_rejects_wrong_length_and_input_errors_before_commit()
     {
        for exact in [2, 4] {
            let chunks =
                stream::iter([Ok::<_, &str>(Bytes::from_static(b"abc"))]);
            let result = checked_upload_stream(chunks, Some(exact))
                .collect::<Vec<_>>()
                .now_or_never()
                .expect("ready input");
            assert!(result.last().expect("length error").is_err());
        }
        let chunks = stream::iter([Err::<Bytes, _>("broken request stream")]);
        let result = checked_upload_stream(chunks, None)
            .collect::<Vec<_>>()
            .now_or_never()
            .expect("ready input");
        assert!(result[0].is_err());
        let empty = stream::empty::<Result<Bytes, &str>>();
        assert!(
            checked_upload_stream(empty, Some(0))
                .collect::<Vec<_>>()
                .now_or_never()
                .expect("ready input")
                .is_empty()
        );
    }
}
