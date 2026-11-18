//! Owner projections, anonymous authorization and content grants.
use axum::http::HeaderMap;
use serde_json::{
    Value,
    json,
};
use worker::{
    D1Database,
    query,
};

use super::{
    mutation::notify_update,
    token::{
        DOWNLOAD_SCOPE,
        decode_file_token,
        decode_token,
        encode_token,
    },
};
use crate::{
    api::{
        AppState,
        service::{
            notifications,
            rate,
            turnstile,
        },
    },
    errors::AppError,
    infra::{
        db,
        storage::Storage,
    },
    send::types::{
        SendDB,
        inaccessible,
    },
};

pub(super) async fn record_access(
    state: &AppState,
    send: &mut SendDB,
    file_id: Option<&str>,
) -> Result<(), AppError> {
    send.consume_access(&state.get_db(), file_id).await?;
    notify_update(
        state,
        send,
        notifications::UpdateType::SyncSendUpdate,
        None,
        &send.updated_at,
    )
    .await;
    Ok(())
}

pub(super) async fn record_file_metadata_access(
    state: &AppState,
    send: &SendDB,
) -> Result<(), AppError> {
    let revision = send.advance_revision(&state.get_db()).await?;
    notify_update(
        state,
        send,
        notifications::UpdateType::SyncSendUpdate,
        None,
        &revision,
    )
    .await;
    Ok(())
}

pub(super) async fn grant_file_access(
    state: &AppState,
    send: &mut SendDB,
    file_id: &str,
) -> Result<Value, AppError> {
    if send.send_type != 1 {
        return Err(AppError::bad_request("Send is not a file type send"));
    }
    if send.file_id.as_deref() != Some(file_id) {
        return Err(inaccessible());
    }
    let key = send.storage_key().ok_or_else(inaccessible)?;
    if Storage::from_env(&state.env)?.head(&key).await?.is_none() {
        return Err(inaccessible());
    }
    record_access(state, send, Some(file_id)).await?;
    download_response(state, send, file_id)
}

pub(super) async fn download_file(
    state: &AppState,
    token: &str,
    send_id: &str,
    file_id: &str,
    headers: &HeaderMap,
    head: bool,
) -> Result<axum::response::Response, AppError> {
    let claims = decode_file_token(
        &state.config.jwt_secret,
        token,
        DOWNLOAD_SCOPE,
        send_id,
        file_id,
    )?;
    let send = SendDB::find_by_id(&state.get_db(), send_id).await?;
    send.validate_access(false)?;
    if send.file_id.as_deref() != Some(file_id) ||
        send.access_stamp != claims.access_stamp
    {
        return Err(inaccessible());
    }
    let key = send.storage_key().ok_or_else(inaccessible)?;
    let mut response = Storage::from_env(&state.env)?
        .download(&key, headers, head)
        .await?;
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        "application/octet-stream".parse().expect("static header"),
    );
    headers.insert(
        "content-disposition",
        "attachment; filename=\"send-file\""
            .parse()
            .expect("static header"),
    );
    headers.insert(
        "cache-control",
        "private, no-store".parse().expect("static header"),
    );
    headers.insert(
        "x-content-type-options",
        "nosniff".parse().expect("static header"),
    );
    Ok(response)
}

pub(super) async fn send_from_access_token(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<SendDB, AppError> {
    let claims = decode_token(state, headers)?;
    let send = SendDB::find_by_id(&state.get_db(), &claims.send_id).await?;
    // Metadata reads do not consume a file download. Actual content grants
    // count atomically after validating the referenced file.
    send.validate_access(false)?;
    if claims.access_stamp != send.access_stamp {
        return Err(inaccessible());
    }
    Ok(send)
}

pub(super) async fn authorize_anonymous(
    state: &AppState,
    headers: &HeaderMap,
    send: &SendDB,
    password: Option<&str>,
) -> Result<(), AppError> {
    turnstile::verify_send_access(state, headers, &send.id).await?;
    send.validate_access(true)?;
    rate::check_send_access_rate_limit(
        state,
        format!("send:{}:{}", send.id, rate::client_ip(headers)),
    )
    .await?;
    send.check_password(password).await
}

pub(crate) async fn list_json(
    db: &D1Database,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    Ok(SendDB::list_for_user(db, user_id)
        .await?
        .iter()
        .map(SendDB::to_json)
        .collect())
}

pub(super) async fn access_response(
    state: &AppState,
    send: &SendDB,
) -> Result<Value, AppError> {
    let db = state.get_db();
    let email: Option<String> = if send.hide_email == 0 {
        db::run_query(
            async {
                query!(
                    &db,
                    "SELECT email FROM users WHERE id=?1",
                    send.user_id
                )?
                .first(Some("email"))
                .await
            },
            "Failed to fetch Send creator",
        )
        .await?
    } else {
        None
    };
    Ok(send.to_access_json(email.as_deref()))
}

pub(super) fn download_response(
    state: &AppState,
    send: &SendDB,
    file_id: &str,
) -> Result<Value, AppError> {
    if send.send_type != 1 || send.file_id.as_deref() != Some(file_id) {
        return Err(inaccessible());
    }
    let token = encode_token(state, send, DOWNLOAD_SCOPE, None)?;
    Ok(json!({"id": file_id,
        "url": format!("{}/api/sends/{}/{file_id}?t={token}", state.get_domain().trim_end_matches('/'), send.id),
        "object": "send-fileDownload"}))
}
