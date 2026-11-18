//! HTTP extraction, multipart handling and Send response mapping.
use axum::{
    Json,
    body::Body,
    extract::{
        Multipart,
        Path,
        Query,
        State,
        multipart::Field,
    },
    http::{
        HeaderMap,
        Method,
        StatusCode,
    },
    response::Response,
};
use bytes::BytesMut;
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};

use super::{
    access,
    mutation,
    upload,
};
use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::AppError,
    send::types::{
        NumberOrString,
        SendDB,
        SendRequestData,
        inaccessible,
        now_string,
        uuid_from_access_id,
        validate_send_dates,
    },
};

const MAX_MODEL_BYTES: usize = 2 * 1024 * 1024;

async fn next_file_field(
    multipart: &mut Multipart,
) -> Result<Field<'_>, AppError> {
    let field = multipart
        .next_field()
        .await
        .map_err(|error| {
            AppError::bad_request(format!("Invalid multipart body: {error}"))
        })?
        .ok_or_else(|| AppError::bad_request("The file field is missing"))?;
    if !matches!(field.name(), Some("data" | "file")) {
        return Err(AppError::bad_request("A file field is required"));
    }
    Ok(field)
}

async fn require_last_field(multipart: &mut Multipart) -> Result<(), AppError> {
    if multipart
        .next_field()
        .await
        .map_err(|error| {
            AppError::bad_request(format!("Invalid multipart body: {error}"))
        })?
        .is_some()
    {
        return Err(AppError::bad_request("Only one file field is allowed"));
    }
    Ok(())
}

async fn read_file_model(
    multipart: &mut Multipart,
    maximum: i64,
) -> Result<(SendRequestData, Option<u64>), AppError> {
    let mut field = multipart
        .next_field()
        .await
        .map_err(|error| {
            AppError::bad_request(format!("Invalid multipart body: {error}"))
        })?
        .ok_or_else(|| {
            AppError::bad_request("The Send model must precede the file field")
        })?;
    if field.name() != Some("model") {
        return Err(AppError::bad_request(
            "The Send model must precede the file field",
        ));
    }
    let mut bytes = BytesMut::new();
    while let Some(chunk) = field.chunk().await.map_err(|error| {
        AppError::bad_request(format!("Invalid Send model: {error}"))
    })? {
        if chunk.len() > MAX_MODEL_BYTES.saturating_sub(bytes.len()) {
            return Err(AppError::bad_request("Send model is too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let mut model: Value = serde_json::from_slice(&bytes)
        .map_err(|_error| AppError::bad_request("Invalid Send model"))?;
    let object = model
        .as_object_mut()
        .ok_or_else(|| AppError::bad_request("Invalid Send model"))?;
    let declared = object
        .get("fileLength")
        .filter(|value| !value.is_null())
        .or_else(|| object.get("FileLength").filter(|value| !value.is_null()))
        .cloned();
    object.insert(
        "fileLength".into(),
        declared.clone().unwrap_or_else(|| json!(maximum)),
    );
    let payload: SendRequestData = serde_json::from_value(model)
        .map_err(|_error| AppError::bad_request("Invalid Send model"))?;
    let exact = declared
        .map(|value| {
            let value: NumberOrString =
                serde_json::from_value(value).map_err(|_error| {
                    AppError::bad_request("Invalid fileLength")
                })?;
            u64::try_from(value.value()?)
                .map_err(|_error| AppError::bad_request("Invalid fileLength"))
        })
        .transpose()?;
    Ok((payload, exact))
}

fn validate_file_name(
    send: &SendDB,
    filename: Option<&str>,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    let filename = filename.ok_or_else(|| {
        AppError::bad_request("Send file name is not provided")
    })?;
    let data: Value =
        serde_json::from_str(&send.data).map_err(|_| AppError::Internal)?;
    let expected = data
        .get("fileName")
        .and_then(Value::as_str)
        .unwrap_or("file");
    let cli = headers
        .get("device-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i32>().ok())
        .is_some_and(|value| (23..=25).contains(&value));
    if filename != expected && !(cli && expected.ends_with(filename)) {
        return Err(AppError::bad_request("Send file name does not match"));
    }
    Ok(())
}

async fn upload_multipart_file(
    state: &AppState,
    multipart: &mut Multipart,
    mut pending: SendDB,
    owner: &upload::UploadSession,
    exact_bytes: Option<u64>,
    headers: &HeaderMap,
) -> Result<SendDB, AppError> {
    let key_guard = upload::upload_key_guard(state, owner).await?;
    let staged_key = upload::staged_file_key(&pending)?;
    let result = async {
        let field = next_file_field(multipart).await?;
        validate_file_name(&pending, field.file_name(), headers)?;
        let size = upload::write_file(
            state,
            &pending,
            field,
            exact_bytes,
            &staged_key,
        )
        .await?;
        require_last_field(multipart).await?;
        upload::finish_file_upload(
            state,
            &mut pending,
            size,
            owner,
            &staged_key,
            key_guard,
        )
        .await
    }
    .await;
    if result.is_err() {
        upload::discard_staged_file(state, &staged_key).await;
    }
    result?;
    Ok(pending)
}

#[derive(Deserialize)]
pub(super) struct UploadQuery {
    token: Option<String>,
}

#[worker::send]
pub(super) async fn upload_file_send_azure(
    State(state): State<AppState>,
    Path((id, file_id)): Path<(String, String)>,
    Query(query): Query<UploadQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, AppError> {
    let token =
        query
            .token
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized {
                message: "Invalid upload token".into(),
            })?;
    let (owner, stamp) =
        upload::upload_session(&state, token, &id, &file_id).await?;
    let mut pending = SendDB::find_by_id(&state.get_db(), &id).await?;
    if pending.user_id != owner.user_id ||
        pending.file_id.as_deref() != Some(&file_id) ||
        pending.access_stamp != stamp ||
        !matches!(pending.pending, 0 | 1)
    {
        return Err(inaccessible());
    }
    let key_guard = upload::upload_key_guard(&state, &owner).await?;
    let staged_key = upload::staged_file_key(&pending)?;
    let result = async {
        let expected = u64::try_from(pending.file_size).map_err(|_error| {
            AppError::bad_request("Invalid Send file size")
        })?;
        if let Some(length) = headers.get("content-length") {
            let length = length
                .to_str()
                .ok()
                .filter(|value| {
                    !value.is_empty() &&
                        value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|value| value.parse::<u64>().ok());
            if length != Some(expected) {
                return Err(AppError::bad_request(
                    "Content-Length does not match fileLength",
                ));
            }
        }
        let size = upload::write_file(
            &state,
            &pending,
            body.into_data_stream(),
            Some(expected),
            &staged_key,
        )
        .await?;
        upload::finish_file_upload(
            &state,
            &mut pending,
            size,
            &owner,
            &staged_key,
            key_guard,
        )
        .await
    }
    .await;
    if result.is_err() {
        upload::discard_staged_file(&state, &staged_key).await;
    }
    result?;
    Ok(StatusCode::CREATED)
}

#[worker::send]
pub(super) async fn upload_file_send_direct(
    claims: Claims,
    State(state): State<AppState>,
    Path((id, file_id)): Path<(String, String)>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<StatusCode, AppError> {
    let owner = upload::UploadSession::from_claims(&claims)?;
    let pending = SendDB::find_by_id(&state.get_db(), &id).await?;
    if pending.user_id != claims.sub ||
        !matches!(pending.pending, 0 | 1) ||
        pending.file_id.as_deref() != Some(&file_id)
    {
        return Err(AppError::not_found("Pending Send not found"));
    }
    let exact = u64::try_from(pending.file_size)
        .map_err(|_error| AppError::bad_request("Invalid Send file size"))?;
    upload_multipart_file(
        &state,
        &mut multipart,
        pending,
        &owner,
        Some(exact),
        &headers,
    )
    .await?;
    Ok(StatusCode::CREATED)
}

#[worker::send]
pub(super) async fn create_file_send_legacy(
    claims: Claims,
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let owner = upload::UploadSession::from_claims(&claims)?;
    let (payload, exact) =
        read_file_model(&mut multipart, upload::file_max_bytes(&state.env))
            .await?;
    let pending =
        upload::create_pending_file(&state, &claims, &payload).await?;
    match upload_multipart_file(
        &state,
        &mut multipart,
        pending.clone(),
        &owner,
        exact,
        &headers,
    )
    .await
    {
        Ok(send) => Ok(Json(send.to_json())),
        Err(error) => {
            if let Err(cleanup) = pending.delete_pending(&state.get_db()).await
            {
                log::warn!(
                    "Failed to discard legacy Send reservation: {cleanup}"
                );
            }
            Err(error)
        }
    }
}

#[derive(Deserialize)]
pub(super) struct DownloadQuery {
    t: Option<String>,
}

#[worker::send]
pub(super) async fn download_file_send(
    State(state): State<AppState>,
    Path((id, file_id)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, AppError> {
    let token = query.t.as_deref().ok_or_else(inaccessible)?;
    access::download_file(
        &state,
        token,
        &id,
        &file_id,
        &headers,
        method == Method::HEAD,
    )
    .await
}

#[worker::send]
pub(super) async fn list_sends(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(
        json!({"data": access::list_json(&state.get_db(), &claims.sub).await?, "continuationToken": null, "object": "list"}),
    ))
}

#[worker::send]
pub(super) async fn get_send(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(
        SendDB::get_for_user(&state.get_db(), &id, &claims.sub)
            .await?
            .to_json(),
    ))
}

#[worker::send]
pub(super) async fn create_text_send(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<SendRequestData>,
) -> Result<Json<Value>, AppError> {
    if payload.send_type != 0 {
        return Err(AppError::bad_request(
            "Use the file upload endpoint for file Sends",
        ));
    }
    let db = state.get_db();
    let key_guard =
        crate::api::service::cipher_mutation::account_key_guard(&db, &claims)
            .await?;
    let mut send = SendDB::new(claims.sub.clone(), &payload)?;
    send.set_password(payload.password.as_deref()).await?;
    mutation::insert(&db, &send, None, &claims, key_guard).await?;
    mutation::notify_update(
        &state,
        &send,
        crate::api::service::notifications::UpdateType::SyncSendCreate,
        claims.device(),
        &send.updated_at,
    )
    .await;
    Ok(Json(send.to_json()))
}

#[worker::send]
pub(super) async fn create_file_send_v2(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<SendRequestData>,
) -> Result<Json<Value>, AppError> {
    let send = upload::create_pending_file(&state, &claims, &payload).await?;
    Ok(Json(upload::upload_response(&state, &send, &claims).await?))
}

#[worker::send]
pub(super) async fn update_send(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<SendRequestData>,
) -> Result<Json<Value>, AppError> {
    payload.validate()?;
    let (deletion, expiration) = validate_send_dates(
        &payload.deletion_date,
        payload.expiration_date.as_deref(),
    )?;
    let db = state.get_db();
    let key_guard =
        crate::api::service::cipher_mutation::account_key_guard(&db, &claims)
            .await?;
    let existing = SendDB::get_for_user(&db, &id, &claims.sub).await?;
    let mut send = existing.clone();
    if payload.send_type != send.send_type {
        return Err(AppError::bad_request("Send type cannot change"));
    }
    if send.send_type == 0 {
        send.data = serde_json::to_string(&payload.content()?)
            .map_err(|_error| AppError::Internal)?;
    }
    send.name = payload.name;
    send.notes = payload.notes;
    send.akey = payload.key;
    send.max_access_count = payload
        .max_access_count
        .as_ref()
        .map(NumberOrString::value)
        .transpose()?;
    send.expiration_date = expiration;
    send.deletion_date = deletion;
    send.disabled = i32::from(payload.disabled.unwrap_or(false));
    send.hide_email = i32::from(payload.hide_email.unwrap_or(false));
    send.updated_at = now_string();
    send.access_stamp = uuid::Uuid::new_v4().to_string();
    if let Some(password) = payload.password.as_deref() {
        send.set_password(Some(password)).await?;
    }
    let revision = crate::api::service::cipher_mutation::commit(
        &db,
        &claims,
        vec![key_guard, mutation::snapshot_guard(&db, &existing)?],
        vec![send.update_statement(&db)?],
    )
    .await?;
    mutation::notify_update(
        &state,
        &send,
        crate::api::service::notifications::UpdateType::SyncSendUpdate,
        claims.device(),
        &revision,
    )
    .await;
    Ok(Json(send.to_json()))
}

#[worker::send]
pub(super) async fn delete_send(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    // Pending uploads can also be cancelled by their owner.
    let send = SendDB::find_by_id(&db, &id).await?;
    if send.user_id != claims.sub {
        return Err(inaccessible());
    }
    let revision = crate::api::service::cipher_mutation::commit(
        &db,
        &claims,
        vec![mutation::snapshot_guard(&db, &send)?],
        vec![send.delete_statement(&db)?],
    )
    .await?;
    mutation::notify_update(
        &state,
        &send,
        crate::api::service::notifications::UpdateType::SyncSendDelete,
        claims.device(),
        &revision,
    )
    .await;
    if let Err(error) =
        crate::infra::storage::cleanup::drain(&state.env, &db).await
    {
        log::warn!("Send deletion cleanup deferred: {error}");
    }
    Ok(Json(json!({})))
}

#[worker::send]
pub(super) async fn remove_password(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let existing = SendDB::get_for_user(&db, &id, &claims.sub).await?;
    let mut send = existing.clone();
    send.set_password(None).await?;
    send.access_stamp = uuid::Uuid::new_v4().to_string();
    send.updated_at = now_string();
    let revision = crate::api::service::cipher_mutation::commit(
        &db,
        &claims,
        vec![mutation::snapshot_guard(&db, &existing)?],
        vec![send.update_statement(&db)?],
    )
    .await?;
    mutation::notify_update(
        &state,
        &send,
        crate::api::service::notifications::UpdateType::SyncSendUpdate,
        claims.device(),
        &revision,
    )
    .await;
    Ok(Json(send.to_json()))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct SendAccessRequest {
    pub password: Option<String>,
}

#[worker::send]
pub(super) async fn access_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(access_id): Path<String>,
    Json(payload): Json<SendAccessRequest>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let id = uuid_from_access_id(&access_id)?;
    let mut send = SendDB::find_by_id(&db, &id).await?;
    access::authorize_anonymous(
        &state,
        &headers,
        &send,
        payload.password.as_deref(),
    )
    .await?;
    if send.send_type == 0 {
        access::record_access(&state, &mut send, None).await?;
    }
    Ok(Json(access::access_response(&state, &send).await?))
}

#[worker::send]
pub(super) async fn access_file_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, file_id)): Path<(String, String)>,
    Json(payload): Json<SendAccessRequest>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let mut send = SendDB::find_by_id(&db, &id).await?;
    if send.send_type != 1 || send.file_id.as_deref() != Some(&file_id) {
        return Err(inaccessible());
    }
    access::authorize_anonymous(
        &state,
        &headers,
        &send,
        payload.password.as_deref(),
    )
    .await?;
    Ok(Json(
        access::grant_file_access(&state, &mut send, &file_id).await?,
    ))
}

#[worker::send]
pub(super) async fn access_send_with_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let mut send = access::send_from_access_token(&state, &headers).await?;
    if send.send_type == 0 {
        access::record_access(&state, &mut send, None).await?;
    } else {
        access::record_file_metadata_access(&state, &send).await?;
    }
    Ok(Json(access::access_response(&state, &send).await?))
}

#[worker::send]
pub(super) async fn access_file_send_with_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let mut send = access::send_from_access_token(&state, &headers).await?;
    Ok(Json(
        access::grant_file_access(&state, &mut send, &file_id).await?,
    ))
}

#[cfg(test)]
mod tests {
    use axum::extract::FromRequest as _;
    use bytes::Bytes;
    use futures_util::{
        FutureExt as _,
        StreamExt as _,
        stream,
    };

    use super::*;

    fn parse_multipart(body: String) -> Multipart {
        let chunks: Vec<_> = body
            .as_bytes()
            .chunks(7)
            .map(|chunk| {
                Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(chunk))
            })
            .collect();
        let request = axum::http::Request::builder()
            .header(
                "content-type",
                "multipart/form-data; boundary=split-boundary",
            )
            .body(Body::from_stream(stream::iter(chunks)))
            .expect("request");
        Multipart::from_request(request, &())
            .now_or_never()
            .expect("ready request")
            .expect("multipart")
    }

    fn model(length: Option<Value>) -> Value {
        let mut model = json!({"type":1,"name":"encrypted","key":"key",
            "file":{"fileName":"encrypted-name"},"deletionDate":"2999-01-01T00:00:00Z"});
        if let Some(length) = length {
            model["FileLength"] = length;
        }
        model
    }

    fn legacy_body(model: &Value, extra: bool) -> String {
        format!(
            concat!(
                "--split-boundary\r\n",
                "Content-Disposition: form-data; name=\"model\"\r\n\r\n",
                "{}\r\n--split-boundary\r\n",
                "Content-Disposition: form-data; name=\"data\"; ",
                "filename=\"encrypted\"\r\n\r\n",
                "密文\0binary{}\r\n--split-boundary--\r\n"
            ),
            model,
            if extra {
                concat!(
                    "\r\n--split-boundary\r\n",
                    "Content-Disposition: form-data; name=\"file\"\r\n\r\n",
                    "extra"
                )
            } else {
                ""
            }
        )
    }

    #[test]
    fn upload_filename_matches_metadata_with_only_the_cli_suffix_exception() {
        let payload: SendRequestData = serde_json::from_value(json!({"type":1,
            "name":"encrypted","key":"wrapped","file":{"fileName":"encrypted-file"},
            "deletionDate":crate::infra::time::format_millis(crate::infra::time::now() + jiff::SignedDuration::from_secs(86_400))})).expect("payload");
        let send = SendDB::new("owner".into(), &payload).expect("send");
        let mut headers = HeaderMap::new();
        assert!(validate_file_name(&send, None, &headers).is_err());
        assert!(validate_file_name(&send, Some("file"), &headers).is_err());
        assert!(
            validate_file_name(&send, Some("encrypted-file"), &headers).is_ok()
        );
        headers.insert("device-type", "23".parse().expect("header"));
        assert!(validate_file_name(&send, Some("file"), &headers).is_ok());
        assert!(validate_file_name(&send, Some("wrong"), &headers).is_err());
    }

    #[test]
    fn legacy_model_accepts_old_length_alias_and_reserves_missing_length() {
        for (declared, expected, exact) in
            [(Some(json!("13")), 13, Some(13)), (None, 95, None)]
        {
            let mut multipart =
                parse_multipart(legacy_body(&model(declared), false));
            let (payload, actual_exact) = read_file_model(&mut multipart, 95)
                .now_or_never()
                .expect("ready model")
                .expect("valid model");
            assert_eq!(
                payload
                    .file_length
                    .expect("reservation")
                    .value()
                    .expect("number"),
                expected
            );
            assert_eq!(actual_exact, exact);
        }
    }

    #[test]
    fn multipart_preserves_binary_data_and_rejects_additional_fields_before_publication()
     {
        for extra in [false, true] {
            let mut multipart =
                parse_multipart(legacy_body(&model(None), extra));
            read_file_model(&mut multipart, 95)
                .now_or_never()
                .expect("ready model")
                .expect("valid model");
            let field = next_file_field(&mut multipart)
                .now_or_never()
                .expect("ready file")
                .expect("file");
            let chunks = field
                .collect::<Vec<_>>()
                .now_or_never()
                .expect("ready bytes");
            let bytes: Vec<u8> = chunks
                .into_iter()
                .flat_map(|chunk| chunk.expect("chunk"))
                .collect();
            assert_eq!(bytes, "密文\0binary".as_bytes());
            let last = require_last_field(&mut multipart)
                .now_or_never()
                .expect("ready tail");
            assert_eq!(last.is_err(), extra);
        }
    }

    #[test]
    fn multipart_rejects_file_before_model_and_missing_file() {
        let mut multipart = parse_multipart(
            "--split-boundary\r\nContent-Disposition: form-data; \
             name=\"data\"\r\n\r\nfile\r\n--split-boundary--\r\n"
                .into(),
        );
        assert!(
            read_file_model(&mut multipart, 95)
                .now_or_never()
                .expect("ready")
                .is_err()
        );
        let mut multipart = parse_multipart(format!(
            "--split-boundary\r\nContent-Disposition: form-data; \
             name=\"model\"\r\n\r\n{}\r\n--split-boundary--\r\n",
            model(None)
        ));
        read_file_model(&mut multipart, 95)
            .now_or_never()
            .expect("ready")
            .expect("model");
        assert!(
            next_file_field(&mut multipart)
                .now_or_never()
                .expect("ready")
                .is_err()
        );
    }
}
