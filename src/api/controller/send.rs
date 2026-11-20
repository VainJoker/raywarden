//! Send HTTP extraction, uploads and responses.
pub(in crate::api) mod turnstile;
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
        HeaderValue,
        Method,
        StatusCode,
        header,
    },
    response::Response,
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;

use crate::{
    api::{
        AppState,
        common::response::{
            ApiResponse,
            EmptyObject,
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    models::send::SendRow,
    service::{
        identity::session::Claims,
        send::{
            self,
            SendAccess,
            SendFileDownloadResponse,
            SendOwner,
            content::{
                self,
                SendAccessResponse,
                SendRequest,
                SendResponse,
                decode_access_id,
            },
            upload,
        },
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct SendListResponse {
    data:               Vec<SendResponse>,
    continuation_token: Option<String>,
    object:             &'static str,
}

async fn next_file_field(multipart: &mut Multipart) -> AppResult<Field<'_>> {
    let field = multipart
        .next_field()
        .await
        .map_err(AppError::invalid_multipart)?
        .ok_or_else(|| AppError::bad_request("The file field is missing"))?;
    if !matches!(field.name(), Some("data" | "file")) {
        return Err(AppError::bad_request("A file field is required"));
    }
    Ok(field)
}

async fn require_last_field(multipart: &mut Multipart) -> AppResult<()> {
    if multipart
        .next_field()
        .await
        .map_err(AppError::invalid_multipart)?
        .is_some()
    {
        return Err(AppError::bad_request("Only one file field is allowed"));
    }
    Ok(())
}

fn validate_file_name(
    send: &SendRow,
    filename: Option<&str>,
    headers: &HeaderMap,
) -> AppResult<()> {
    let filename = filename.ok_or_else(|| {
        AppError::bad_request("Send file name is not provided")
    })?;
    let data: Value =
        serde_json::from_str(&send.data).map_err(AppError::internal_error)?;
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

#[derive(Deserialize)]
pub(in crate::api) struct UploadTokenQuery {
    token: Option<String>,
}

#[worker::send]
pub(in crate::api) async fn upload_send_file_with_token(
    State(state): State<AppState>,
    Path((id, file_id)): Path<(String, String)>,
    Query(query): Query<UploadTokenQuery>,
    headers: HeaderMap,
    body: Body,
) -> AppResult<StatusCode> {
    let token =
        query
            .token
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized {
                message: "Invalid upload token".into(),
            })?;
    let (session, send) = upload::UploadSession::authorize_token_upload(
        &state, token, &id, &file_id,
    )
    .await?;
    let mut upload =
        upload::SendUpload::prepare(&state, &send, &session).await?;
    let result = async {
        if let Some(length) = headers.get("content-length") {
            let length = length
                .to_str()
                .ok()
                .filter(|value| {
                    !value.is_empty() &&
                        value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|value| value.parse::<u64>().ok());
            if length != Some(upload.expected_bytes()) {
                return Err(AppError::bad_request(
                    "Content-Length does not match fileLength",
                ));
            }
        }
        upload.write(body.into_data_stream()).await
    }
    .await;
    match result {
        Ok(()) => upload.commit().await?,
        Err(error) => {
            upload.abort().await;
            return Err(error);
        }
    }
    Ok(StatusCode::CREATED)
}

#[worker::send]
pub(in crate::api) async fn upload_send_file_multipart(
    claims: Claims,
    State(state): State<AppState>,
    Path((id, file_id)): Path<(String, String)>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> AppResult<StatusCode> {
    let session = upload::UploadSession::from_claims(&claims)?;
    let send = session.fetch_uploadable_send(&state, &id, &file_id).await?;
    let mut upload =
        upload::SendUpload::prepare(&state, &send, &session).await?;
    let result = async {
        let field = next_file_field(&mut multipart).await?;
        validate_file_name(&send, field.file_name(), &headers)?;
        upload.write(field).await?;
        require_last_field(&mut multipart).await
    }
    .await;
    match result {
        Ok(()) => upload.commit().await?,
        Err(error) => {
            upload.abort().await;
            return Err(error);
        }
    }
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
pub(in crate::api) struct DownloadTokenQuery {
    #[serde(rename = "t")]
    token: Option<String>,
}

#[worker::send]
pub(in crate::api) async fn download_send_file(
    State(state): State<AppState>,
    Path((id, file_id)): Path<(String, String)>,
    Query(query): Query<DownloadTokenQuery>,
    headers: HeaderMap,
    method: Method,
) -> AppResult<Response> {
    let token = query
        .token
        .as_deref()
        .ok_or_else(AppError::send_unavailable)?;
    let key =
        send::authorize_file_download(&state, token, &id, &file_id).await?;
    let storage = crate::infra::storage::Storage::from_env(&state.env)?;
    let mut response = crate::api::common::download::download(
        &storage,
        &key,
        &headers,
        method == Method::HEAD,
    )
    .await?;
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"send-file\""),
    );
    Ok(response)
}

#[worker::send]
pub(in crate::api) async fn list_sends(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<SendListResponse>> {
    let data = SendOwner::new(&state, &claims).list().await?;
    Ok(ApiResponse(SendListResponse {
        data,
        continuation_token: None,
        object: "list",
    }))
}

#[worker::send]
pub(in crate::api) async fn get_send(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<SendResponse>> {
    let send = SendOwner::new(&state, &claims).get(&id).await?;
    Ok(ApiResponse(content::send_response(send)))
}

#[worker::send]
pub(in crate::api) async fn create_text_send(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<SendRequest>,
) -> AppResult<ApiResponse<SendResponse>> {
    let send = SendOwner::new(&state, &claims)
        .create_text(&payload)
        .await?;
    Ok(ApiResponse(content::send_response(send)))
}

#[worker::send]
pub(in crate::api) async fn reserve_send_file_upload(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<SendRequest>,
) -> AppResult<ApiResponse<upload::SendFileUploadResponse>> {
    let response = SendOwner::new(&state, &claims)
        .reserve_file_upload(&payload)
        .await?;
    Ok(ApiResponse(response))
}

#[worker::send]
pub(in crate::api) async fn update_send(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<SendRequest>,
) -> AppResult<ApiResponse<SendResponse>> {
    let send = SendOwner::new(&state, &claims).update(&id, payload).await?;
    Ok(ApiResponse(content::send_response(send)))
}

#[worker::send]
pub(in crate::api) async fn delete_send(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<EmptyObject>> {
    SendOwner::new(&state, &claims).delete(&id).await?;
    Ok(ApiResponse(EmptyObject {}))
}

#[worker::send]
pub(in crate::api) async fn remove_password(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<SendResponse>> {
    let send = SendOwner::new(&state, &claims).remove_password(&id).await?;
    Ok(ApiResponse(content::send_response(send)))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct SendAccessRequest {
    password: Option<String>,
}

#[worker::send]
pub(in crate::api) async fn access_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(access_id): Path<String>,
    Json(payload): Json<SendAccessRequest>,
) -> AppResult<ApiResponse<SendAccessResponse>> {
    let id = decode_access_id(&access_id)?;
    let access = SendAccess::anonymous(
        &state,
        &headers,
        &id,
        None,
        payload.password.as_deref(),
    )
    .await?;
    Ok(ApiResponse(access.read().await?))
}

#[worker::send]
pub(in crate::api) async fn grant_send_file_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, file_id)): Path<(String, String)>,
    Json(payload): Json<SendAccessRequest>,
) -> AppResult<ApiResponse<SendFileDownloadResponse>> {
    let access = SendAccess::anonymous(
        &state,
        &headers,
        &id,
        Some(&file_id),
        payload.password.as_deref(),
    )
    .await?;
    Ok(ApiResponse(access.grant_file(&file_id).await?))
}

#[worker::send]
pub(in crate::api) async fn access_send_with_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<ApiResponse<SendAccessResponse>> {
    let access = SendAccess::with_token(&state, &headers).await?;
    Ok(ApiResponse(access.read().await?))
}

#[worker::send]
pub(in crate::api) async fn grant_send_file_access_with_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> AppResult<ApiResponse<SendFileDownloadResponse>> {
    let access = SendAccess::with_token(&state, &headers).await?;
    Ok(ApiResponse(access.grant_file(&file_id).await?))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn upload_filename_matches_metadata_with_only_the_cli_suffix_exception() {
        let payload: SendRequest = serde_json::from_value(json!({"type":1,
            "name":"encrypted","key":"wrapped","file":{"fileName":"encrypted-file"},
            "deletionDate":crate::utils::time::format_millis(crate::utils::time::now() + jiff::SignedDuration::from_secs(86_400))})).expect("payload");
        let send = content::new_send(
            "owner".into(),
            &payload,
            content::MAX_TEXT_SIZE_BYTES,
        )
        .expect("send");
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
}
