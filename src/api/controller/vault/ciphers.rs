//! Cipher CRUD, archive and import HTTP handlers.
use axum::{
    Json,
    extract::{
        Path,
        RawQuery,
        State,
    },
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    api::{
        AppState,
        common::response::{
            ApiResponse,
            RawJson,
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    models::vault::cipher::{
        CipherMutation,
        CipherRow,
    },
    service::{
        identity::{
            session::Claims,
            user::AccountVerificationRequest,
        },
        vault::{
            attachment,
            cipher::{
                self,
                CipherRequest,
                CipherResponse,
                CipherSelection,
                CreateCipherWithCollectionsRequest,
                UpdateCipherPartialRequest,
                mutate_selected,
                parse_cipher_selection,
            },
            import::{
                self,
                ImportRequest,
            },
        },
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct CipherListResponse {
    data:               Vec<CipherResponse>,
    object:             &'static str,
    continuation_token: Option<String>,
}

impl CipherListResponse {
    const fn new(data: Vec<CipherResponse>) -> Self {
        Self {
            data,
            object: "list",
            continuation_token: None,
        }
    }
}

#[worker::send]
pub(in crate::api) async fn create_cipher_with_collections(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateCipherWithCollectionsRequest>,
) -> AppResult<ApiResponse<CipherResponse>> {
    if !payload.collection_ids.is_empty() {
        return Err(AppError::bad_request("Collections are not supported"));
    }
    Ok(ApiResponse(
        cipher::save_cipher(&claims, &state, None, payload.cipher).await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn create_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CipherRequest>,
) -> AppResult<ApiResponse<CipherResponse>> {
    Ok(ApiResponse(
        cipher::save_cipher(&claims, &state, None, payload).await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn update_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequest>,
) -> AppResult<ApiResponse<CipherResponse>> {
    Ok(ApiResponse(
        cipher::save_cipher(&claims, &state, Some(id), payload).await?,
    ))
}

#[worker::send]
pub(in crate::api) async fn list_ciphers(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<RawJson> {
    let data = cipher::list_cipher_responses_json(
        state.database(),
        &claims.sub,
        attachment::is_enabled(&state.env),
        true,
        true,
        state.domain(),
    )
    .await?;
    Ok(RawJson(format!(
        r#"{{"data":{data},"object":"list","continuationToken":null}}"#
    )))
}
#[worker::send]
pub(in crate::api) async fn get_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<CipherResponse>> {
    let db = state.database();
    let mut cipher = CipherRow::fetch_for_user(db, &id, &claims.sub)
        .await?
        .try_into()?;
    attachment::hydrate_cipher_attachments(&state, &mut cipher).await?;
    Ok(ApiResponse(cipher))
}
#[worker::send]
pub(in crate::api) async fn update_cipher_partial(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateCipherPartialRequest>,
) -> AppResult<ApiResponse<CipherResponse>> {
    Ok(ApiResponse(
        cipher::update_cipher_partial(&claims, &state, id, payload).await?,
    ))
}

#[worker::send]
pub(in crate::api) async fn soft_delete_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<()>> {
    mutate_selected(
        &claims,
        &state,
        CipherSelection::Single(id),
        CipherMutation::SoftDelete,
    )
    .await?;
    Ok(ApiResponse(()))
}
#[worker::send]
pub(in crate::api) async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> AppResult<ApiResponse<()>> {
    mutate_selected(
        &claims,
        &state,
        CipherSelection::Bulk(parse_cipher_selection(&body)?.ids),
        CipherMutation::SoftDelete,
    )
    .await?;
    Ok(ApiResponse(()))
}
#[worker::send]
pub(in crate::api) async fn hard_delete_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<()>> {
    mutate_selected(
        &claims,
        &state,
        CipherSelection::Single(id),
        CipherMutation::HardDelete,
    )
    .await?;
    Ok(ApiResponse(()))
}
#[worker::send]
pub(in crate::api) async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> AppResult<ApiResponse<()>> {
    mutate_selected(
        &claims,
        &state,
        CipherSelection::Bulk(parse_cipher_selection(&body)?.ids),
        CipherMutation::HardDelete,
    )
    .await?;
    Ok(ApiResponse(()))
}
#[worker::send]
pub(in crate::api) async fn restore_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<CipherResponse>> {
    mutate_one(claims, state, id, CipherMutation::Restore).await
}
#[worker::send]
pub(in crate::api) async fn restore_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> AppResult<ApiResponse<CipherListResponse>> {
    let rows = mutate_selected(
        &claims,
        &state,
        CipherSelection::Bulk(parse_cipher_selection(&body)?.ids),
        CipherMutation::Restore,
    )
    .await?;
    Ok(ApiResponse(CipherListResponse::new(rows)))
}
#[worker::send]
pub(in crate::api) async fn move_ciphers(
    claims: Claims,
    State(state): State<AppState>,
    body: String,
) -> AppResult<ApiResponse<()>> {
    let selection = parse_cipher_selection(&body)?;
    mutate_selected(
        &claims,
        &state,
        CipherSelection::Bulk(selection.ids),
        CipherMutation::Move {
            folder_id: selection.folder_id,
        },
    )
    .await?;
    Ok(ApiResponse(()))
}

#[worker::send]
pub(in crate::api) async fn purge_vault(
    claims: Claims,
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<()>> {
    cipher::purge_vault(&claims, &state, query.as_deref(), payload).await?;
    Ok(ApiResponse(()))
}

#[derive(Deserialize)]
pub(in crate::api) struct ArchiveRequest {
    ids: Vec<String>,
}
async fn mutate_one(
    claims: Claims,
    state: AppState,
    id: String,
    kind: CipherMutation,
) -> AppResult<ApiResponse<CipherResponse>> {
    Ok(ApiResponse(
        mutate_selected(&claims, &state, CipherSelection::Single(id), kind)
            .await?
            .into_iter()
            .next()
            .ok_or(AppError::Internal)?,
    ))
}
async fn mutate_bulk(
    claims: Claims,
    state: AppState,
    payload: ArchiveRequest,
    kind: CipherMutation,
) -> AppResult<RawJson> {
    let rows = mutate_selected(
        &claims,
        &state,
        CipherSelection::Bulk(payload.ids),
        kind,
    )
    .await?;
    Ok(RawJson(
        serde_json::to_string(&CipherListResponse::new(rows))
            .map_err(AppError::internal_error)?,
    ))
}
#[worker::send]
pub(in crate::api) async fn archive_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<CipherResponse>> {
    mutate_one(claims, state, id, CipherMutation::Archive).await
}
#[worker::send]
pub(in crate::api) async fn unarchive_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<CipherResponse>> {
    mutate_one(claims, state, id, CipherMutation::Unarchive).await
}
#[worker::send]
pub(in crate::api) async fn archive_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ArchiveRequest>,
) -> AppResult<RawJson> {
    mutate_bulk(claims, state, payload, CipherMutation::Archive).await
}
#[worker::send]
pub(in crate::api) async fn unarchive_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ArchiveRequest>,
) -> AppResult<RawJson> {
    mutate_bulk(claims, state, payload, CipherMutation::Unarchive).await
}

#[worker::send]
pub(in crate::api) async fn import_data(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ImportRequest>,
) -> AppResult<ApiResponse<()>> {
    import::import_data(&claims, &state, payload).await?;
    Ok(ApiResponse(()))
}
