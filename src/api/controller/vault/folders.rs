//! Personal folder HTTP handlers.
use axum::{
    Json,
    extract::{
        Path,
        State,
    },
};
use serde::Serialize;

use crate::{
    api::{
        AppState,
        common::response::ApiResponse,
    },
    errors::AppResult,
    models::vault::folder::FolderRow,
    service::{
        identity::session::Claims,
        vault::folder::{
            CreateFolderRequest,
            FolderResponse,
        },
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct FolderListResponse {
    data:               Vec<FolderResponse>,
    object:             &'static str,
    continuation_token: Option<String>,
}

#[worker::send]
pub(in crate::api) async fn list_folders(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<FolderListResponse>> {
    let data = FolderRow::list_for_user(state.database(), &claims.sub)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(ApiResponse(FolderListResponse {
        data,
        object: "list",
        continuation_token: None,
    }))
}
#[worker::send]
pub(in crate::api) async fn get_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<FolderResponse>> {
    Ok(ApiResponse(
        FolderRow::fetch_for_user(state.database(), &id, &claims.sub)
            .await?
            .into(),
    ))
}
#[worker::send]
pub(in crate::api) async fn create_folder(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateFolderRequest>,
) -> AppResult<ApiResponse<FolderResponse>> {
    Ok(ApiResponse(
        crate::service::vault::folder::create_folder(&state, &claims, payload)
            .await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn delete_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<()>> {
    Ok(ApiResponse(
        crate::service::vault::folder::delete_folder(&state, &claims, id)
            .await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn update_folder(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateFolderRequest>,
) -> AppResult<ApiResponse<FolderResponse>> {
    Ok(ApiResponse(
        crate::service::vault::folder::update_folder(
            &state, &claims, id, payload,
        )
        .await?,
    ))
}
