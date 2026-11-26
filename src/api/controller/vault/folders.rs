//! Personal folder HTTP handlers.
use std::sync::Arc;

use axum::{extract::State, response::Response};

use crate::{
    api::{
        AppState,
        common::{
            extract::Path,
            json::Json,
            response::ApiResponse,
            snapshot::{ListOrder, SnapshotJson},
        },
    },
    errors::AppResult,
    models::vault::folder::FolderRow,
    service::{
        identity::session::Claims,
        vault::folder::{self, CreateFolderRequest, FolderResponse},
    },
};

#[worker::send]
pub(in crate::api) async fn list_folders(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<Response> {
    let db = state.database();
    SnapshotJson::list(db, &claims, ListOrder::ObjectFirst, async |data| {
        folder::visit_folder_responses(db, &claims.sub, |folder| data.push(&folder)).await
    })
    .await
}
#[worker::send]
pub(in crate::api) async fn get_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
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
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateFolderRequest>,
) -> AppResult<ApiResponse<FolderResponse>> {
    Ok(ApiResponse(
        folder::save_folder(state.database(), &state.env, &claims, None, payload).await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn delete_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<()>> {
    Ok(ApiResponse(
        folder::delete_folder(state.database(), &state.env, &claims, &id).await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn update_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<CreateFolderRequest>,
) -> AppResult<ApiResponse<FolderResponse>> {
    Ok(ApiResponse(
        folder::save_folder(state.database(), &state.env, &claims, Some(id), payload).await?,
    ))
}
