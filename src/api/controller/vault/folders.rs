//! Personal folder HTTP handlers.
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::Response,
};

use crate::{
    api::{
        AppState,
        common::{
            json::Json,
            response::ApiResponse,
            snapshot::{ReadSnapshot, SnapshotJson},
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
    let snapshot = ReadSnapshot::capture(db, &claims).await?;
    let mut response = SnapshotJson::new();
    let mut data = response.array("data")?;
    folder::visit_folder_responses(db, &claims.sub, |folder| data.push(&folder)).await?;
    data.finish()?;
    response.field("object", &"list")?;
    response.field("continuationToken", &None::<String>)?;
    let response = response.finish()?;
    snapshot.verify(db, &claims).await?;
    Ok(response)
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
        crate::service::vault::folder::create_folder(
            state.database(),
            &state.env,
            &claims,
            payload,
        )
        .await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn delete_folder(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<()>> {
    Ok(ApiResponse(
        crate::service::vault::folder::delete_folder(state.database(), &state.env, &claims, id)
            .await?,
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
        crate::service::vault::folder::update_folder(
            state.database(),
            &state.env,
            &claims,
            id,
            payload,
        )
        .await?,
    ))
}
