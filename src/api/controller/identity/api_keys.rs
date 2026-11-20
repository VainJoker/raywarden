use axum::{
    Json,
    extract::State,
};
use serde::Serialize;

use crate::{
    api::{
        AppState,
        common::response::ApiResponse,
    },
    errors::AppResult,
    service::identity::{
        api_key,
        session::Claims,
        user::AccountVerificationRequest,
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct ApiKeyResponse {
    api_key:       String,
    revision_date: String,
    object:        &'static str,
}

impl ApiKeyResponse {
    const fn new(api_key: String, revision_date: String) -> Self {
        Self {
            api_key,
            revision_date,
            object: "apiKey",
        }
    }
}

#[worker::send]
pub(in crate::api) async fn get_api_key(
    claims: Claims,
    State(state): State<AppState>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<ApiKeyResponse>> {
    let (key, revision) =
        api_key::get_or_rotate(&state, &claims, &proof, false).await?;
    Ok(ApiResponse(ApiKeyResponse::new(key, revision)))
}
#[worker::send]
pub(in crate::api) async fn rotate_api_key(
    claims: Claims,
    State(state): State<AppState>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<ApiKeyResponse>> {
    let (key, revision) =
        api_key::get_or_rotate(&state, &claims, &proof, true).await?;
    Ok(ApiResponse(ApiKeyResponse::new(key, revision)))
}
