use std::sync::Arc;

use axum::extract::State;
use serde::Serialize;

use crate::{
    api::{
        AppState,
        common::{json::Json, response::ApiResponse},
    },
    errors::AppResult,
    service::identity::{
        api_key::{ApiKeyAction, ApiKeyService},
        session::Claims,
        user::AccountVerificationRequest,
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct ApiKeyResponse {
    api_key: String,
    revision_date: String,
    object: &'static str,
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
    State(state): State<Arc<AppState>>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<ApiKeyResponse>> {
    let service = ApiKeyService {
        db: state.database(),
        env: &state.env,
        access_secret: &state.jwt_keys.access_secret,
    };
    let (key, revision) = service
        .get_or_rotate(&claims, &proof, ApiKeyAction::Get)
        .await?;
    Ok(ApiResponse(ApiKeyResponse::new(key, revision)))
}
#[worker::send]
pub(in crate::api) async fn rotate_api_key(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(proof): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<ApiKeyResponse>> {
    let service = ApiKeyService {
        db: state.database(),
        env: &state.env,
        access_secret: &state.jwt_keys.access_secret,
    };
    let (key, revision) = service
        .get_or_rotate(&claims, &proof, ApiKeyAction::Rotate)
        .await?;
    Ok(ApiResponse(ApiKeyResponse::new(key, revision)))
}
