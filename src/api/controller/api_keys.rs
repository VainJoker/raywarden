use axum::{
    Json,
    extract::State,
};
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        service::{
            api_key,
            claims::Claims,
        },
    },
    errors::AppResult,
    models::user::PasswordOrOtpData,
};
#[worker::send]
pub async fn get_api_key(
    claims: Claims,
    State(state): State<AppState>,
    Json(proof): Json<PasswordOrOtpData>,
) -> AppResult<Json<Value>> {
    let (key, revision) =
        api_key::get_or_rotate(&state, &claims, &proof, false).await?;
    Ok(Json(
        json!({"apiKey":key,"revisionDate":revision,"object":"apiKey"}),
    ))
}
#[worker::send]
pub async fn rotate_api_key(
    claims: Claims,
    State(state): State<AppState>,
    Json(proof): Json<PasswordOrOtpData>,
) -> AppResult<Json<Value>> {
    let (key, revision) =
        api_key::get_or_rotate(&state, &claims, &proof, true).await?;
    Ok(Json(
        json!({"apiKey":key,"revisionDate":revision,"object":"apiKey"}),
    ))
}
