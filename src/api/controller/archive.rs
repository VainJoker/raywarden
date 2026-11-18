use axum::{
    Json,
    extract::{
        Path,
        State,
    },
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    api::{
        AppState,
        RawJson,
        service::{
            ciphers::{
                Mutation,
                mutate_selected,
            },
            claims::Claims,
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    models::cipher::Cipher,
};

#[derive(Deserialize)]
pub struct ArchiveRequest {
    pub ids: Vec<String>,
}
async fn single(
    claims: Claims,
    state: AppState,
    id: String,
    kind: Mutation,
) -> AppResult<Json<Cipher>> {
    Ok(Json(
        mutate_selected(&claims, &state, vec![id], kind, None, false)
            .await?
            .into_iter()
            .next()
            .ok_or(AppError::Internal)?,
    ))
}
async fn bulk(
    claims: Claims,
    state: AppState,
    payload: ArchiveRequest,
    kind: Mutation,
) -> AppResult<RawJson> {
    let rows =
        mutate_selected(&claims, &state, payload.ids, kind, None, true).await?;
    Ok(RawJson(
        serde_json::to_string(
            &json!({"data":rows,"object":"list","continuationToken":null}),
        )
        .map_err(|_| AppError::Internal)?,
    ))
}
#[worker::send]
pub async fn archive_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Cipher>> {
    single(claims, state, id, Mutation::Archive).await
}
#[worker::send]
pub async fn unarchive_cipher(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Cipher>> {
    single(claims, state, id, Mutation::Unarchive).await
}
#[worker::send]
pub async fn archive_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ArchiveRequest>,
) -> AppResult<RawJson> {
    bulk(claims, state, payload, Mutation::Archive).await
}
#[worker::send]
pub async fn unarchive_ciphers_bulk(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<ArchiveRequest>,
) -> AppResult<RawJson> {
    bulk(claims, state, payload, Mutation::Unarchive).await
}
