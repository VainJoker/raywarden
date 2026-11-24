//! Cipher CRUD, archive and import HTTP handlers.
use std::sync::Arc;

use axum::{
    extract::{FromRequest, Path, RawQuery, Request, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        AppState,
        common::{
            json::Json,
            response::ApiResponse,
            snapshot::{ReadSnapshot, SnapshotJson},
        },
    },
    errors::{AppError, AppResult},
    models::vault::cipher::{CipherMutation, CipherRow},
    service::{
        identity::{session::Claims, user::AccountVerificationRequest},
        vault::{
            attachment,
            cipher::{
                self, CipherRequest, CipherResponse, CipherSelection,
                CreateCipherWithCollectionsRequest, UpdateCipherPartialRequest, mutate_selected,
            },
            import::{self, ImportRequest},
        },
    },
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct CipherListResponse {
    data: Vec<CipherResponse>,
    object: &'static str,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct BulkCipherSelection {
    ids: Vec<String>,
    folder_id: Option<String>,
}

impl<S: Send + Sync> FromRequest<S> for BulkCipherSelection {
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let body = String::from_request(request, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Self::parse(&body).map_err(IntoResponse::into_response)
    }
}

impl BulkCipherSelection {
    fn parse(body: &str) -> AppResult<Self> {
        let mut selection: Self = serde_json::from_str(body)
            .map_err(|_error| AppError::bad_request("Invalid cipher selection"))?;
        selection.folder_id = selection.folder_id.filter(|id| !id.is_empty());
        Ok(selection)
    }
}

async fn mutate_bulk(
    state: &AppState,
    claims: &Claims,
    ids: Vec<String>,
    kind: CipherMutation,
) -> AppResult<Vec<CipherResponse>> {
    mutate_selected(
        state.database(),
        &state.env,
        state.domain(),
        claims,
        CipherSelection::Bulk(ids),
        kind,
    )
    .await
}

#[worker::send]
pub(in crate::api) async fn create_cipher_with_collections(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateCipherWithCollectionsRequest>,
) -> AppResult<ApiResponse<CipherResponse>> {
    if !payload.collection_ids.is_empty() {
        return Err(AppError::bad_request("Collections are not supported"));
    }
    Ok(ApiResponse(
        cipher::save_cipher(
            state.database(),
            &state.env,
            state.domain(),
            &claims,
            None,
            payload.cipher,
        )
        .await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn create_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CipherRequest>,
) -> AppResult<ApiResponse<CipherResponse>> {
    Ok(ApiResponse(
        cipher::save_cipher(
            state.database(),
            &state.env,
            state.domain(),
            &claims,
            None,
            payload,
        )
        .await?,
    ))
}
#[worker::send]
pub(in crate::api) async fn update_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequest>,
) -> AppResult<ApiResponse<CipherResponse>> {
    Ok(ApiResponse(
        cipher::save_cipher(
            state.database(),
            &state.env,
            state.domain(),
            &claims,
            Some(id),
            payload,
        )
        .await?,
    ))
}

#[worker::send]
pub(in crate::api) async fn list_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> AppResult<Response> {
    let db = state.database();
    let snapshot = ReadSnapshot::capture(db, &claims).await?;
    let mut response = SnapshotJson::new();
    let mut data = response.array("data")?;
    cipher::visit_cipher_responses(
        db,
        &claims.sub,
        attachment::include_metadata(&state.env),
        true,
        true,
        state.domain(),
        |cipher| data.push(&cipher),
    )
    .await?;
    data.finish()?;
    response.field("object", &"list")?;
    response.field("continuationToken", &None::<String>)?;
    let response = response.finish()?;
    snapshot.verify(db, &claims).await?;
    Ok(response)
}
#[worker::send]
pub(in crate::api) async fn get_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<CipherResponse>> {
    let db = state.database();
    let mut cipher = CipherRow::fetch_for_user(db, &id, &claims.sub)
        .await?
        .try_into()?;
    attachment::hydrate_cipher_attachments(
        db,
        state.domain(),
        attachment::include_metadata(&state.env),
        &mut cipher,
    )
    .await?;
    Ok(ApiResponse(cipher))
}
#[worker::send]
pub(in crate::api) async fn update_cipher_partial(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateCipherPartialRequest>,
) -> AppResult<ApiResponse<CipherResponse>> {
    Ok(ApiResponse(
        cipher::update_cipher_partial(
            state.database(),
            &state.env,
            state.domain(),
            &claims,
            id,
            payload,
        )
        .await?,
    ))
}

#[worker::send]
pub(in crate::api) async fn soft_delete_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<()>> {
    mutate_selected(
        state.database(),
        &state.env,
        state.domain(),
        &claims,
        CipherSelection::Single(id),
        CipherMutation::SoftDelete,
    )
    .await?;
    Ok(ApiResponse(()))
}
#[worker::send]
pub(in crate::api) async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    selection: BulkCipherSelection,
) -> AppResult<ApiResponse<()>> {
    mutate_bulk(&state, &claims, selection.ids, CipherMutation::SoftDelete).await?;
    Ok(ApiResponse(()))
}
#[worker::send]
pub(in crate::api) async fn hard_delete_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<()>> {
    mutate_selected(
        state.database(),
        &state.env,
        state.domain(),
        &claims,
        CipherSelection::Single(id),
        CipherMutation::HardDelete,
    )
    .await?;
    Ok(ApiResponse(()))
}
#[worker::send]
pub(in crate::api) async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    selection: BulkCipherSelection,
) -> AppResult<ApiResponse<()>> {
    mutate_bulk(&state, &claims, selection.ids, CipherMutation::HardDelete).await?;
    Ok(ApiResponse(()))
}
#[worker::send]
pub(in crate::api) async fn restore_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<CipherResponse>> {
    mutate_one(claims, state, id, CipherMutation::Restore).await
}
#[worker::send]
pub(in crate::api) async fn restore_ciphers_bulk(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    selection: BulkCipherSelection,
) -> AppResult<ApiResponse<CipherListResponse>> {
    let rows = mutate_bulk(&state, &claims, selection.ids, CipherMutation::Restore).await?;
    Ok(ApiResponse(CipherListResponse::new(rows)))
}
#[worker::send]
pub(in crate::api) async fn move_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    selection: BulkCipherSelection,
) -> AppResult<ApiResponse<()>> {
    mutate_bulk(&state, &claims, selection.ids, CipherMutation::Move {
        folder_id: selection.folder_id,
    })
    .await?;
    Ok(ApiResponse(()))
}

#[worker::send]
pub(in crate::api) async fn purge_vault(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    Json(payload): Json<AccountVerificationRequest>,
) -> AppResult<ApiResponse<()>> {
    cipher::purge_vault(
        state.database(),
        &state.env,
        &state.jwt_keys.access_secret,
        &claims,
        query.as_deref(),
        payload,
    )
    .await?;
    Ok(ApiResponse(()))
}

#[derive(Deserialize)]
pub(in crate::api) struct ArchiveRequest {
    ids: Vec<String>,
}
async fn mutate_one(
    claims: Claims,
    state: Arc<AppState>,
    id: String,
    kind: CipherMutation,
) -> AppResult<ApiResponse<CipherResponse>> {
    Ok(ApiResponse(
        mutate_selected(
            state.database(),
            &state.env,
            state.domain(),
            &claims,
            CipherSelection::Single(id),
            kind,
        )
        .await?
        .into_iter()
        .next()
        .ok_or(AppError::Internal)?,
    ))
}
#[worker::send]
pub(in crate::api) async fn archive_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<CipherResponse>> {
    mutate_one(claims, state, id, CipherMutation::Archive).await
}
#[worker::send]
pub(in crate::api) async fn unarchive_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<CipherResponse>> {
    mutate_one(claims, state, id, CipherMutation::Unarchive).await
}
#[worker::send]
pub(in crate::api) async fn archive_ciphers_bulk(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ArchiveRequest>,
) -> AppResult<ApiResponse<CipherListResponse>> {
    let rows = mutate_bulk(&state, &claims, payload.ids, CipherMutation::Archive).await?;
    Ok(ApiResponse(CipherListResponse::new(rows)))
}
#[worker::send]
pub(in crate::api) async fn unarchive_ciphers_bulk(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ArchiveRequest>,
) -> AppResult<ApiResponse<CipherListResponse>> {
    let rows = mutate_bulk(&state, &claims, payload.ids, CipherMutation::Unarchive).await?;
    Ok(ApiResponse(CipherListResponse::new(rows)))
}

#[worker::send]
pub(in crate::api) async fn import_data(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ImportRequest>,
) -> AppResult<ApiResponse<()>> {
    import::import_data(
        state.database(),
        &state.env,
        state.config.import_batch_size,
        &claims,
        payload,
    )
    .await?;
    Ok(ApiResponse(()))
}

#[cfg(test)]
mod tests {
    use super::BulkCipherSelection;

    #[test]
    fn an_empty_move_folder_clears_the_relationship_without_normalizing_other_ids() {
        for body in [
            r#"{"ids":[],"folderId":""}"#,
            r#"{"ids":[],"folderId":null}"#,
            r#"{"ids":[]}"#,
        ] {
            assert!(
                BulkCipherSelection::parse(body)
                    .expect("valid vault workflow fixture")
                    .folder_id
                    .is_none()
            );
        }
        assert_eq!(
            BulkCipherSelection::parse(r#"{"ids":["cipher"],"folderId":"folder"}"#)
                .expect("valid vault workflow fixture")
                .folder_id
                .as_deref(),
            Some("folder")
        );
        assert_eq!(
            BulkCipherSelection::parse(r#"{"ids":[],"folderId":" "}"#)
                .expect("valid vault workflow fixture")
                .folder_id
                .as_deref(),
            Some(" ")
        );
    }
}
