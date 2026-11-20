use axum::{
    Json,
    extract::{
        Path,
        Query,
        State,
    },
    http::HeaderMap,
};
use serde::{
    Deserialize,
    Serialize,
};
use worker::D1Database;

use crate::{
    api::{
        AppState,
        common::response::ApiResponse,
        middleware::auth::request_device_type,
    },
    errors::{
        AppError,
        AppResult,
    },
    models::identity::{
        auth_request::AuthRequestRow,
        device::DeviceRow,
        user::UserRow,
    },
    service::{
        identity::{
            auth_request::{
                self,
                AuthRequestResponse,
            },
            session::Claims,
            user::fetch_by_email_with,
        },
        notifications,
        notifications::{
            UpdateType,
            admin as admin_notify,
            admin::Event,
        },
        rate_limit,
    },
    utils::constant_time_eq,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct CreateAuthRequest {
    access_code:       String,
    device_identifier: String,
    email:             String,
    public_key:        String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct UpdateAuthRequest {
    device_identifier:    String,
    key:                  String,
    master_password_hash: Option<String>,
    request_approved:     bool,
}

#[derive(Deserialize)]
pub(in crate::api) struct AuthRequestResponseQuery {
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct AuthRequestListResponse {
    data:               Vec<AuthRequestResponse>,
    continuation_token: Option<String>,
    object:             &'static str,
}

async fn owned_active_request(
    db: &D1Database,
    id: &str,
    claims: &Claims,
) -> AppResult<AuthRequestRow> {
    AuthRequestRow::find_by_id(db, id)
        .await?
        .filter(|request| {
            request.user_id == claims.sub &&
                auth_request::is_auth_request_active(request) &&
                constant_time_eq(
                    request.security_stamp.as_bytes(),
                    claims.sstamp.as_bytes(),
                )
        })
        .ok_or_else(AppError::auth_request_unavailable)
}

async fn require_current_generation(
    db: &D1Database,
    request: &AuthRequestRow,
) -> AppResult<()> {
    if auth_request::auth_request_generation_matches(request, db).await? {
        Ok(())
    } else {
        Err(AppError::auth_request_unavailable())
    }
}

#[worker::send]
pub(in crate::api) async fn create_auth_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAuthRequest>,
) -> AppResult<ApiResponse<AuthRequestResponse>> {
    let ip = rate_limit::client_ip(&headers);
    rate_limit::check_auth_attempt(&state, format!("auth-request:{ip}"))
        .await?;
    if payload.access_code.is_empty() ||
        payload.access_code.len() > 256 ||
        payload.device_identifier.is_empty() ||
        payload.device_identifier.len() > 256 ||
        payload.public_key.is_empty() ||
        payload.public_key.len() > 16_384
    {
        return Err(AppError::auth_request_unavailable());
    }
    let db = state.database();
    let user = fetch_by_email_with(
        db,
        &payload.email,
        "Failed to fetch authentication request user",
        AppError::auth_request_unavailable,
    )
    .await?;
    let device_type = request_device_type(&headers)?;
    let device =
        DeviceRow::find_for_user(db, &user.id, &payload.device_identifier)
            .await?
            .ok_or_else(AppError::auth_request_unavailable)?;
    if device.device_type != device_type {
        return Err(AppError::auth_request_unavailable());
    }
    let mut request = auth_request::new_auth_request(
        user.id.clone(),
        payload.device_identifier,
        device_type,
        ip.to_owned(),
        payload.access_code,
        payload.public_key,
        user.security_stamp.clone(),
    );
    request.account_snapshot = Some(
        crate::models::identity::account_keys::AccountSnapshot::from_user(
            &user,
        )
        .to_json()?,
    );
    request.insert(db).await?;
    notifications::publish_auth_update(
        &state.env,
        &request.user_id,
        UpdateType::AuthRequest,
        &request.id,
        Some(&request.request_device_id),
    )
    .await;
    require_current_generation(db, &request).await?;
    admin_notify::emit(&state.env, Event::AuthRequest, &request.user_id).await;
    Ok(ApiResponse(AuthRequestResponse::new(
        request,
        state.domain(),
    )))
}

#[worker::send]
pub(in crate::api) async fn list_pending_auth_requests(
    claims: Claims,
    State(state): State<AppState>,
) -> AppResult<ApiResponse<AuthRequestListResponse>> {
    let requests =
        AuthRequestRow::list_pending_for_user(state.database(), &claims.sub)
            .await?;
    let data = requests
        .into_iter()
        .map(|request| AuthRequestResponse::new(request, state.domain()))
        .collect();
    Ok(ApiResponse(AuthRequestListResponse {
        data,
        continuation_token: None,
        object: "list",
    }))
}

#[worker::send]
pub(in crate::api) async fn get_auth_request(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<ApiResponse<AuthRequestResponse>> {
    let db = state.database();
    let request = owned_active_request(db, &id, &claims).await?;
    require_current_generation(db, &request).await?;
    Ok(ApiResponse(AuthRequestResponse::new(
        request,
        state.domain(),
    )))
}

#[worker::send]
pub(in crate::api) async fn respond_to_auth_request(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateAuthRequest>,
) -> AppResult<ApiResponse<AuthRequestResponse>> {
    let db = state.database();
    let request = owned_active_request(db, &id, &claims).await?;
    if claims.device() != Some(payload.device_identifier.as_str()) ||
        payload.device_identifier == request.request_device_id ||
        (payload.request_approved && payload.key.is_empty())
    {
        return Err(AppError::auth_request_unavailable());
    }
    require_current_generation(db, &request).await?;
    let response = request
        .respond(
            db,
            &payload.device_identifier,
            payload.request_approved,
            &payload.key,
            payload.master_password_hash.as_deref(),
        )
        .await?;
    notifications::publish_anonymous_update(
        &state.env,
        &response.id,
        &response.user_id,
    )
    .await;
    notifications::publish_auth_update(
        &state.env,
        &response.user_id,
        UpdateType::AuthRequestResponse,
        &response.id,
        claims.device(),
    )
    .await;
    admin_notify::emit(&state.env, Event::AuthResponse, &response.user_id)
        .await;
    Ok(ApiResponse(AuthRequestResponse::new(
        response,
        state.domain(),
    )))
}

#[worker::send]
pub(in crate::api) async fn get_auth_request_response(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<AuthRequestResponseQuery>,
) -> AppResult<ApiResponse<AuthRequestResponse>> {
    let db = state.database();
    let request = AuthRequestRow::find_by_id(db, &id)
        .await?
        .filter(auth_request::is_auth_request_active)
        .ok_or_else(AppError::auth_request_unavailable)?;
    if request.device_type != request_device_type(&headers)? ||
        request.request_ip != rate_limit::client_ip(&headers) ||
        !constant_time_eq(
            request.access_code.as_bytes(),
            query.code.as_bytes(),
        )
    {
        rate_limit::check_auth_attempt(
            &state,
            format!("auth-response:{}", rate_limit::client_ip(&headers)),
        )
        .await?;
        return Err(AppError::auth_request_unavailable());
    }
    let user = UserRow::fetch_by_id_with(
        db,
        &request.user_id,
        "Failed to fetch authentication request owner",
        AppError::auth_request_unavailable,
    )
    .await?;
    if !constant_time_eq(
        user.security_stamp.as_bytes(),
        request.security_stamp.as_bytes(),
    ) {
        return Err(AppError::auth_request_unavailable());
    }
    require_current_generation(db, &request).await?;
    Ok(ApiResponse(AuthRequestResponse::new(
        request,
        state.domain(),
    )))
}
