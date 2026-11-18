use axum::{
    Json,
    extract::{
        Path,
        Query,
        State,
    },
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        service::{
            auth::request_device_type,
            claims::Claims,
            notifications::{
                self,
                UpdateType,
            },
            rate,
        },
    },
    errors::AppError,
    infra::{
        admin_notify::{
            self,
            Event,
        },
        crypto::ct_eq,
    },
    models::{
        auth_request::AuthRequestDB,
        device::DeviceDB,
        user::UserDB,
    },
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAuthRequest {
    access_code:       String,
    device_identifier: String,
    email:             String,
    public_key:        String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAuthRequest {
    device_identifier:    String,
    key:                  String,
    master_password_hash: Option<String>,
    request_approved:     bool,
}

#[derive(Deserialize)]
pub struct ResponseQuery {
    code: String,
}

fn invalid_request() -> AppError {
    AppError::bad_request("Authentication request is unavailable")
}

#[worker::send]
pub async fn post_auth_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAuthRequest>,
) -> Result<Json<Value>, AppError> {
    rate::check_rate_limit(
        &state,
        format!("auth-request:{}", rate::client_ip(&headers)),
    )
    .await?;
    if payload.access_code.is_empty() ||
        payload.access_code.len() > 256 ||
        payload.device_identifier.is_empty() ||
        payload.device_identifier.len() > 256 ||
        payload.public_key.is_empty() ||
        payload.public_key.len() > 16_384
    {
        return Err(invalid_request());
    }
    let db = state.get_db();
    let email = payload.email.trim().to_lowercase();
    let user = UserDB::fetch_by_email_with(
        &db,
        &email,
        "Failed to fetch authentication request user",
        invalid_request,
    )
    .await?;
    let device_type = request_device_type(&headers)?;
    let device =
        DeviceDB::find_for_user(&db, &user.id, &payload.device_identifier)
            .await?
            .ok_or_else(invalid_request)?;
    if device.device_type != device_type {
        return Err(invalid_request());
    }
    let mut request = AuthRequestDB::new(
        user.id.clone(),
        payload.device_identifier,
        device_type,
        rate::client_ip(&headers).to_string(),
        payload.access_code,
        payload.public_key,
        user.security_stamp.clone(),
    );
    request.account_snapshot = Some(
        crate::models::account_keys::AccountSnapshot::from_user(&user)
            .to_json()?,
    );
    request.insert(&db).await?;
    notifications::publish_auth_update(
        &state.env,
        &request.user_id,
        UpdateType::AuthRequest,
        &request.id,
        Some(&request.request_device_identifier),
    )
    .await;
    if !request.generation_valid(&db).await? {
        return Err(invalid_request());
    }
    admin_notify::emit(&state.env, Event::AuthRequest, &request.user_id).await;
    Ok(Json(request.to_json(state.get_domain())))
}

#[worker::send]
pub async fn get_auth_requests_pending(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let requests =
        AuthRequestDB::list_pending_for_user(&state.get_db(), &claims.sub)
            .await?;
    Ok(Json(
        json!({ "data": requests.iter().map(|request| request.to_json(state.get_domain())).collect::<Vec<_>>(), "continuationToken": null, "object": "list" }),
    ))
}

#[worker::send]
pub async fn get_auth_request(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let request = AuthRequestDB::find_by_id(&db, &id)
        .await?
        .filter(|request| {
            request.user_id == claims.sub &&
                request.is_active() &&
                ct_eq(&request.security_stamp, &claims.sstamp)
        })
        .ok_or_else(invalid_request)?;
    if !request.generation_valid(&db).await? {
        return Err(invalid_request());
    }
    Ok(Json(request.to_json(state.get_domain())))
}

#[worker::send]
pub async fn put_auth_request(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateAuthRequest>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let request = AuthRequestDB::find_by_id(&db, &id)
        .await?
        .filter(|request| {
            request.user_id == claims.sub &&
                request.is_active() &&
                ct_eq(&request.security_stamp, &claims.sstamp)
        })
        .ok_or_else(invalid_request)?;
    if claims.device() != Some(payload.device_identifier.as_str()) ||
        payload.device_identifier == request.request_device_identifier ||
        (payload.request_approved && payload.key.is_empty())
    {
        return Err(invalid_request());
    }
    if !request.generation_valid(&db).await? {
        return Err(invalid_request());
    }
    let response = request
        .respond(
            &db,
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
    Ok(Json(response.to_json(state.get_domain())))
}

#[worker::send]
pub async fn get_auth_request_response(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ResponseQuery>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    let request = AuthRequestDB::find_by_id(&db, &id)
        .await?
        .filter(AuthRequestDB::is_active)
        .ok_or_else(invalid_request)?;
    if request.device_type != request_device_type(&headers)? ||
        request.request_ip != rate::client_ip(&headers) ||
        !ct_eq(&request.access_code, &query.code)
    {
        rate::check_rate_limit(
            &state,
            format!("auth-response:{}", rate::client_ip(&headers)),
        )
        .await?;
        return Err(invalid_request());
    }
    let user = UserDB::fetch_by_id_with(
        &db,
        &request.user_id,
        "Failed to fetch authentication request owner",
        invalid_request,
    )
    .await?;
    if !ct_eq(&user.security_stamp, &request.security_stamp) {
        return Err(invalid_request());
    }
    if !request.generation_valid(&db).await? {
        return Err(invalid_request());
    }
    Ok(Json(request.to_json(state.get_domain())))
}
