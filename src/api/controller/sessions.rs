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
        service::claims::Claims,
    },
    errors::AppError,
    infra::admin_notify::{
        self,
        Event,
    },
    models::{
        device::DeviceDB,
        user::PasswordOrOtpData,
    },
};

#[worker::send]
pub async fn post_security_stamp(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = state.get_db();
    crate::api::service::email::verify_password_or_otp(
        &state, &claims, &payload,
    )
    .await?;
    crate::api::service::notifications::publish_user_update(
        &state.env,
        &claims.sub,
        crate::api::service::notifications::UpdateType::LogOut,
        &crate::infra::time::now_rfc3339(),
        claims.device(),
    )
    .await;
    crate::api::service::push::unregister_user(&state.env, &claims.sub).await;
    DeviceDB::revoke_all(&db, &claims.sub).await?;
    admin_notify::emit(&state.env, Event::AccountSecurityChanged, &claims.sub)
        .await;
    Ok(Json(json!({})))
}
