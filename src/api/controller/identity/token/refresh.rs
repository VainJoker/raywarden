use super::TokenExchange;
use crate::{
    errors::{AppError, AppResult},
    infra::jwt,
    models::identity::{
        device::{DeviceRow, SessionSnapshot},
        user::UserRow,
    },
    service::{
        identity::{
            oauth,
            session::{Claims, TokenUse},
        },
        notifications::{admin as admin_notify, admin::Event},
    },
    utils::constant_time_eq,
};

impl TokenExchange<'_> {
    pub(super) async fn refresh(
        &self,
        refresh_token: Option<&str>,
    ) -> AppResult<oauth::TokenResponse> {
        let db = self.state.database();
        let state = self.state;
        let refresh_token = refresh_token.ok_or_else(invalid_refresh_token)?;
        let claims = jwt::decode::<Claims>(
            refresh_token,
            state.jwt_keys.refresh_secret.as_bytes(),
            &jwt::ValidationOptions::default(),
        )
        .map_err(|_error| invalid_refresh_token())?;
        claims
            .validate_session(db, TokenUse::Refresh)
            .await
            .map_err(|error| {
                if matches!(error, AppError::Auth(_) | AppError::Unauthorized { .. }) {
                    invalid_refresh_token()
                } else {
                    error
                }
            })?;
        let user = UserRow::fetch_by_id_with(
            db,
            &claims.sub,
            "Failed to fetch refresh token owner",
            invalid_refresh_token,
        )
        .await?;
        // Keep the account generation from the original proof. A
        // credential rotation can finish after validate_session and
        // before this user read; signing that newer row would revive
        // an otherwise revoked refresh token.
        if !constant_time_eq(user.security_stamp.as_bytes(), claims.sstamp.as_bytes()) {
            return Err(invalid_refresh_token());
        }
        let device = DeviceRow::find_for_user(db, &claims.sub, claims.device().unwrap_or_default())
            .await?
            .ok_or_else(invalid_refresh_token)?;
        // Never upgrade an old refresh proof to a concurrently created
        // device nonce just because the row was read after validation.
        if !constant_time_eq(
            device.session_token.as_bytes(),
            claims.session_token.as_bytes(),
        ) {
            return Err(invalid_refresh_token());
        }
        self.validate_account(&user).await?;
        let session = SessionSnapshot {
            user_id: &user.id,
            security_stamp: &user.security_stamp,
            device_id: &device.device_id,
            session_token: &device.session_token,
        };
        let tokens = oauth::IssuedTokens::issue(
            &user,
            &session,
            &state.jwt_keys,
            state.config.jwt_duration_seconds,
        )?;
        let response = tokens.refresh_response();
        admin_notify::emit(&state.env, Event::TokenRefresh, &user.id).await;
        Ok(response)
    }
}

const fn invalid_refresh_token() -> AppError {
    AppError::OAuth {
        error: "invalid_grant",
        description: "Invalid or expired refresh token",
    }
}
