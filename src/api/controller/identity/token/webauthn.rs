use super::{LoginDevice, TokenExchange, form::WebauthnGrant};
use crate::{
    errors::{AppError, AppResult, AuthError},
    models::identity::user::UserRow,
    service::{
        identity::{oauth, webauthn},
        notifications::{admin as admin_notify, admin::Event},
        rate_limit,
    },
};

impl TokenExchange<'_> {
    pub(super) async fn webauthn(
        &self,
        payload: &WebauthnGrant,
    ) -> AppResult<oauth::LoginTokenResponse> {
        let db = self.state.database();
        let state = self.state;
        rate_limit::check_auth_attempt(&state.env, format!("passkey-login:{}", self.client_ip))
            .await?;
        let challenge = payload
            .token
            .as_deref()
            .ok_or_else(|| AppError::invalid_token_request("Missing passkey challenge token"))?;
        let assertion = payload
            .device_response
            .as_deref()
            .ok_or_else(|| AppError::invalid_token_request("Missing deviceResponse"))?;
        let device_id = payload
            .device
            .id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AppError::invalid_token_request("Missing deviceIdentifier"))?;
        let device = LoginDevice::with_required_id(&payload.device)?;
        let result = webauthn::verify_passwordless(
            state.database(),
            &state.env,
            &state.jwt_keys.access_secret,
            challenge,
            assertion,
            device_id,
        )
        .await?;
        let user = UserRow::fetch_by_id_with(
            db,
            result.user_id(),
            "Failed to fetch passkey owner",
            || AuthError::UserNotFound.into(),
        )
        .await?;
        self.validate_account(&user).await?;
        let (nonce, tokens) = device.prepare_tokens(&user, state)?;
        let prf_keys = result
            .start_session(db, &user, &device.new_session(&nonce))
            .await?;
        let mut response = tokens.login_response(&user, None);
        if let Some((encrypted_user_key, encrypted_private_key)) = prf_keys {
            response.user_decryption_options.webauthn_prf_option = Some(oauth::WebauthnPrfOption {
                encrypted_user_key,
                encrypted_private_key,
            });
        }
        admin_notify::emit(&state.env, Event::WebauthnLogin, &user.id).await;
        Ok(response)
    }
}
