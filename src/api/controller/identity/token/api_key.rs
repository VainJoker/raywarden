use super::{LoginDevice, TokenExchange, form::ApiKeyGrant};
use crate::{
    errors::{AppError, AppResult},
    service::{
        identity::{api_key, oauth},
        notifications::{admin as admin_notify, admin::Event},
    },
};

impl TokenExchange<'_> {
    pub(super) async fn client_credentials(
        &self,
        payload: &ApiKeyGrant,
    ) -> AppResult<oauth::LoginTokenResponse> {
        let db = self.state.database();
        let state = self.state;
        let client_id = payload
            .client_id
            .as_deref()
            .ok_or_else(|| AppError::invalid_token_request("Missing client_id"))?;
        let client_secret = payload
            .client_secret
            .as_deref()
            .ok_or_else(|| AppError::invalid_token_request("Missing client_secret"))?;
        let (user, key_hash) = api_key::authenticate(
            state.database(),
            &state.env,
            self.client_ip,
            client_id,
            client_secret,
            payload.scope.as_deref(),
        )
        .await?;
        self.validate_account(&user).await?;
        let device = LoginDevice::with_required_id(&payload.device)?;
        let (nonce, tokens) = device.prepare_tokens(&user, state)?;
        api_key::start_session(db, &user, &device.new_session(&nonce), &key_hash).await?;
        let response = tokens.login_response(&user, None);
        admin_notify::emit(&state.env, Event::Login, &user.id).await;
        Ok(response)
    }
}
