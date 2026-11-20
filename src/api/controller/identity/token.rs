use std::borrow::Cow;

use axum::{
    Form,
    extract::State,
    http::{
        HeaderMap,
        header,
    },
    response::{
        IntoResponse,
        Response,
    },
};
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
};
use serde_json::{
    Map,
    Value,
};
use worker::D1Database;

use crate::{
    api::{
        AppState,
        common::response::ApiResponse,
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    infra::jwt,
    models::identity::{
        auth_request::AuthRequestRow,
        device::DeviceRow,
        two_factor::TwoFactorRow,
        user::UserRow,
    },
    service::{
        identity::{
            api_key,
            auth_request,
            email,
            oauth,
            session::Claims,
            two_factor::{
                RememberedDevices,
                TwoFactorProvider,
                validate_totp,
            },
            user,
            webauthn,
        },
        notifications::{
            admin as admin_notify,
            admin::Event,
        },
        rate_limit,
        send::SendAccessTokenResponse,
    },
    utils::constant_time_eq,
};

/// Deserialize an Option<i32> that may have trailing/leading whitespace.
/// This handles Android clients that send "0 " instead of "0".
fn deserialize_trimmed_i32<'de, D>(
    deserializer: D,
) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                trimmed.parse::<i32>().map(Some).map_err(|e| {
                    D::Error::custom(format!("invalid integer: {s} ({e})"))
                })
            }
        }
        None => Ok(None),
    }
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type:          String,
    username:            Option<String>,
    password:            Option<String>, // This is the masterPasswordHash
    refresh_token:       Option<String>,
    #[serde(rename = "twoFactorToken")]
    two_factor_token:    Option<String>,
    #[serde(
        rename = "twoFactorProvider",
        default,
        deserialize_with = "deserialize_trimmed_i32"
    )]
    two_factor_provider: Option<i32>,
    #[serde(
        rename = "twoFactorRemember",
        default,
        deserialize_with = "deserialize_trimmed_i32"
    )]
    two_factor_remember: Option<i32>,
    #[serde(rename = "deviceIdentifier")]
    device_id:           Option<String>,
    #[serde(rename = "deviceName")]
    device_name:         Option<String>,
    #[serde(
        rename = "deviceType",
        default,
        deserialize_with = "deserialize_trimmed_i32"
    )]
    device_type:         Option<i32>,
    #[serde(rename = "authRequest")]
    auth_request_id:     Option<String>,
    access_code:         Option<String>,
    send_id:             Option<String>,
    access_id:           Option<String>,
    password_hash_b64:   Option<String>,
    client_id:           Option<String>,
    client_secret:       Option<String>,
    scope:               Option<String>,
    token:               Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response:     Option<String>,
}

#[worker::send]
pub(in crate::api) async fn exchange_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(fields): Form<Vec<(String, String)>>,
) -> AppResult<Response> {
    let allow_token_cookies =
        oauth::allows_token_cookie_origin(&headers, state.domain());
    let payload =
        TokenRequest::from_form(fields, &headers, allow_token_cookies)?;
    let login_attempt = matches!(
        payload.grant_type.as_str(),
        "password" | "client_credentials" | "webauthn"
    );
    let mut exchange = TokenExchange {
        state:                    &state,
        headers:                  &headers,
        credential_lookup_failed: false,
    };
    let result = exchange.redeem(&payload).await;
    if login_attempt &&
        !exchange.credential_lookup_failed &&
        matches!(&result, Err(error) if rejected_credentials(error))
    {
        admin_notify::emit(&state.env, Event::LoginFailed, "unidentified")
            .await;
    }
    let result = result?;
    let mut cookies = Vec::new();
    if allow_token_cookies {
        if let Some(token) = result.refresh_token() {
            cookies.push(oauth::refresh_cookie_header(state.domain(), token)?);
        }
        if let TokenGrantResponse::Login(login) = &result &&
            let Some(token) = login.two_factor_token.as_deref()
        {
            for name in ["twoFactorRemember", "TwoFactorRemember"] {
                cookies.push(oauth::token_cookie_header(
                    state.domain(),
                    name,
                    token,
                    state.config.two_factor_remember_days * 86400,
                )?);
            }
        }
    }
    let mut response = ApiResponse(result).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    for cookie in cookies {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    Ok(response)
}

const fn rejected_credentials(error: &AppError) -> bool {
    matches!(
        error,
        AppError::Auth(
            AuthError::UserNotFound |
                AuthError::InvalidCredentials(_) |
                AuthError::InvalidPassword |
                AuthError::InvalidTotp |
                AuthError::AccountLocked
        )
    )
}

impl TokenRequest {
    fn from_form(
        fields: Vec<(String, String)>,
        headers: &HeaderMap,
        allow_token_cookies: bool,
    ) -> AppResult<Self> {
        let mut payload: Self = serde_json::from_value(
            oauth::parse_token_form(fields)?,
        )
        .map_err(|_error| AppError::bad_request("Invalid token form"))?;
        if payload.grant_type == "refresh_token" &&
            payload.refresh_token.is_none()
        {
            if !allow_token_cookies {
                return Err(AppError::Unauthorized {
                    message: "Token cookie requires the same origin".into(),
                });
            }
            payload.refresh_token =
                oauth::read_token_cookie(headers, "bw_refresh_token")?;
        }
        if payload.grant_type == "password" &&
            payload.two_factor_token.is_none() &&
            payload.two_factor_provider.is_none_or(|provider| {
                provider == TwoFactorProvider::Remember as i32
            })
        {
            let primary =
                oauth::read_token_cookie(headers, "twoFactorRemember")?;
            let alias = oauth::read_token_cookie(headers, "TwoFactorRemember")?;
            if primary.as_ref().zip(alias.as_ref()).is_some_and(
                |(left, right)| {
                    !constant_time_eq(left.as_bytes(), right.as_bytes())
                },
            ) {
                return Err(AppError::bad_request(
                    "Conflicting remembered-login cookies",
                ));
            }
            if let Some(token) = primary.or(alias) {
                if !allow_token_cookies {
                    return Err(AppError::Unauthorized {
                        message: "Token cookie requires the same origin".into(),
                    });
                }
                payload.two_factor_token = Some(token);
                payload.two_factor_provider =
                    Some(TwoFactorProvider::Remember as i32);
            }
        }
        Ok(payload)
    }
}

struct LoginDevice<'a> {
    id:          Cow<'a, str>,
    name:        &'a str,
    device_type: i32,
}

impl<'a> LoginDevice<'a> {
    fn for_password(payload: &'a TokenRequest) -> AppResult<Self> {
        let id = payload
            .device_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map_or_else(
                || Cow::Owned(uuid::Uuid::new_v4().to_string()),
                Cow::Borrowed,
            );
        Self::new(payload, id)
    }

    fn with_required_id(payload: &'a TokenRequest) -> AppResult<Self> {
        let id = payload
            .device_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AppError::bad_request("Missing deviceIdentifier"))?;
        Self::new(payload, Cow::Borrowed(id))
    }

    fn new(payload: &'a TokenRequest, id: Cow<'a, str>) -> AppResult<Self> {
        let name = payload.device_name.as_deref().unwrap_or("Unknown Device");
        let device_type = payload.device_type.unwrap_or(14);
        if id.len() > 256 ||
            name.len() > 256 ||
            !(0..=40).contains(&device_type)
        {
            return Err(AppError::bad_request("Invalid device information"));
        }
        Ok(Self {
            id,
            name,
            device_type,
        })
    }

    async fn start_session(
        &self,
        db: &D1Database,
        user: &UserRow,
    ) -> AppResult<DeviceRow> {
        crate::service::identity::session::start_session(
            db,
            &user.id,
            &self.id,
            self.name,
            self.device_type,
        )
        .await
    }
}

struct TokenExchange<'a> {
    state:                    &'a AppState,
    headers:                  &'a HeaderMap,
    credential_lookup_failed: bool,
}

#[derive(Serialize)]
#[serde(untagged)]
enum TokenGrantResponse {
    Login(Box<oauth::LoginTokenResponse>),
    Refresh(oauth::TokenResponse),
    Send(SendAccessTokenResponse),
}

impl TokenGrantResponse {
    fn refresh_token(&self) -> Option<&str> {
        match self {
            Self::Login(login) => Some(&login.tokens.refresh_token),
            Self::Refresh(tokens) => Some(&tokens.refresh_token),
            Self::Send(_) => None,
        }
    }
}

impl TokenExchange<'_> {
    async fn redeem(
        &mut self,
        payload: &TokenRequest,
    ) -> AppResult<TokenGrantResponse> {
        let response = match payload.grant_type.as_str() {
            "password" => TokenGrantResponse::Login(Box::new(
                self.password(payload).await?,
            )),
            "refresh_token" => {
                TokenGrantResponse::Refresh(self.refresh(payload).await?)
            }
            "client_credentials" => TokenGrantResponse::Login(Box::new(
                self.client_credentials(payload).await?,
            )),
            "webauthn" => TokenGrantResponse::Login(Box::new(
                self.webauthn(payload).await?,
            )),
            "send_access" | "access_token" => {
                let access_id = payload
                    .send_id
                    .as_deref()
                    .or(payload.access_id.as_deref())
                    .ok_or_else(|| AppError::bad_request("Missing send_id"))?;
                let password = payload
                    .password_hash_b64
                    .as_deref()
                    .or(payload.password.as_deref());
                TokenGrantResponse::Send(
                    crate::service::send::issue_access_token(
                        self.state,
                        self.headers,
                        access_id,
                        password,
                    )
                    .await?,
                )
            }
            _ => {
                return Err(AppError::Params(
                    "Unsupported grant_type".to_string(),
                ));
            }
        };
        Ok(response)
    }

    async fn validate_account(&self, user: &UserRow) -> AppResult<()> {
        validate_client_version(user, self.headers)?;
        ensure_account_snapshot(self.state.database(), user).await
    }

    async fn password(
        &mut self,
        payload: &TokenRequest,
    ) -> AppResult<oauth::LoginTokenResponse> {
        let db = self.state.database();
        let headers = self.headers;
        let state = self.state;
        let username = payload
            .username
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| AppError::bad_request("Missing username"))?
            .to_lowercase();
        let device = LoginDevice::for_password(payload)?;
        let password_hash = payload
            .access_code
            .as_deref()
            .filter(|_| payload.auth_request_id.is_some())
            .or(payload.password.as_deref())
            .ok_or_else(|| AppError::Params("Missing password".to_string()))?;

        // Check rate limit using email as key to prevent brute force
        // attacks.
        let rate_limit_key = format!("login:{username}");
        rate_limit::check_auth_attempt(state, rate_limit_key).await?;
        rate_limit::check_auth_attempt(
            state,
            format!("login-ip:{}", rate_limit::client_ip(headers)),
        )
        .await?;

        let user = UserRow::fetch_by_email_with(
            db,
            &username,
            "Failed to fetch user for login",
            || AppError::invalid_credentials("Invalid credentials"),
        )
        .await
        .map_err(|e| {
            // Preserve the generic public response without turning a D1
            // outage into an administrative credential-rejection event.
            self.credential_lookup_failed = !rejected_credentials(&e);
            log::warn!("user lookup failed: {e}");
            AppError::invalid_credentials("Invalid credentials")
        })?;

        let auth_request = if let Some(id) = payload.auth_request_id.as_deref()
        {
            Some(
                self.approved_request(id, &user, &device, password_hash)
                    .await?,
            )
        } else {
            None
        };
        let needs_migration = if auth_request.is_none() {
            let verification =
                user::verify_master_password(&user, password_hash).await?;
            if !verification.is_valid() {
                return Err(AppError::Auth(AuthError::InvalidPassword));
            }
            verification.needs_migration()
        } else {
            false
        };

        let two_factor_remember_token = self
            .verify_password_second_factor(payload, &user, &device.id)
            .await?;

        // Upgrade verified passwords only after the complete login proof.
        // Device approvals carry an access code, never a master password.
        let user = if needs_migration {
            let password =
                user::stored_password_for_user(password_hash, &user).await?;
            UserRow::migrate_password_if_current(db, &user, &password).await?;

            // Return updated user
            UserRow {
                master_password_hash: password.hash,
                password_salt: Some(password.salt),
                password_iterations: password.iterations,
                ..user
            }
        } else {
            user
        };

        if let Some(request) = auth_request {
            request.consume(db).await?;
        }
        self.validate_account(&user).await?;
        let device = device.start_session(db, &user).await?;
        let tokens = oauth::IssuedTokens::issue(&user, state, &device)?;
        let response = tokens.login_response(&user, two_factor_remember_token);
        admin_notify::emit(&state.env, Event::Login, &user.id).await;
        Ok(response)
    }

    async fn approved_request(
        &self,
        id: &str,
        user: &UserRow,
        device: &LoginDevice<'_>,
        access_code: &str,
    ) -> AppResult<AuthRequestRow> {
        let db = self.state.database();
        let request = AuthRequestRow::find_by_id(db, id)
            .await?
            .ok_or_else(AppError::auth_request_unavailable)?;
        if !auth_request::auth_request_generation_matches(&request, db).await? {
            return Err(AppError::bad_request(
                "Authentication approval belongs to an older account \
                 encryption state",
            ));
        }
        if !auth_request::auth_request_matches_login(
            &request,
            &user.id,
            &device.id,
            device.device_type,
            rate_limit::client_ip(self.headers),
            access_code,
            &user.security_stamp,
        ) {
            return Err(AppError::invalid_credentials(
                "Invalid authentication request",
            ));
        }
        Ok(request)
    }

    async fn verify_password_second_factor(
        &self,
        payload: &TokenRequest,
        user: &UserRow,
        device_id: &str,
    ) -> AppResult<Option<String>> {
        let db = self.state.database();
        let providers = TwoFactorRow::list_for_user(db, &user.id).await?;
        let login_providers: Vec<_> = providers
            .iter()
            .filter(|factor| factor.requires_login_challenge())
            .collect();
        let Some(first_provider) = login_providers.first() else {
            return Ok(None);
        };
        let provider_types: Vec<_> = login_providers
            .iter()
            .map(|provider| provider.provider_type)
            .collect();
        let selected_id = payload
            .two_factor_provider
            .unwrap_or(first_provider.provider_type);
        let selected = TwoFactorProvider::from_i32(selected_id);
        let recovery_code = user
            .two_factor_recovery_code
            .as_deref()
            .filter(|code| !code.trim().is_empty());
        if selected == Some(TwoFactorProvider::RecoveryCode) &&
            (payload.two_factor_token.is_none() || recovery_code.is_none())
        {
            return Err(AuthError::InvalidTotp.into());
        }

        let Some(code) = &payload.two_factor_token else {
            if selected == Some(TwoFactorProvider::Email) {
                email::issue_login_code(self.state, user).await?;
            }
            return Err(self
                .two_factor_challenge(user, device_id, &provider_types)
                .await?);
        };
        let selected_provider = login_providers.into_iter().find(|provider| {
            provider.provider_type == selected_id && provider.is_enabled
        });
        let remembered = RememberedLogin {
            exchange: self,
            user,
            row: providers.iter().find(|provider| {
                provider.provider_type == TwoFactorProvider::Remember as i32
            }),
            // Remembered tokens use the identifier as supplied by the client.
            device_id: payload.device_id.as_deref(),
            renew: payload.two_factor_remember == Some(1),
        };
        match selected {
            Some(TwoFactorProvider::Authenticator) => {
                self.verify_authenticator(selected_provider, code).await?;
            }
            Some(TwoFactorProvider::Email) => {
                if selected_provider.is_none() {
                    return Err(AppError::bad_request(
                        "Email two-factor is not configured",
                    ));
                }
                email::verify_login_code(self.state, user, code).await?;
            }
            Some(TwoFactorProvider::Webauthn) => {
                if selected_provider.is_none() {
                    return Err(AppError::bad_request(
                        "WebAuthn two-factor is not configured",
                    ));
                }
                webauthn::verify_two_factor_assertion(
                    self.state, user, device_id, code,
                )
                .await?;
            }
            Some(TwoFactorProvider::Remember) => {
                if !remembered.verify(code).await? {
                    return Err(self
                        .two_factor_challenge(
                            user,
                            remembered.device_id.unwrap_or(device_id),
                            &provider_types,
                        )
                        .await?);
                }
            }
            Some(TwoFactorProvider::RecoveryCode) => {
                self.recover(user, recovery_code, code).await?;
            }
            _ => {
                return Err(AppError::Params(
                    "Invalid two factor provider".to_string(),
                ));
            }
        }

        validate_client_version(user, self.headers)?;
        match selected {
            Some(TwoFactorProvider::RecoveryCode) => Ok(None),
            Some(TwoFactorProvider::Remember) => {
                remembered.renew(remembered.row).await
            }
            _ => remembered.renew(selected_provider).await,
        }
    }

    async fn verify_authenticator(
        &self,
        provider: Option<&TwoFactorRow>,
        code: &str,
    ) -> AppResult<()> {
        let provider = provider.ok_or_else(|| {
            AppError::Params("TOTP not configured".to_string())
        })?;
        let new_last_used = validate_totp(
            code,
            &provider.data,
            provider.last_used_step,
            !self.state.config.authenticator_time_drift_disabled,
        )
        .await?;
        TwoFactorRow::update_last_used_step(
            self.state.database(),
            &provider.id,
            new_last_used,
        )
        .await
    }

    async fn recover(
        &self,
        user: &UserRow,
        recovery_code: Option<&str>,
        code: &str,
    ) -> AppResult<()> {
        let recovery_code = recovery_code.ok_or(AuthError::InvalidTotp)?;
        if !constant_time_eq(
            recovery_code.to_uppercase().as_bytes(),
            code.to_uppercase().as_bytes(),
        ) {
            return Err(AuthError::InvalidTotp.into());
        }
        validate_client_version(user, self.headers)?;
        TwoFactorRow::recover_if_current(self.state.database(), user).await?;
        admin_notify::emit(&self.state.env, Event::TwoFactorRecover, &user.id)
            .await;
        Ok(())
    }

    async fn two_factor_challenge(
        &self,
        user: &UserRow,
        device: &str,
        providers: &[i32],
    ) -> AppResult<AppError> {
        let mut provider_details: Map<String, Value> = providers
            .iter()
            .map(|provider| (provider.to_string(), Value::Null))
            .collect();
        if providers.contains(&(TwoFactorProvider::Webauthn as i32)) {
            provider_details.insert(
                "7".to_string(),
                webauthn::two_factor_assertion_options(
                    self.state, user, device,
                )
                .await?,
            );
        }
        if providers.contains(&(TwoFactorProvider::Email as i32)) {
            provider_details.insert(
                "1".to_string(),
                email::login_metadata(self.state.database(), &user.id).await?,
            );
        }
        Ok(AppError::identity_challenge(providers, &provider_details))
    }

    async fn refresh(
        &self,
        payload: &TokenRequest,
    ) -> AppResult<oauth::TokenResponse> {
        let db = self.state.database();
        let state = self.state;
        let refresh_token = payload
            .refresh_token
            .as_deref()
            .ok_or_else(AppError::invalid_refresh_token)?;
        let claims = jwt::decode::<Claims>(
            refresh_token,
            state.jwt_keys.refresh_secret.as_bytes(),
            &jwt::ValidationOptions::default(),
        )
        .map_err(|_error| AppError::invalid_refresh_token())?;
        claims
            .validate_session(db, "refresh")
            .await
            .map_err(|error| {
                if matches!(
                    error,
                    AppError::Auth(_) | AppError::Unauthorized { .. }
                ) {
                    AppError::invalid_refresh_token()
                } else {
                    error
                }
            })?;
        let user = UserRow::fetch_by_id_with(
            db,
            &claims.sub,
            "Failed to fetch refresh token owner",
            AppError::invalid_refresh_token,
        )
        .await?;
        // Keep the account generation from the original proof. A
        // credential rotation can finish after validate_session and
        // before this user read; signing that newer row would revive
        // an otherwise revoked refresh token.
        if !constant_time_eq(
            user.security_stamp.as_bytes(),
            claims.sstamp.as_bytes(),
        ) {
            return Err(AppError::invalid_refresh_token());
        }
        let device = DeviceRow::find_for_user(
            db,
            &claims.sub,
            claims.device().unwrap_or_default(),
        )
        .await?
        .ok_or_else(AppError::invalid_refresh_token)?;
        // Never upgrade an old refresh proof to a concurrently created
        // device nonce just because the row was read after validation.
        if !constant_time_eq(
            device.session_token.as_bytes(),
            claims.session_token.as_bytes(),
        ) {
            return Err(AppError::invalid_refresh_token());
        }
        self.validate_account(&user).await?;
        let tokens = oauth::IssuedTokens::issue(&user, state, &device)?;
        let response = tokens.refresh_response();
        admin_notify::emit(&state.env, Event::TokenRefresh, &user.id).await;
        Ok(response)
    }

    async fn client_credentials(
        &self,
        payload: &TokenRequest,
    ) -> AppResult<oauth::LoginTokenResponse> {
        let db = self.state.database();
        let headers = self.headers;
        let state = self.state;
        let client_id = payload
            .client_id
            .as_deref()
            .ok_or_else(|| AppError::bad_request("Missing client_id"))?;
        let client_secret = payload
            .client_secret
            .as_deref()
            .ok_or_else(|| AppError::bad_request("Missing client_secret"))?;
        let (user, key_hash) = api_key::authenticate(
            state,
            headers,
            client_id,
            client_secret,
            payload.scope.as_deref(),
        )
        .await?;
        self.validate_account(&user).await?;
        let device = LoginDevice::with_required_id(payload)?;
        let device = api_key::start_session(
            db,
            &user.id,
            &device.id,
            device.name,
            device.device_type,
            &key_hash,
        )
        .await?;
        let tokens = oauth::IssuedTokens::issue(&user, state, &device)?;
        let response = tokens.login_response(&user, None);
        admin_notify::emit(&state.env, Event::Login, &user.id).await;
        Ok(response)
    }

    async fn webauthn(
        &self,
        payload: &TokenRequest,
    ) -> AppResult<oauth::LoginTokenResponse> {
        let db = self.state.database();
        let headers = self.headers;
        let state = self.state;
        rate_limit::check_auth_attempt(
            state,
            format!("passkey-login:{}", rate_limit::client_ip(headers)),
        )
        .await?;
        let challenge = payload.token.as_deref().ok_or_else(|| {
            AppError::bad_request("Missing passkey challenge token")
        })?;
        let assertion = payload
            .device_response
            .as_deref()
            .ok_or_else(|| AppError::bad_request("Missing deviceResponse"))?;
        let device_id = payload
            .device_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AppError::bad_request("Missing deviceIdentifier"))?;
        let result = webauthn::verify_passwordless(
            state, challenge, assertion, device_id,
        )
        .await?;
        let user = UserRow::fetch_by_id_with(
            db,
            &result.user_id,
            "Failed to fetch passkey owner",
            || AuthError::UserNotFound.into(),
        )
        .await?;
        self.validate_account(&user).await?;
        if result.account_snapshot !=
            crate::models::identity::account_keys::AccountSnapshot::from_user(
                &user,
            )
            .to_json()?
        {
            return Err(AppError::conflict(
                "Account encryption changed during passkey login",
            ));
        }
        let device = LoginDevice::with_required_id(payload)?
            .start_session(db, &user)
            .await?;
        let tokens = oauth::IssuedTokens::issue(&user, state, &device)?;
        let mut response = tokens.login_response(&user, None);
        if let (Some(encrypted_user_key), Some(encrypted_private_key)) =
            (result.encrypted_user_key, result.encrypted_private_key)
        {
            response.user_decryption_options.webauthn_prf_option =
                Some(oauth::WebauthnPrfOption {
                    encrypted_user_key,
                    encrypted_private_key,
                });
        }
        admin_notify::emit(&state.env, Event::WebauthnLogin, &user.id).await;
        Ok(response)
    }
}

/// The stored remembered-login row used for proof and guarded renewal.
struct RememberedLogin<'a> {
    exchange:  &'a TokenExchange<'a>,
    user:      &'a UserRow,
    row:       Option<&'a TwoFactorRow>,
    device_id: Option<&'a str>,
    renew:     bool,
}

impl RememberedLogin<'_> {
    async fn verify(&self, code: &str) -> AppResult<bool> {
        let Some((device_id, provider)) = self.device_id.zip(self.row) else {
            return Ok(false);
        };
        let days = self.exchange.state.config.two_factor_remember_days;
        let mut tokens = RememberedDevices::from_json(&provider.data);
        tokens.remove_expired(days);
        if !tokens.validate(device_id, code, days) {
            return Ok(false);
        }
        // Confirm the bypass is still current even without renewal.
        if !self.renew {
            validate_client_version(self.user, self.exchange.headers)?;
            TwoFactorRow::persist_remember_if_current(
                self.exchange.state.database(),
                self.user,
                provider,
                Some(provider),
                &provider.data,
            )
            .await?;
        }
        Ok(true)
    }

    async fn renew(
        &self,
        verified_factor: Option<&TwoFactorRow>,
    ) -> AppResult<Option<String>> {
        let Some(device_id) = self.device_id.filter(|_| self.renew) else {
            return Ok(None);
        };
        let token = uuid::Uuid::new_v4().to_string();
        let mut tokens = self
            .row
            .map_or_else(RememberedDevices::default, |provider| {
                RememberedDevices::from_json(&provider.data)
            });
        tokens.remove_expired(
            self.exchange.state.config.two_factor_remember_days,
        );
        tokens.upsert(device_id.to_owned(), &token);
        let verified_factor = verified_factor.ok_or_else(|| {
            AppError::bad_request("Missing verified second factor")
        })?;
        TwoFactorRow::persist_remember_if_current(
            self.exchange.state.database(),
            self.user,
            verified_factor,
            self.row,
            &tokens.to_json(),
        )
        .await?;
        Ok(Some(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_credential_rejections_are_login_failures() {
        for error in [
            AuthError::InvalidPassword,
            AuthError::InvalidTotp,
            AuthError::UserNotFound,
            AuthError::InvalidCredentials("rejected".into()),
        ] {
            assert!(rejected_credentials(&AppError::Auth(error)));
        }
        for error in [
            AppError::TooManyRequests {
                message: "limited".into(),
            },
            AppError::Database(crate::errors::DatabaseError::QueryFailed(
                "unavailable".into(),
            )),
            AppError::Params("missing password".into()),
            AppError::OAuth {
                error:       "version_header_missing",
                description: "unsupported client",
            },
            AppError::IdentityChallenge(
                serde_json::json!({"TwoFactorProviders":[0]}),
            ),
            AppError::Internal,
        ] {
            assert!(!rejected_credentials(&error));
        }
    }

    #[test]
    fn token_form_accepts_both_device_and_twofactor_spellings() {
        for (id, kind, provider, proof) in [
            (
                "device_id",
                "device_type",
                "two_factor_provider",
                "two_factor_token",
            ),
            (
                "deviceIdentifier",
                "deviceType",
                "twoFactorProvider",
                "twoFactorToken",
            ),
        ] {
            let fields = [
                ("grant_type", "password"),
                (id, "device"),
                (kind, "2 "),
                (provider, "0 "),
                (proof, " opaque proof "),
            ];
            let request = TokenRequest::from_form(
                fields
                    .into_iter()
                    .map(|(key, value)| (key.into(), value.into()))
                    .collect(),
                &HeaderMap::new(),
                true,
            )
            .expect("valid identity fixture");
            assert_eq!(request.device_id.as_deref(), Some("device"));
            assert_eq!(request.device_type, Some(2));
            assert_eq!(request.two_factor_provider, Some(0));
            assert_eq!(
                request.two_factor_token.as_deref(),
                Some(" opaque proof ")
            );
        }
    }
}

fn validate_client_version(
    user: &UserRow,
    headers: &HeaderMap,
) -> AppResult<()> {
    let version = headers
        .get("bitwarden-client-version")
        .and_then(|v| v.to_str().ok())
        .and_then(crate::utils::version::parse)
        .ok_or_else(AppError::client_version_header_missing)?;
    if user::has_v2_encryption(user) {
        let device = headers
            .get("device-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(14);
        let minimum = if matches!(device, 6 | 7 | 8 | 16) {
            (2026, 10, 2)
        } else {
            (2026, 10, 1)
        };
        if version.0 < minimum || (version.0 == minimum && version.1) {
            return Err(AppError::invalid_client_version());
        }
    }
    Ok(())
}
async fn ensure_account_snapshot(
    db: &worker::D1Database,
    user: &UserRow,
) -> AppResult<()> {
    let current = UserRow::fetch_by_id_with(
        db,
        &user.id,
        "Failed to verify authentication snapshot",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    if current.master_password_hash != user.master_password_hash ||
        current.password_salt != user.password_salt ||
        current.password_iterations != user.password_iterations ||
        current.security_stamp != user.security_stamp ||
        crate::models::identity::account_keys::AccountSnapshot::from_user(
            &current,
        ) !=
            crate::models::identity::account_keys::AccountSnapshot::from_user(
                user,
            )
    {
        return Err(AppError::conflict(
            "Account encryption changed during authentication. Retry login.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod account_version_tests {
    use super::*;
    #[test]
    fn version_gate_is_applied_to_v2_and_desktop_boundaries() {
        let mut user:UserRow=serde_json::from_value(serde_json::json!({"id":"owner","email":"owner@example.test","is_email_verified":0,"master_password_hash":"hash","key":"wrapped-user","private_key":"2.private","public_key":"public","kdf_type":0,"kdf_iterations":600_000,"security_stamp":"stamp","created_at":"now","updated_at":"now"})).expect("valid identity fixture");
        let mut headers = HeaderMap::new();
        assert!(matches!(
            validate_client_version(&user, &headers),
            Err(AppError::OAuth {
                error: "version_header_missing",
                ..
            })
        ));
        headers.insert(
            "bitwarden-client-version",
            "2026.7.0".parse().expect("valid identity fixture"),
        );
        assert!(validate_client_version(&user, &headers).is_ok());
        user.security_version = Some(2);
        user.private_key = "7.private".into();
        assert!(validate_client_version(&user, &headers).is_err());
        headers.insert(
            "bitwarden-client-version",
            "2026.10.1".parse().expect("valid identity fixture"),
        );
        assert!(validate_client_version(&user, &headers).is_ok());
        headers.insert(
            "device-type",
            "6".parse().expect("valid identity fixture"),
        );
        assert!(validate_client_version(&user, &headers).is_err());
        headers.insert(
            "bitwarden-client-version",
            "2026.10.2".parse().expect("valid identity fixture"),
        );
        assert!(validate_client_version(&user, &headers).is_ok());
        for (version, accepted) in [
            ("2026.10.2-beta.1", false),
            ("2026.11.0-beta.1+build", true),
        ] {
            headers.insert(
                "bitwarden-client-version",
                version.parse().expect("valid identity fixture"),
            );
            assert_eq!(
                validate_client_version(&user, &headers).is_ok(),
                accepted,
                "{version}"
            );
        }
    }
}
