mod api_key;
mod form;
mod password;
mod refresh;
mod webauthn;

use std::{borrow::Cow, sync::Arc};

use axum::{
    Form,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use self::form::{DeviceForm, GrantRequest};
use crate::{
    api::{
        AppState,
        common::{
            extract::{ClientIp, ClientVersionHeader},
            response::{ApiResponse, NoStore, WithCookies},
        },
    },
    errors::{AppError, AppResult, AuthError},
    models::identity::{
        device::{NewDeviceSession, SessionSnapshot},
        user::UserRow,
    },
    service::{
        identity::{oauth, session::new_session_token, user},
        notifications::{admin as admin_notify, admin::Event},
        send::SendAccessTokenResponse,
    },
    utils::version::ParsedVersion,
};

type TokenForm = Form<Vec<(String, String)>>;

#[worker::send]
pub(in crate::api) async fn exchange_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ClientIp(client_ip): ClientIp,
    ClientVersionHeader(version): ClientVersionHeader,
    form: Result<TokenForm, FormRejection>,
) -> AppResult<Response> {
    let Form(fields) = match form {
        Ok(form) => form,
        Err(error) => return Ok(token_form_rejection(&error)),
    };
    let allow_token_cookies = oauth::allows_token_cookie_origin(&headers, state.domain());
    let payload = GrantRequest::parse(fields, &headers, allow_token_cookies)?;
    let exchange = TokenExchange {
        state: &state,
        headers: &headers,
        client_ip: &client_ip,
        version,
    };
    let result = exchange.redeem(&payload).await;
    if payload.is_login() && matches!(&result, Err(error) if rejected_credentials(error)) {
        admin_notify::emit(&state.env, Event::LoginFailed, "unidentified").await;
    }
    let result = result?;
    let mut cookies = Vec::new();
    if allow_token_cookies {
        if let Some(token) = result.refresh_token() {
            cookies.push(oauth::refresh_cookie_header(state.domain(), token)?);
        }
        if let TokenGrantResponse::Login(login) = &result
            && let Some(token) = login.two_factor_token.as_deref()
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
    Ok(WithCookies {
        response: NoStore(ApiResponse(result)),
        cookies,
    }
    .into_response())
}

fn token_form_rejection(error: &FormRejection) -> Response {
    let status = error.status();
    let message = match status {
        StatusCode::PAYLOAD_TOO_LARGE => "Token form is too large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "Expected application/x-www-form-urlencoded",
        _ => "Invalid token form",
    };
    (status, AppError::invalid_token_request(message)).into_response()
}

const fn rejected_credentials(error: &AppError) -> bool {
    matches!(
        error,
        AppError::Auth(
            AuthError::UserNotFound
                | AuthError::InvalidCredentials(_)
                | AuthError::InvalidPassword
                | AuthError::InvalidTotp
                | AuthError::AccountLocked
        )
    )
}

struct LoginDevice<'a> {
    id: Cow<'a, str>,
    name: &'a str,
    device_type: i32,
}

impl<'a> LoginDevice<'a> {
    fn for_password(payload: &'a DeviceForm) -> AppResult<Self> {
        let id = payload
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map_or_else(
                || Cow::Owned(uuid::Uuid::new_v4().to_string()),
                Cow::Borrowed,
            );
        Self::new(payload, id)
    }

    fn with_required_id(payload: &'a DeviceForm) -> AppResult<Self> {
        let id = payload
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AppError::invalid_token_request("Missing deviceIdentifier"))?;
        Self::new(payload, Cow::Borrowed(id))
    }

    fn new(payload: &'a DeviceForm, id: Cow<'a, str>) -> AppResult<Self> {
        let name = payload.name.as_deref().unwrap_or("Unknown Device");
        let device_type = payload.kind.unwrap_or(14);
        if id.len() > 256 || name.len() > 256 || !(0..=40).contains(&device_type) {
            return Err(AppError::invalid_token_request(
                "Invalid device information",
            ));
        }
        Ok(Self {
            id,
            name,
            device_type,
        })
    }

    fn new_session<'b>(&'b self, nonce: &'b str) -> NewDeviceSession<'b> {
        NewDeviceSession {
            device_id: &self.id,
            name: self.name,
            device_type: self.device_type,
            nonce,
        }
    }

    fn prepare_tokens(
        &self,
        user: &UserRow,
        state: &AppState,
    ) -> AppResult<(String, oauth::IssuedTokens)> {
        let nonce = new_session_token();
        let session = SessionSnapshot {
            user_id: &user.id,
            security_stamp: &user.security_stamp,
            device_id: &self.id,
            session_token: &nonce,
        };
        let tokens = oauth::IssuedTokens::issue(
            user,
            &session,
            &state.jwt_keys,
            state.config.jwt_duration_seconds,
        )?;
        Ok((nonce, tokens))
    }
}

struct TokenExchange<'a> {
    state: &'a AppState,
    headers: &'a HeaderMap,
    client_ip: &'a str,
    version: Option<ParsedVersion>,
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
    async fn redeem(&self, payload: &GrantRequest) -> AppResult<TokenGrantResponse> {
        let response = match payload {
            GrantRequest::Password(payload) => {
                TokenGrantResponse::Login(Box::new(self.password(payload).await?))
            }
            GrantRequest::Refresh(token) => {
                TokenGrantResponse::Refresh(self.refresh(token.as_deref()).await?)
            }
            GrantRequest::ApiKey(payload) => {
                TokenGrantResponse::Login(Box::new(self.client_credentials(payload).await?))
            }
            GrantRequest::Webauthn(payload) => {
                TokenGrantResponse::Login(Box::new(self.webauthn(payload).await?))
            }
            GrantRequest::Send(payload) => {
                let access_id = payload
                    .id
                    .as_deref()
                    .ok_or_else(|| AppError::invalid_token_request("Missing send_id"))?;
                let password = payload.password.as_deref();
                TokenGrantResponse::Send(
                    crate::service::send::issue_access_token(
                        self.state.database(),
                        &self.state.env,
                        &self.state.jwt_keys.access_secret,
                        self.headers,
                        access_id,
                        password,
                    )
                    .await?,
                )
            }
        };
        Ok(response)
    }

    async fn validate_account(&self, user: &UserRow) -> AppResult<()> {
        self.validate_client_version(user)?;
        ensure_account_snapshot(self.state.database(), user).await
    }

    fn validate_client_version(&self, user: &UserRow) -> AppResult<()> {
        validate_client_version(user, self.version, self.headers)
    }
}

fn validate_client_version(
    user: &UserRow,
    version: Option<ParsedVersion>,
    headers: &HeaderMap,
) -> AppResult<()> {
    let version = version.ok_or(AppError::OAuth {
        error: "version_header_missing",
        description: "No client version header found, required to prevent \
                          encryption errors. Please confirm your client is \
                          supplying the header: \"Bitwarden-Client-Version\"",
    })?;
    if user::has_v2_encryption(user) {
        let device = headers
            .get("device-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(14);
        let patch = if matches!(device, 6 | 7 | 8 | 16) {
            2
        } else {
            1
        };
        if !version.satisfies_minimum(2026, 10, patch) {
            return Err(AppError::OAuth {
                error: "invalid_client_version",
                description: "Please update your app to continue using \
                              Bitwarden",
            });
        }
    }
    Ok(())
}
async fn ensure_account_snapshot(db: &worker::D1Database, user: &UserRow) -> AppResult<()> {
    let current = UserRow::fetch_by_id_with(
        db,
        &user.id,
        "Failed to verify authentication snapshot",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    if current.master_password_hash != user.master_password_hash
        || current.password_salt != user.password_salt
        || current.password_iterations != user.password_iterations
        || current.security_stamp != user.security_stamp
        || !crate::models::identity::account_keys::AccountSnapshot::users_match(&current, user)
    {
        return Err(AppError::conflict(
            "Account encryption changed during authentication. Retry login.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_rejections_and_client_version_gates_match_policy() {
        assert!(rejected_credentials(&AppError::Auth(
            AuthError::InvalidPassword
        )));
        assert!(!rejected_credentials(&AppError::TooManyRequests {
            message: "limited".into()
        }));
        assert!(!rejected_credentials(&AppError::IdentityChallenge(
            serde_json::json!({})
        )));

        let mut user: UserRow = serde_json::from_value(serde_json::json!({
            "id": "owner", "email": "owner@example.test", "is_email_verified": 0,
            "master_password_hash": "hash", "key": "wrapped", "private_key": "2.private",
            "public_key": "public", "kdf_type": 0, "kdf_iterations": 600_000,
            "security_stamp": "stamp", "created_at": "now", "updated_at": "now"
        }))
        .expect("user");
        let mut headers = HeaderMap::new();
        assert!(
            validate_client_version(
                &user,
                ClientVersionHeader::from_headers(&headers).0,
                &headers
            )
            .is_err()
        );
        headers.insert("bitwarden-client-version", "2026.7.0".parse().expect("hdr"));
        assert!(
            validate_client_version(
                &user,
                ClientVersionHeader::from_headers(&headers).0,
                &headers
            )
            .is_ok()
        );
        user.security_version = Some(2);
        user.private_key = "7.private".into();
        assert!(
            validate_client_version(
                &user,
                ClientVersionHeader::from_headers(&headers).0,
                &headers
            )
            .is_err()
        );
        headers.insert(
            "bitwarden-client-version",
            "2026.10.2".parse().expect("hdr"),
        );
        headers.insert("device-type", "6".parse().expect("hdr"));
        assert!(
            validate_client_version(
                &user,
                ClientVersionHeader::from_headers(&headers).0,
                &headers
            )
            .is_ok()
        );
    }
}
