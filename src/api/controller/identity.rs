use axum::{
    Form,
    Json,
    extract::State,
    http::HeaderMap,
};
use serde::{
    Deserialize,
    Deserializer,
};

use crate::{
    api::{
        AppState,
        service::{
            api_key,
            auth,
            claims::Claims,
            email,
            rate,
            webauthn,
        },
    },
    errors::{
        AppError,
        AuthError,
    },
    infra::{
        admin_notify::{
            self,
            Event,
        },
        crypto::{
            ct_eq,
            generate_salt,
            hash_password_for_storage,
            validate_totp,
        },
        jwt,
    },
    models::{
        api_key::ApiKeyDB,
        auth_request::AuthRequestDB,
        device::DeviceDB,
        twofactor::{
            RememberTokenData,
            TwoFactorDB,
            TwoFactorType,
        },
        user::UserDB,
    },
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
pub struct TokenRequest {
    grant_type:          String,
    username:            Option<String>,
    password:            Option<String>, // This is the masterPasswordHash
    refresh_token:       Option<String>,
    // 2FA fields
    #[serde(rename = "twoFactorToken", alias = "two_factor_token")]
    two_factor_token:    Option<String>,
    #[serde(
        rename = "twoFactorProvider",
        alias = "two_factor_provider",
        default,
        deserialize_with = "deserialize_trimmed_i32"
    )]
    two_factor_provider: Option<i32>,
    #[serde(
        rename = "twoFactorRemember",
        alias = "two_factor_remember",
        default,
        deserialize_with = "deserialize_trimmed_i32"
    )]
    two_factor_remember: Option<i32>,
    #[serde(rename = "deviceIdentifier", alias = "device_identifier")]
    device_identifier:   Option<String>,
    #[serde(rename = "deviceName", alias = "device_name")]
    device_name:         Option<String>,
    #[serde(
        rename = "deviceType",
        alias = "device_type",
        default,
        deserialize_with = "deserialize_trimmed_i32"
    )]
    device_type:         Option<i32>,
    #[serde(
        rename = "authRequest",
        alias = "authrequest",
        alias = "auth_request"
    )]
    auth_request:        Option<String>,
    send_id:             Option<String>,
    access_id:           Option<String>,
    password_hash_b64:   Option<String>,
    client_id:           Option<String>,
    client_secret:       Option<String>,
    scope:               Option<String>,
    token:               Option<String>,
    #[serde(rename = "deviceResponse", alias = "device_response")]
    device_response:     Option<String>,
}

#[worker::send]
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let login_attempt = matches!(
        payload.grant_type.as_str(),
        "password" | "client_credentials" | "webauthn"
    );
    let mut credential_lookup_failed = false;
    let result = async {
    let db = state.get_db();
    match payload.grant_type.as_str() {
        "password" => {
            let username = payload
                .username
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| AppError::bad_request("Missing username"))?
                .to_lowercase();
            let identifier = payload
                .device_identifier
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map_or_else(
                    || uuid::Uuid::new_v4().to_string(),
                    str::to_string,
                );
            let device_name =
                payload.device_name.as_deref().unwrap_or("Unknown Device");
            let device_type = payload.device_type.unwrap_or(14);
            if identifier.len() > 256 ||
                device_name.len() > 256 ||
                !(0..=40).contains(&device_type)
            {
                return Err(AppError::bad_request(
                    "Invalid device information",
                ));
            }
            let password_hash = payload.password.ok_or_else(|| {
                AppError::Params("Missing password".to_string())
            })?;

            // Check rate limit using email as key to prevent brute force
            // attacks.
            let rate_limit_key = format!("login:{}", username.to_lowercase());
            rate::check_rate_limit(&state, rate_limit_key).await?;
            rate::check_rate_limit(
                &state,
                format!("login-ip:{}", rate::client_ip(&headers)),
            )
            .await?;

            let user = UserDB::fetch_by_email_with(
                &db,
                &username,
                "Failed to fetch user for login",
                || {
                    AppError::Auth(AuthError::InvalidCredentials(
                        "Invalid credentials".to_string(),
                    ))
                },
            )
            .await
            .map_err(|e| {
                // Preserve the generic public response without turning a D1
                // outage into an administrative credential-rejection event.
                credential_lookup_failed = !rejected_credentials(&e);
                log::warn!("user lookup failed: {e}");
                AppError::Auth(AuthError::InvalidCredentials(
                    "Invalid credentials".to_string(),
                ))
            })?;

            let auth_request = if let Some(id) = payload.auth_request.as_deref()
            {
                let request = AuthRequestDB::find_by_id(&db, id)
                    .await?
                    .ok_or_else(|| {
                        AppError::bad_request(
                            "Authentication request is unavailable",
                        )
                    })?;
                if !request.generation_valid(&db).await? {
                    return Err(AppError::bad_request(
                        "Authentication approval belongs to an older account \
                         encryption state",
                    ));
                }
                if !request.matches_login(
                    &user.id,
                    &identifier,
                    device_type,
                    rate::client_ip(&headers),
                    &password_hash,
                    &user.security_stamp,
                ) {
                    return Err(AppError::Auth(AuthError::InvalidCredentials(
                        "Invalid authentication request".to_string(),
                    )));
                }
                Some(request)
            } else {
                None
            };
            let needs_migration = if auth_request.is_none() {
                let verification =
                    user.verify_master_password(&password_hash).await?;
                if !verification.is_valid() {
                    return Err(AppError::Auth(AuthError::InvalidPassword));
                }
                verification.needs_migration()
            } else {
                false
            };

            // Check for 2FA
            let twofactors =
                TwoFactorDB::list_user_twofactors(&db, &user.id).await?;

            let mut two_factor_remember_token: Option<String> = None;

            // Filter out Remember type - it's not a real 2FA provider, just a
            // convenience feature
            let real_twofactors: Vec<&TwoFactorDB> = twofactors
                .iter()
                .filter(|factor| factor.requires_login_challenge())
                .collect();

            if !real_twofactors.is_empty() {
                // 2FA is enabled, need to verify
                // Only show real 2FA providers to client (not Remember)
                let twofactor_ids: Vec<i32> =
                    real_twofactors.iter().map(|tf| tf.atype).collect();
                let selected_id =
                    payload.two_factor_provider.unwrap_or(twofactor_ids[0]);

                let Some(twofactor_code) = &payload.two_factor_token else {
                    // Return 2FA required error
                    if selected_id == TwoFactorType::Email as i32 {
                        email::issue_login_code(&state, &user).await?;
                    }
                    return Err(twofactor_challenge(
                        &state,
                        &user,
                        &identifier,
                        &twofactor_ids,
                    )
                    .await?);
                };

                // Find the selected twofactor from real_twofactors
                let selected_twofactor = real_twofactors
                    .iter()
                    .find(|tf| tf.atype == selected_id && tf.enabled)
                    .copied();

                match TwoFactorType::from_i32(selected_id) {
                    Some(TwoFactorType::Authenticator) => {
                        let Some(tf) = selected_twofactor else {
                            return Err(AppError::Params(
                                "TOTP not configured".to_string(),
                            ));
                        };

                        // Validate TOTP code
                        let allow_drift =
                            !state.config.authenticator_disable_time_drift;
                        let new_last_used = validate_totp(
                            twofactor_code,
                            &tf.data,
                            tf.last_used,
                            allow_drift,
                        )
                        .await?;

                        // Update last_used
                        TwoFactorDB::update_last_used(
                            &db,
                            &tf.uuid,
                            new_last_used,
                        )
                        .await?;
                    }
                    Some(TwoFactorType::Email) => {
                        if selected_twofactor.is_none() {
                            return Err(AppError::bad_request(
                                "Email two-factor is not configured",
                            ));
                        }
                        email::verify_login_code(&state, &user, twofactor_code)
                            .await?;
                    }
                    Some(TwoFactorType::Webauthn) => {
                        if selected_twofactor.is_none() {
                            return Err(AppError::bad_request(
                                "WebAuthn two-factor is not configured",
                            ));
                        }
                        webauthn::verify_2fa(
                            &state,
                            &user,
                            &identifier,
                            twofactor_code,
                        )
                        .await?;
                    }
                    Some(TwoFactorType::Remember) => {
                        // Remember is handled separately - client sends
                        // remember token from previous login
                        // Check remember token against stored value for this
                        // device
                        if let Some(ref device_id) = payload.device_identifier {
                            // Find remember token in twofactors (not
                            // real_twofactors)
                            let remember_tf = twofactors.iter().find(|tf| {
                                tf.atype == TwoFactorType::Remember as i32
                            });

                            if let Some(tf) = remember_tf {
                                // Parse stored remember tokens as JSON
                                let mut token_data =
                                    RememberTokenData::from_json(&tf.data);

                                // Remove expired tokens first
                                token_data.remove_expired();

                                // Validate the provided token
                                if !token_data
                                    .validate(device_id, twofactor_code)
                                {
                                    return Err(twofactor_challenge(
                                        &state,
                                        &user,
                                        &identifier,
                                        &twofactor_ids,
                                    )
                                    .await?);
                                }

                                // Update database with cleaned tokens (remove
                                // expired)
                                let updated_data = token_data.to_json();
                                TwoFactorDB::update_data(
                                    &db,
                                    &tf.uuid,
                                    &updated_data,
                                )
                                .await?;

                                // Remember token valid, proceed with login
                            } else {
                                return Err(twofactor_challenge(
                                    &state,
                                    &user,
                                    &identifier,
                                    &twofactor_ids,
                                )
                                .await?);
                            }
                        } else {
                            return Err(twofactor_challenge(
                                &state,
                                &user,
                                &identifier,
                                &twofactor_ids,
                            )
                            .await?);
                        }
                    }
                    Some(TwoFactorType::RecoveryCode) => {
                        // Check recovery code
                        if let Some(ref stored_code) = user.totp_recover {
                            let stored_upper = stored_code.to_uppercase();
                            let provided_upper = twofactor_code.to_uppercase();
                            if !ct_eq(
                                stored_upper.as_str(),
                                provided_upper.as_str(),
                            ) {
                                return Err(AppError::Auth(
                                    AuthError::InvalidTotp,
                                ));
                            }

                            // Delete all 2FA and clear recovery code
                            TwoFactorDB::delete_for_user(&db, &user.id).await?;
                            crate::models::webauthn::CredentialDB::purge_2fa(
                                &db, &user.id,
                            )
                            .await?;
                            crate::models::email::EmailDB::invalidate_user(
                                &db, &user.id,
                            )
                            .await?;
                            UserDB::clear_recovery_code(&db, &user.id).await?;
                            admin_notify::emit(&state.env, Event::TwoFactorRecover, &user.id).await;

                        } else {
                            return Err(AppError::Auth(AuthError::InvalidTotp));
                        }
                    }
                    _ => {
                        return Err(AppError::Params(
                            "Invalid two factor provider".to_string(),
                        ));
                    }
                }

                // Generate remember token if requested
                if payload.two_factor_remember == Some(1) &&
                    let Some(ref device_id) = payload.device_identifier
                {
                    let remember_token = uuid::Uuid::new_v4().to_string();

                    // Load existing remember tokens or create new
                    let remember_tf = twofactors
                        .iter()
                        .find(|tf| tf.atype == TwoFactorType::Remember as i32);

                    let mut token_data = remember_tf
                        .map(|tf| RememberTokenData::from_json(&tf.data))
                        .unwrap_or_default();

                    // Remove expired tokens first
                    token_data.remove_expired();

                    // Add/update token for this device
                    token_data
                        .upsert(device_id.clone(), remember_token.clone());

                    let json_data = token_data.to_json();

                    TwoFactorDB::upsert_remember_token(
                        &db, &user.id, &json_data,
                    )
                    .await?;

                    two_factor_remember_token = Some(remember_token);
                }
            }

            // Migrate legacy user to PBKDF2 if password matches and no salt
            // exists
            let user = if needs_migration {
                // Generate new salt and hash the password
                let new_salt = generate_salt()?;
                let new_hash =
                    hash_password_for_storage(&password_hash, &new_salt)
                        .await?;
                let now = crate::infra::time::now_rfc3339();

                // Update user in database
                UserDB::migrate_legacy_password_if_current(
                    &db, &user, &new_hash, &new_salt, &now,
                )
                .await?;

                // Return updated user
                UserDB {
                    master_password_hash: new_hash,
                    password_salt: Some(new_salt),
                    updated_at: now,
                    ..user
                }
            } else {
                user
            };

            if let Some(request) = auth_request {
                request.consume(&db).await?;
            }
            validate_client_version(&user, &headers)?;
            ensure_account_snapshot(&db, &user).await?;
            let device = DeviceDB::start_session(
                &db,
                &user.id,
                &identifier,
                device_name,
                device_type,
            )
            .await?;
            let response = generate_tokens_and_response(
                &user,
                &state,
                &device,
                two_factor_remember_token,
            )?;
            admin_notify::emit(&state.env, Event::Login, &user.id).await;
            Ok(response)
        }
        "refresh_token" => {
            let refresh_token = payload.refresh_token.ok_or_else(|| {
                AppError::bad_request("Missing refresh_token")
            })?;
            let claims = jwt::decode::<Claims>(
                &refresh_token,
                state.config.jwt_refresh_secret.as_bytes(),
                &jwt::ValidationOptions::default(),
            )?
            .claims;
            claims.validate_session(&db, "refresh").await?;
            let user = UserDB::fetch_by_id_with(
                &db,
                &claims.sub,
                "Failed to fetch refresh token owner",
                || AppError::Auth(AuthError::UserNotFound),
            )
            .await?;
            let device = DeviceDB::find_for_user(
                &db,
                &claims.sub,
                claims.device().unwrap_or_default(),
            )
            .await?
            .ok_or_else(|| {
                AppError::Auth(AuthError::InvalidCredentials(
                    "Session expired".to_string(),
                ))
            })?;
            validate_client_version(&user, &headers)?;
            ensure_account_snapshot(&db, &user).await?;
            let response = generate_tokens_and_response(&user, &state, &device, None)?;
            admin_notify::emit(&state.env, Event::TokenRefresh, &user.id).await;
            Ok(response)
        }
        "client_credentials" => {
            let client_id = payload
                .client_id
                .as_deref()
                .ok_or_else(|| AppError::bad_request("Missing client_id"))?;
            let client_secret =
                payload.client_secret.as_deref().ok_or_else(|| {
                    AppError::bad_request("Missing client_secret")
                })?;
            let (user, key_hash) = api_key::authenticate(
                &state,
                &headers,
                client_id,
                client_secret,
                payload.scope.as_deref(),
            )
            .await?;
            validate_client_version(&user, &headers)?;
            ensure_account_snapshot(&db, &user).await?;
            let device = start_grant_session(&state, &user, &payload).await?;
            ApiKeyDB::bind_session(
                &db,
                &user.id,
                &device.identifier,
                &device.session_token,
                &key_hash,
            )
            .await?;
            let mut response =
                generate_tokens_and_response(&user, &state, &device, None)?;
            response.0["scope"] = serde_json::json!("api offline_access");
            admin_notify::emit(&state.env, Event::Login, &user.id).await;
            Ok(response)
        }
        "webauthn" => {
            rate::check_rate_limit(
                &state,
                format!("passkey-login:{}", rate::client_ip(&headers)),
            )
            .await?;
            let challenge = payload.token.as_deref().ok_or_else(|| {
                AppError::bad_request("Missing passkey challenge token")
            })?;
            let assertion =
                payload.device_response.as_deref().ok_or_else(|| {
                    AppError::bad_request("Missing deviceResponse")
                })?;
            let identifier = payload
                .device_identifier
                .as_deref()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    AppError::bad_request("Missing deviceIdentifier")
                })?;
            let result = webauthn::verify_passwordless(
                &state, challenge, assertion, identifier,
            )
            .await?;
            let user = UserDB::fetch_by_id_with(
                &db,
                &result.user_id,
                "Failed to fetch passkey owner",
                || AuthError::UserNotFound.into(),
            )
            .await?;
            validate_client_version(&user, &headers)?;
            ensure_account_snapshot(&db, &user).await?;
            if result.account_snapshot !=
                crate::models::account_keys::AccountSnapshot::from_user(
                    &user,
                )
                .to_json()?
            {
                return Err(AppError::conflict(
                    "Account encryption changed during passkey login",
                ));
            }
            let device = start_grant_session(&state, &user, &payload).await?;
            let mut response =
                generate_tokens_and_response(&user, &state, &device, None)?;
            if let (Some(encrypted_user_key), Some(encrypted_private_key)) =
                (result.encrypted_user_key, result.encrypted_private_key)
            {
                response.0["UserDecryptionOptions"]["WebAuthnPrfOption"] = serde_json::json!({"EncryptedUserKey":encrypted_user_key,"EncryptedPrivateKey":encrypted_private_key});
            }
            admin_notify::emit(&state.env, Event::WebAuthnLogin, &user.id).await;
            Ok(response)
        }
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
            Ok(Json(
                crate::send::issue_access_token(
                    &state, &headers, access_id, password,
                )
                .await?,
            ))
        }
        _ => Err(AppError::Params("Unsupported grant_type".to_string())),
    }
    }.await;
    if login_attempt &&
        !credential_lookup_failed &&
        matches!(&result, Err(error) if rejected_credentials(error))
    {
        admin_notify::emit(&state.env, Event::LoginFailed, "unidentified")
            .await;
    }
    result
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

async fn start_grant_session(
    state: &AppState,
    user: &UserDB,
    payload: &TokenRequest,
) -> Result<DeviceDB, AppError> {
    let identifier = payload
        .device_identifier
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| AppError::bad_request("Missing deviceIdentifier"))?;
    let name = payload.device_name.as_deref().unwrap_or("Unknown Device");
    let device_type = payload.device_type.unwrap_or(14);
    if identifier.len() > 256 ||
        name.len() > 256 ||
        !(0..=40).contains(&device_type)
    {
        return Err(AppError::bad_request("Invalid device information"));
    }
    DeviceDB::start_session(
        &state.get_db(),
        &user.id,
        identifier,
        name,
        device_type,
    )
    .await
}

async fn twofactor_challenge(
    state: &AppState,
    user: &UserDB,
    device: &str,
    providers: &[i32],
) -> Result<AppError, AppError> {
    let mut response = crate::api::response::twofactor_json(providers);
    if providers.contains(&(TwoFactorType::Webauthn as i32)) {
        response["TwoFactorProviders2"]["7"] =
            webauthn::issue_2fa_options(state, user, device).await?;
    }
    if providers.contains(&(TwoFactorType::Email as i32)) {
        response["TwoFactorProviders2"]["1"] =
            email::login_metadata(&state.get_db(), &user.id).await?;
    }
    Ok(AppError::IdentityChallenge(response))
}

fn generate_tokens_and_response(
    user: &UserDB,
    state: &AppState,
    device: &DeviceDB,
    two_factor_token: Option<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (access_token, refresh_token, expires_in) =
        auth::generate_tokens(user, state, device)?;
    Ok(Json(auth::token_response_json(
        user,
        &access_token,
        &refresh_token,
        expires_in,
        two_factor_token,
    )))
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
        let request: TokenRequest = serde_json::from_value(serde_json::json!({
            "grant_type": "password", "device_identifier": "device",
            "device_type": "2 ", "two_factor_provider": "0 "
        }))
        .unwrap();
        assert_eq!(request.device_identifier.as_deref(), Some("device"));
        assert_eq!(request.device_type, Some(2));
        assert_eq!(request.two_factor_provider, Some(0));
    }
}

fn validate_client_version(
    user: &UserDB,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    let version = headers
        .get("bitwarden-client-version")
        .and_then(|v| v.to_str().ok())
        .and_then(auth::parse_client_version)
        .ok_or(AppError::OAuth {
            error:       "version_header_missing",
            description: "No client version header found, required to prevent \
                          encryption errors. Please confirm your client is \
                          supplying the header: \"Bitwarden-Client-Version\"",
        })?;
    if user.has_v2_encryption() {
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
            return Err(AppError::OAuth {
                error:       "invalid_client_version",
                description: "Please update your app to continue using \
                              Bitwarden",
            });
        }
    }
    Ok(())
}
async fn ensure_account_snapshot(
    db: &worker::D1Database,
    user: &UserDB,
) -> Result<(), AppError> {
    let current = UserDB::fetch_by_id_with(
        db,
        &user.id,
        "Failed to verify authentication snapshot",
        || AuthError::UserNotFound.into(),
    )
    .await?;
    if current.master_password_hash != user.master_password_hash ||
        current.security_stamp != user.security_stamp ||
        crate::models::account_keys::AccountSnapshot::from_user(&current) !=
            crate::models::account_keys::AccountSnapshot::from_user(user)
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
        let mut user:UserDB=serde_json::from_value(serde_json::json!({"id":"owner","email":"owner@example.test","email_verified":0,"master_password_hash":"hash","key":"wrapped-user","private_key":"2.private","public_key":"public","kdf_type":0,"kdf_iterations":600000,"security_stamp":"stamp","created_at":"now","updated_at":"now"})).unwrap();
        let mut headers = HeaderMap::new();
        assert!(matches!(
            validate_client_version(&user, &headers),
            Err(AppError::OAuth {
                error: "version_header_missing",
                ..
            })
        ));
        headers.insert("bitwarden-client-version", "2026.7.0".parse().unwrap());
        assert!(validate_client_version(&user, &headers).is_ok());
        user.security_version = Some(2);
        user.private_key = "7.private".into();
        assert!(validate_client_version(&user, &headers).is_err());
        headers
            .insert("bitwarden-client-version", "2026.10.1".parse().unwrap());
        assert!(validate_client_version(&user, &headers).is_ok());
        headers.insert("device-type", "6".parse().unwrap());
        assert!(validate_client_version(&user, &headers).is_err());
        headers
            .insert("bitwarden-client-version", "2026.10.2".parse().unwrap());
        assert!(validate_client_version(&user, &headers).is_ok());
        for invalid in [
            "2026.10",
            "2026.10.01",
            "2026.10.2-",
            "2026.10.2+",
            "2026.10.2-beta.01",
        ] {
            assert!(auth::parse_client_version(invalid).is_none(), "{invalid}");
        }
        assert!(auth::parse_client_version("2026.11.0-beta.1+build").is_some());
    }
}
