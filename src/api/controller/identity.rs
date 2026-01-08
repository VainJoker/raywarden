use axum::{
    Form,
    Json,
    extract::State,
    response::IntoResponse,
};
use chrono::{
    Duration,
    Utc,
};
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
};

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            rate,
        },
    },
    errors::{
        AppError,
        AuthError,
    },
    infra::{
        cryptor::{
            ct_eq,
            generate_salt,
            hash_password_for_storage,
            validate_totp,
        },
        jwtor as jwt,
    },
    models::{
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
    device_identifier:   Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenResponse {
    #[serde(rename = "access_token")]
    access_token:            String,
    #[serde(rename = "expires_in")]
    expires_in:              i64,
    #[serde(rename = "token_type")]
    token_type:              String,
    #[serde(rename = "refresh_token")]
    refresh_token:           String,
    #[serde(rename = "Key")]
    key:                     String,
    private_key:             String,
    kdf:                     i32,
    kdf_iterations:          i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf_memory:              Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf_parallelism:         Option<i32>,
    force_password_reset:    bool,
    reset_master_password:   bool,
    user_decryption_options: UserDecryptionOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    two_factor_token:        Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserDecryptionOptions {
    pub has_master_password: bool,
    pub object:              String,
}

#[worker::send]
pub async fn token(
    State(state): State<AppState>,
    Form(payload): Form<TokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let db = state.get_db();
    match payload.grant_type.as_str() {
        "password" => {
            let username = payload.username.ok_or_else(|| {
                AppError::Params("Missing username".to_string())
            })?;
            let password_hash = payload.password.ok_or_else(|| {
                AppError::Params("Missing password".to_string())
            })?;

            // Check rate limit using email as key to prevent brute force
            // attacks.
            let rate_limit_key = format!("login:{}", username.to_lowercase());
            rate::check_rate_limit(&state, rate_limit_key).await?;

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
                log::warn!("user lookup failed: {e}");
                AppError::Auth(AuthError::InvalidCredentials(
                    "Invalid credentials".to_string(),
                ))
            })?;

            let verification =
                user.verify_master_password(&password_hash).await?;

            if !verification.is_valid() {
                return Err(AppError::Auth(AuthError::InvalidCredentials(
                    "Invalid credentials".to_string(),
                )));
            }

            // Check for 2FA
            let twofactors =
                TwoFactorDB::list_user_twofactors(&db, &user.id).await?;

            let mut two_factor_remember_token: Option<String> = None;

            // Filter out Remember type - it's not a real 2FA provider, just a
            // convenience feature
            let real_twofactors: Vec<&TwoFactorDB> = twofactors
                .iter()
                .filter(|tf| tf.atype != TwoFactorType::Remember as i32)
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
                    return Err(AppError::TwoFactorRequired(
                        twofactor_ids.into(),
                    ));
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
                            state.config.authenticator_disable_time_drift;
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
                                    return Err(AppError::TwoFactorRequired(
                                        twofactor_ids.into(),
                                    ));
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
                                return Err(AppError::TwoFactorRequired(
                                    twofactor_ids.into(),
                                ));
                            }
                        } else {
                            return Err(AppError::TwoFactorRequired(
                                twofactor_ids.into(),
                            ));
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
                            UserDB::clear_recovery_code(&db, &user.id).await?;
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
            let user = if verification.needs_migration() {
                // Generate new salt and hash the password
                let new_salt = generate_salt()?;
                let new_hash =
                    hash_password_for_storage(&password_hash, &new_salt)
                        .await?;
                let now = Utc::now().to_rfc3339();

                // Update user in database
                UserDB::migrate_legacy_password(
                    &db, &user.id, &new_hash, &new_salt, &now,
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

            generate_tokens_and_response(
                user,
                &state,
                two_factor_remember_token,
            )
        }
        "refresh_token" => {
            let refresh_token = payload.refresh_token.ok_or_else(|| {
                AppError::Params("Missing refresh_token".to_string())
            })?;

            let jwt_refresh_secret = state.config.jwt_refresh_secret.clone();

            let token_data = jwt::decode::<Claims>(
                &refresh_token,
                jwt_refresh_secret.as_bytes(),
                &jwt::ValidationOptions::default(),
            )
            .map_err(|e| {
                log::warn!("refresh token decode failed: {e}");
                AppError::from(e)
            })?;

            // let token_data = decode::<Claims>(
            //     &refresh_token,
            //     &DecodingKey::from_secret(jwt_refresh_secret.as_ref()),
            //     &Validation::default(),
            // )
            // .map_err(|_| AppError::Unauthorized("Invalid refresh
            // token".to_string()))?;

            let user_id = token_data.claims.sub;
            let user = UserDB::fetch_by_id_with(
                &db,
                &user_id,
                "Failed to fetch user for refresh_token",
                || AppError::Auth(AuthError::UserNotFound),
            )
            .await
            .map_err(|e| {
                log::warn!("refresh_token user query failed: {e}");
                AppError::Auth(AuthError::UserNotFound)
            })?;

            generate_tokens_and_response(user, &state, None)
        }
        _ => Err(AppError::Params("Unsupported grant_type".to_string())),
    }
}

fn generate_tokens_and_response(
    user: UserDB,
    state: &AppState,
    two_factor_token: Option<String>,
) -> Result<Json<TokenResponse>, AppError> {
    // Align with the project's Claims shape (infra/jwtor.rs)
    let mut amr = std::collections::HashSet::new();
    amr.insert("Application".to_string());

    let access_claims = Claims::new(
        user.id.clone(),
        user.email.clone(),
        user.name.clone().unwrap_or_else(|| "User".to_string()),
        true,
        true,
        amr.clone(),
        None,
        Duration::hours(1).num_seconds(),
    );

    let refresh_claims = Claims::new(
        user.id.clone(),
        user.email.clone(),
        user.name.clone().unwrap_or_else(|| "User".to_string()),
        true,
        true,
        amr,
        None,
        Duration::days(30).num_seconds(),
    );

    let jwt_secret = state.config.jwt_secret.clone();
    let access_token = jwt::encode(&access_claims, jwt_secret.as_bytes())
        .map_err(|e| {
            log::warn!("access token encode failed: {e}");
            AppError::Internal
        })?;

    let jwt_refresh_secret = state.config.jwt_refresh_secret.clone();
    let refresh_token =
        jwt::encode(&refresh_claims, jwt_refresh_secret.as_bytes()).map_err(
            |e| {
                log::warn!("refresh token encode failed: {e}");
                AppError::Internal
            },
        )?;

    let expires_in = access_claims.exp - Utc::now().timestamp();

    Ok(Json(TokenResponse {
        access_token,
        expires_in,
        token_type: "Bearer".to_string(),
        refresh_token,
        key: user.key,
        private_key: user.private_key,
        kdf: user.kdf_type,
        kdf_iterations: user.kdf_iterations,
        kdf_memory: user.kdf_memory,
        kdf_parallelism: user.kdf_parallelism,
        force_password_reset: false,
        reset_master_password: false,
        user_decryption_options: UserDecryptionOptions {
            has_master_password: true,
            object:              "userDecryptionOptions".to_string(),
        },
        two_factor_token,
    }))
}
