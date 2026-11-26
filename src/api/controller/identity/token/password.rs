use serde_json::{Map, Value};
use worker::{D1Database, D1PreparedStatement};

use super::{LoginDevice, TokenExchange, ensure_account_snapshot, form::PasswordGrant};
use crate::{
    errors::{AppError, AppResult},
    models::identity::{
        auth_request::AuthRequestRow,
        device::DeviceRow,
        email::VerifiedCode,
        two_factor::{LoginMfaPolicy, TwoFactorRow},
        user::{StoredPassword, UserRow},
    },
    service::{
        identity::{
            auth_request, email, oauth,
            two_factor::{RememberedDevices, TwoFactorProvider, validate_totp},
            user, webauthn,
        },
        notifications::{admin as admin_notify, admin::Event},
        rate_limit,
    },
    utils::constant_time_eq,
};

enum VerifiedPasswordSecondFactor {
    Regular(Box<PasswordLoginFactors>),
    RecoveryCode,
}

#[derive(Default)]
struct PasswordLoginFactors {
    policy: LoginMfaPolicy,
    proof: Option<LoginFactorProof>,
    remember: Option<RememberUpdate>,
}

enum LoginFactorProof {
    Totp { id: String, step: i64 },
    Email(VerifiedCode),
    Webauthn(Box<webauthn::VerifiedTwoFactorAssertion>),
}

impl LoginFactorProof {
    fn append_writes(
        self,
        db: &D1Database,
        statements: &mut Vec<D1PreparedStatement>,
    ) -> AppResult<()> {
        match self {
            Self::Totp { id, step } => {
                statements.extend(TwoFactorRow::consume_totp(db, &id, step)?);
            }
            Self::Email(proof) => statements.extend(proof.consume_statements(db)?),
            Self::Webauthn(proof) => statements.extend(proof.consume_statements(db)?),
        }
        Ok(())
    }
}

struct RememberUpdate {
    verified_factor: TwoFactorRow,
    previous: Option<TwoFactorRow>,
    data: String,
    token: String,
}

impl TokenExchange<'_> {
    pub(super) async fn password(
        &self,
        payload: &PasswordGrant,
    ) -> AppResult<oauth::LoginTokenResponse> {
        let db = self.state.database();
        let state = self.state;
        let username = payload
            .username
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| AppError::invalid_token_request("Missing username"))?
            .to_lowercase();
        let device = LoginDevice::for_password(&payload.device)?;
        let password_hash = payload
            .access_code
            .as_deref()
            .filter(|_| payload.auth_request_id.is_some())
            .or(payload.password.as_deref())
            .ok_or_else(|| AppError::InvalidTokenParams("Missing password".into()))?;

        // Check rate limit using email as key to prevent brute force
        // attacks.
        let rate_limit_key = format!("login:{username}");
        rate_limit::check_auth_attempt(&state.env, rate_limit_key).await?;
        rate_limit::check_auth_attempt(&state.env, format!("login-ip:{}", self.client_ip)).await?;

        let user =
            UserRow::fetch_by_email_with(db, &username, "Failed to fetch user for login", || {
                AppError::invalid_credentials("Invalid credentials")
            })
            .await?;

        let auth_request = if let Some(id) = payload.auth_request_id.as_deref() {
            Some(
                self.approved_request(id, &user, &device, password_hash)
                    .await?,
            )
        } else {
            None
        };
        let needs_migration = auth_request.is_none()
            && user::require_master_password(&user, password_hash)
                .await?
                .needs_migration();

        let second_factor = self
            .verify_password_second_factor(payload, &user, &device.id)
            .await?;

        // Upgrade verified passwords only after the complete login proof.
        // Device approvals carry an access code, never a master password.
        let password = if needs_migration {
            Some(user::stored_password_for_user(password_hash, &user).await?)
        } else {
            None
        };

        self.start_password_session(
            &user,
            &device,
            second_factor,
            password.as_ref(),
            auth_request,
        )
        .await
    }

    async fn start_password_session(
        &self,
        user: &UserRow,
        device: &LoginDevice<'_>,
        second_factor: VerifiedPasswordSecondFactor,
        password: Option<&StoredPassword>,
        auth_request: Option<AuthRequestRow>,
    ) -> AppResult<oauth::LoginTokenResponse> {
        let state = self.state;
        let db = state.database();
        ensure_account_snapshot(db, user).await?;
        let (nonce, tokens) = device.prepare_tokens(user, state)?;
        let session = device.new_session(&nonce);
        let two_factor_remember_token = match second_factor {
            VerifiedPasswordSecondFactor::Regular(factors) => {
                let PasswordLoginFactors {
                    policy,
                    proof,
                    remember,
                } = *factors;
                let mut writes = Vec::new();
                if let Some(approval) = auth_request {
                    writes.extend(approval.consume_statements(db)?);
                }
                if let Some(proof) = proof {
                    proof.append_writes(db, &mut writes)?;
                }
                let remember_token = if let Some(update) = remember {
                    writes.extend(TwoFactorRow::persist_remember_if_current(
                        db,
                        user,
                        &update.verified_factor,
                        update.previous.as_ref(),
                        &update.data,
                    )?);
                    Some(update.token)
                } else {
                    None
                };
                DeviceRow::persist_session_if_current(
                    db, user, &session, &policy, writes, password,
                )
                .await?;
                remember_token
            }
            VerifiedPasswordSecondFactor::RecoveryCode => {
                TwoFactorRow::recover_and_start_session(
                    db,
                    user,
                    &session,
                    password,
                    auth_request.as_ref(),
                )
                .await?;
                admin_notify::emit(&state.env, Event::TwoFactorRecover, &user.id).await;
                None
            }
        };
        let response = tokens.login_response(user, two_factor_remember_token);
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
        if !auth_request::auth_request_matches_login(&request, &auth_request::LoginApprovalMatch {
            user_id: &user.id,
            device_id: &device.id,
            device_type: device.device_type,
            request_ip: self.client_ip,
            access_code,
            security_stamp: &user.security_stamp,
        }) {
            return Err(AppError::invalid_credentials(
                "Invalid authentication request",
            ));
        }
        Ok(request)
    }

    async fn verify_password_second_factor(
        &self,
        payload: &PasswordGrant,
        user: &UserRow,
        device_id: &str,
    ) -> AppResult<VerifiedPasswordSecondFactor> {
        let db = self.state.database();
        let providers = TwoFactorRow::list_for_user(db, &user.id).await?;
        let login_providers: Vec<_> = providers
            .iter()
            .filter(|factor| factor.requires_login_challenge())
            .collect();
        let Some(first_provider) = login_providers.first() else {
            self.validate_client_version(user)?;
            return Ok(VerifiedPasswordSecondFactor::Regular(Box::default()));
        };
        let selected_id = payload
            .two_factor_provider
            .unwrap_or(first_provider.provider_type);
        let selected = TwoFactorProvider::try_from(selected_id).ok();
        if selected == Some(TwoFactorProvider::RecoveryCode) {
            self.verify_recovery_code(user, payload.two_factor_token.as_deref())?;
            return Ok(VerifiedPasswordSecondFactor::RecoveryCode);
        }

        let Some(code) = &payload.two_factor_token else {
            if selected == Some(TwoFactorProvider::Email) {
                self.state.email_verifier().issue_login_code(user).await?;
            }
            return Err(self
                .two_factor_challenge(user, device_id, &login_providers)
                .await?);
        };
        let mut policy = LoginMfaPolicy::from_providers(&login_providers);
        let selected_provider = login_providers
            .iter()
            .copied()
            .find(|provider| provider.provider_type == selected_id);
        let remembered = RememberedLogin {
            exchange: self,
            user,
            row: providers
                .iter()
                .find(|provider| provider.provider_type == i32::from(TwoFactorProvider::Remember)),
            // Remembered tokens use the identifier as supplied by the client.
            device_id: payload.device.id.as_deref(),
            renew: payload.remember_second_factor,
        };
        let (proof, remember) = if selected == Some(TwoFactorProvider::Remember) {
            if !remembered.verify(code)? {
                return Err(self
                    .two_factor_challenge(
                        user,
                        remembered.device_id.unwrap_or(device_id),
                        &login_providers,
                    )
                    .await?);
            }
            let row = remembered.row.ok_or_else(|| {
                AppError::internal("Verified remembered device record is missing")
            })?;
            policy.remembered = Some((row.id.clone(), row.data.clone()));
            (None, remembered.prepare_renewal(Some(row))?)
        } else {
            let proof = self
                .prepare_login_factor(selected, selected_provider, user, device_id, code)
                .await?;
            if let LoginFactorProof::Webauthn(assertion) = &proof {
                policy.webauthn_id = Some(assertion.credential_row_id().to_owned());
            }
            (Some(proof), remembered.prepare_renewal(selected_provider)?)
        };
        Ok(VerifiedPasswordSecondFactor::Regular(Box::new(
            PasswordLoginFactors {
                policy,
                proof,
                remember,
            },
        )))
    }

    async fn prepare_login_factor(
        &self,
        kind: Option<TwoFactorProvider>,
        provider: Option<&TwoFactorRow>,
        user: &UserRow,
        device_id: &str,
        code: &str,
    ) -> AppResult<LoginFactorProof> {
        match kind {
            Some(TwoFactorProvider::Authenticator) => {
                self.verify_authenticator(provider, user, code).await
            }
            Some(TwoFactorProvider::Email) => self
                .prepare_email(provider, user, code)
                .await
                .map(LoginFactorProof::Email),
            Some(TwoFactorProvider::Webauthn) => self
                .prepare_webauthn(provider, user, device_id, code)
                .await
                .map(|proof| LoginFactorProof::Webauthn(Box::new(proof))),
            _ => Err(AppError::InvalidTokenParams(
                "Invalid two factor provider".into(),
            )),
        }
    }

    async fn verify_authenticator(
        &self,
        provider: Option<&TwoFactorRow>,
        user: &UserRow,
        code: &str,
    ) -> AppResult<LoginFactorProof> {
        let provider = provider.ok_or_else(|| AppError::Params("TOTP not configured".into()))?;
        let new_last_used = validate_totp(
            code,
            &provider.data,
            provider.last_used_step,
            !self.state.config.authenticator_time_drift_disabled,
        )
        .await?;
        self.validate_client_version(user)?;
        Ok(LoginFactorProof::Totp {
            id: provider.id.clone(),
            step: new_last_used,
        })
    }

    async fn prepare_email(
        &self,
        provider: Option<&TwoFactorRow>,
        user: &UserRow,
        code: &str,
    ) -> AppResult<VerifiedCode> {
        if provider.is_none() {
            return Err(AppError::bad_request("Email two-factor is not configured"));
        }
        let version = self.validate_client_version(user);
        let proof = email::prepare_login_code(
            self.state.database(),
            &self.state.jwt_keys.access_secret,
            user,
            code,
        )
        .await?;
        version?;
        Ok(proof)
    }

    async fn prepare_webauthn(
        &self,
        provider: Option<&TwoFactorRow>,
        user: &UserRow,
        device_id: &str,
        code: &str,
    ) -> AppResult<webauthn::VerifiedTwoFactorAssertion> {
        if provider.is_none() {
            return Err(AppError::bad_request(
                "WebAuthn two-factor is not configured",
            ));
        }
        webauthn::verify_two_factor_assertion(
            self.state.database(),
            &self.state.env,
            user,
            device_id,
            code,
            || self.validate_client_version(user),
        )
        .await
    }

    fn verify_recovery_code(&self, user: &UserRow, code: Option<&str>) -> AppResult<()> {
        let invalid = || AppError::invalid_credentials("Invalid recovery code");
        let recovery_code = user
            .two_factor_recovery_code
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(invalid)?;
        let code = code.ok_or_else(invalid)?;
        if !constant_time_eq(
            recovery_code.to_uppercase().as_bytes(),
            code.to_uppercase().as_bytes(),
        ) {
            return Err(invalid());
        }
        self.validate_client_version(user)
    }

    async fn two_factor_challenge(
        &self,
        user: &UserRow,
        device: &str,
        login_providers: &[&TwoFactorRow],
    ) -> AppResult<AppError> {
        let providers: Vec<_> = login_providers
            .iter()
            .map(|provider| provider.provider_type)
            .collect();
        let mut provider_details: Map<String, Value> = providers
            .iter()
            .map(|provider| (provider.to_string(), Value::Null))
            .collect();
        if providers.contains(&(i32::from(TwoFactorProvider::Webauthn))) {
            provider_details.insert(
                "7".to_string(),
                webauthn::two_factor_assertion_options(
                    self.state.database(),
                    self.state.domain(),
                    user,
                    device,
                )
                .await?,
            );
        }
        if providers.contains(&(i32::from(TwoFactorProvider::Email))) {
            provider_details.insert(
                "1".to_string(),
                email::login_metadata(self.state.database(), &user.id).await?,
            );
        }
        Ok(AppError::IdentityChallenge(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": providers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "TwoFactorProviders2": provider_details,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        })))
    }
}

/// The stored remembered-login row used for proof and guarded renewal.
struct RememberedLogin<'a> {
    exchange: &'a TokenExchange<'a>,
    user: &'a UserRow,
    row: Option<&'a TwoFactorRow>,
    device_id: Option<&'a str>,
    renew: bool,
}

impl RememberedLogin<'_> {
    fn verify(&self, code: &str) -> AppResult<bool> {
        let Some((device_id, provider)) = self.device_id.zip(self.row) else {
            return Ok(false);
        };
        let days = self.exchange.state.config.two_factor_remember_days;
        let mut tokens = RememberedDevices::from_json(&provider.data);
        tokens.remove_expired(days);
        if !tokens.validate(device_id, code, days) {
            return Ok(false);
        }
        self.exchange.validate_client_version(self.user)?;
        Ok(true)
    }

    fn prepare_renewal(
        &self,
        verified_factor: Option<&TwoFactorRow>,
    ) -> AppResult<Option<RememberUpdate>> {
        let Some(device_id) = self.device_id.filter(|_| self.renew) else {
            return Ok(None);
        };
        let token = uuid::Uuid::new_v4().to_string();
        let mut tokens = self
            .row
            .map_or_else(RememberedDevices::default, |provider| {
                RememberedDevices::from_json(&provider.data)
            });
        tokens.remove_expired(self.exchange.state.config.two_factor_remember_days);
        tokens.upsert(device_id.to_owned(), &token);
        let verified_factor = verified_factor
            .ok_or_else(|| AppError::bad_request("Missing verified second factor"))?;
        Ok(Some(RememberUpdate {
            verified_factor: verified_factor.clone(),
            previous: self.row.cloned(),
            data: tokens.to_json(),
            token,
        }))
    }
}
