//! Account requests, credential policy and application-level user workflows.
mod requests;

use base64::{
    Engine as _,
    engine::general_purpose::STANDARD as BASE64,
};
pub use requests::{
    AccountKeyPairRequest,
    AccountVerificationRequest,
    ChangeKdfRequest,
    ChangePasswordRequest,
    KdfParams,
    MasterPasswordUnlockPayload,
    PreloginResponse,
    RegisterRequest,
    SetPasswordRequest,
    UpdateAvatarColorRequest,
    UpdateProfileRequest,
};
use serde::Serialize;
use serde_json::Value;
use worker::D1Database;

use crate::{
    app::AppContext,
    errors::{
        AppError,
        AppResult,
        AuthError,
        CryptoError,
    },
    infra::crypto::random_bytes,
    models::identity::user::{
        PasswordInitialization,
        StoredPassword,
        UserRow,
    },
    service::{
        identity::{
            account_keys,
            kdf::{
                KDF_TYPE_ARGON2ID,
                KDF_TYPE_PBKDF2,
                ensure_supported_kdf,
            },
            session::Claims,
        },
        notifications::{
            self,
            admin::{
                self as admin_notify,
                Event,
            },
        },
        password::{
            hash_password_for_storage,
            verify_password,
        },
    },
    utils::constant_time_eq,
};

/// Binds the account snapshot to the same session throughout one credential
/// change.
pub(crate) struct AccountCredentials<'a> {
    state:  &'a AppContext,
    claims: &'a Claims,
    user:   UserRow,
}

/// Both verified deletion routes share the committed account's side effects.
pub(crate) async fn delete_account(
    state: &AppContext,
    user_id: &str,
    device_id: Option<&str>,
) -> AppResult<()> {
    let db = state.database();
    let Some(devices) = UserRow::delete_user(db, user_id).await? else {
        return Ok(());
    };
    notifications::publish_deleted_account(
        &state.env, user_id, &devices, device_id,
    )
    .await;
    if let Err(error) =
        crate::service::storage_cleanup::process_batch(&state.env, db).await
    {
        log::warn!("Account deleted; object cleanup will retry: {error}");
    }
    admin_notify::emit(&state.env, Event::AccountDeleted, user_id).await;
    Ok(())
}

impl<'a> AccountCredentials<'a> {
    pub(crate) async fn load(
        state: &'a AppContext,
        claims: &'a Claims,
        context: &str,
        not_found: impl FnOnce() -> AppError,
    ) -> AppResult<Self> {
        let user = UserRow::fetch_by_id_with(
            state.database(),
            &claims.sub,
            context,
            not_found,
        )
        .await?;
        Ok(Self {
            state,
            claims,
            user,
        })
    }

    async fn verify_current_password(&self, hash: &str) -> AppResult<()> {
        if !verify_master_password(&self.user, hash).await?.is_valid() {
            return Err(AuthError::InvalidPassword.into());
        }
        Ok(())
    }

    pub(crate) async fn initialize(
        self,
        payload: SetPasswordRequest,
    ) -> AppResult<()> {
        let state = self.state;
        let claims = self.claims;
        let user = &self.user;
        ensure_password_uninitialized(user)?;
        let mut data = payload.resolve(user)?;
        ensure_supported_kdf(
            data.kdf.kdf_type,
            data.kdf.iterations,
            data.kdf.memory,
            data.kdf.parallelism,
        )?;
        if data.kdf.kdf_type == KDF_TYPE_PBKDF2 {
            data.kdf.memory = None;
            data.kdf.parallelism = None;
        }
        let password =
            stored_password_for_user(&data.master_password_hash, user).await?;
        let (private_key, public_key) = data.key_pair.as_ref().map_or(
            (user.private_key.as_str(), user.public_key.as_str()),
            |keys| {
                (
                    keys.encrypted_private_key.as_str(),
                    keys.public_key.as_str(),
                )
            },
        );
        let material = PasswordInitialization {
            key: &data.wrapped_user_key,
            private_key,
            public_key,
            hint: data.master_password_hint.as_deref(),
            kdf_type: data.kdf.kdf_type,
            kdf_iterations: data.kdf.iterations,
            kdf_memory: data.kdf.memory,
            kdf_parallelism: data.kdf.parallelism,
        };
        UserRow::initialize_password_if_current(
            state.database(),
            user,
            &claims.session_snapshot()?,
            &material,
            &password,
        )
        .await?;
        admin_notify::emit(&state.env, Event::PasswordChange, &user.id).await;
        Ok(())
    }

    pub(crate) async fn change_password(
        self,
        payload: ChangePasswordRequest,
    ) -> AppResult<()> {
        let state = self.state;
        let claims = self.claims;
        let user = &self.user;
        self.verify_current_password(&payload.master_password_hash)
            .await?;

        let (new_hash, new_key, kdf) = payload.resolve(user)?;
        let password = stored_password_for_user(new_hash, user).await?;
        account_keys::change_credentials(
            state,
            claims,
            user,
            account_keys::CredentialChange {
                password: &password,
                key: new_key,
                kdf,
                hint: payload.master_password_hint.as_deref(),
                keys: payload.user_asymmetric_keys.as_ref(),
            },
        )
        .await?;

        admin_notify::emit(&state.env, Event::PasswordChange, &claims.sub)
            .await;
        Ok(())
    }

    pub(crate) async fn change_kdf(
        self,
        payload: ChangeKdfRequest,
    ) -> AppResult<()> {
        let state = self.state;
        let claims = self.claims;
        let user = &self.user;
        self.verify_current_password(&payload.master_password_hash)
            .await?;

        let (new_hash, new_key, kdf) = payload.resolve(user)?;

        // Validate new KDF parameters
        ensure_supported_kdf(
            kdf.kdf_type,
            kdf.iterations,
            kdf.memory,
            kdf.parallelism,
        )?;

        let password = stored_password_for_user(new_hash, user).await?;

        // Determine kdf_memory and kdf_parallelism based on KDF type
        let (final_kdf_memory, final_kdf_parallelism) =
            if kdf.kdf_type == KDF_TYPE_ARGON2ID {
                (kdf.memory, kdf.parallelism)
            } else {
                // For PBKDF2, clear these fields
                (None, None)
            };

        // Update user record with new KDF settings and password
        account_keys::change_credentials(
            state,
            claims,
            user,
            account_keys::CredentialChange {
                password: &password,
                key:      new_key,
                kdf:      KdfParams {
                    kdf_type:    kdf.kdf_type,
                    iterations:  kdf.iterations,
                    memory:      final_kdf_memory,
                    parallelism: final_kdf_parallelism,
                },
                hint:     user.master_password_hint.as_deref(),
                keys:     None,
            },
        )
        .await?;

        admin_notify::emit(&state.env, Event::KdfChange, &claims.sub).await;
        Ok(())
    }
}

pub const fn is_v2(user: &UserRow) -> bool {
    user.signed_public_key.is_some() &&
        user.security_state.is_some() &&
        user.security_version.is_some()
}

pub fn has_v2_encryption(user: &UserRow) -> bool {
    user.security_version == Some(2) && user.private_key.starts_with("7.")
}

fn ensure_password_uninitialized(user: &UserRow) -> AppResult<()> {
    if !user.master_password_hash.is_empty() || !user.private_key.is_empty() {
        return Err(AppError::bad_request(
            "Account already initialized, cannot set password",
        ));
    }
    if user.signed_public_key.is_some() ||
        user.security_state.is_some() ||
        user.security_version.is_some() ||
        user.signature_key_pair.is_some()
    {
        return Err(AppError::bad_request(
            "V2 JIT password registration is not available in this personal \
             vault",
        ));
    }
    Ok(())
}

pub async fn fetch_by_email_with<F>(
    db: &D1Database,
    email: &str,
    context: &str,
    not_found: F,
) -> AppResult<UserRow>
where
    F: FnOnce() -> AppError,
{
    UserRow::fetch_by_email_with(
        db,
        &email.trim().to_lowercase(),
        context,
        not_found,
    )
    .await
}

pub async fn revision_date_ms(
    db: &D1Database,
    user_id: &str,
) -> AppResult<i64> {
    let updated_at = UserRow::revision_date(db, user_id).await?;
    Ok(updated_at
        .and_then(|ts| crate::utils::time::parse(&ts).ok())
        .map_or_else(
            || crate::utils::time::now().as_millisecond(),
            jiff::Timestamp::as_millisecond,
        ))
}

/// Cost for newly generated account verifiers, independent of the client KDF.
const PASSWORD_HASH_ITERATIONS: u32 = 600_000;
const PASSWORD_SALT_BYTES: u32 = 64;

pub async fn new_stored_password(
    client_hash: &str,
) -> AppResult<StoredPassword> {
    password_at_cost(client_hash, PASSWORD_HASH_ITERATIONS).await
}

/// Changing credentials never lowers an account's existing hashing cost.
pub async fn stored_password_for_user(
    client_hash: &str,
    user: &UserRow,
) -> AppResult<StoredPassword> {
    password_at_cost(client_hash, target_iterations(user)).await
}

async fn password_at_cost(
    client_hash: &str,
    iterations: u32,
) -> AppResult<StoredPassword> {
    if client_hash.trim().is_empty() {
        return Err(AppError::bad_request(
            "Master password authentication hash must not be empty",
        ));
    }
    let salt = BASE64.encode(random_bytes(
        PASSWORD_SALT_BYTES,
        CryptoError::RandomGenerationFailed,
    )?);
    let hash =
        hash_password_for_storage(client_hash, &salt, iterations).await?;
    Ok(StoredPassword {
        hash,
        salt,
        iterations,
    })
}

fn target_iterations(user: &UserRow) -> u32 {
    PASSWORD_HASH_ITERATIONS.max(user.password_iterations)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerification {
    MatchCurrentScheme,
    MatchLegacyScheme,
    MatchOutdatedScheme,
    Mismatch,
}

impl PasswordVerification {
    pub const fn is_valid(self) -> bool {
        !matches!(self, Self::Mismatch)
    }

    pub const fn needs_migration(self) -> bool {
        matches!(self, Self::MatchLegacyScheme | Self::MatchOutdatedScheme)
    }
}

pub async fn verify_master_password(
    user: &UserRow,
    provided_hash: &str,
) -> AppResult<PasswordVerification> {
    if user.master_password_hash.trim().is_empty() ||
        provided_hash.trim().is_empty()
    {
        return Ok(PasswordVerification::Mismatch);
    }
    if let Some(ref salt) = user.password_salt {
        let is_valid = verify_password(
            provided_hash,
            &user.master_password_hash,
            salt,
            user.password_iterations,
        )
        .await?;
        Ok(
            if is_valid && user.password_iterations < PASSWORD_HASH_ITERATIONS {
                PasswordVerification::MatchOutdatedScheme
            } else if is_valid {
                PasswordVerification::MatchCurrentScheme
            } else {
                PasswordVerification::Mismatch
            },
        )
    } else {
        let is_valid = constant_time_eq(
            user.master_password_hash.as_bytes(),
            provided_hash.as_bytes(),
        );

        Ok(if is_valid {
            PasswordVerification::MatchLegacyScheme
        } else {
            PasswordVerification::Mismatch
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct ProfileResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_color: Option<String>,
    pub email: String,
    pub id: String,
    pub kdf: i32,
    pub kdf_iterations: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_password_hint: Option<String>,
    pub security_stamp: String,
    pub user_key_id: Option<String>,
    pub account_keys: Value,
    pub object: String,
    #[serde(rename = "premiumFromOrganization")]
    pub has_organization_premium: bool,
    #[serde(rename = "forcePasswordReset")]
    pub must_reset_password: bool,
    #[serde(rename = "emailVerified")]
    pub is_email_verified: bool,
    #[serde(rename = "twoFactorEnabled")]
    pub is_two_factor_enabled: bool,
    #[serde(rename = "premium")]
    pub is_premium: bool,
    pub uses_key_connector: bool,
    #[serde(rename = "creationDate")]
    pub created_at: String,
    pub private_key: String,
    pub key: String,
    #[serde(default)]
    pub organizations: Vec<Value>,
    #[serde(default)]
    pub providers: Vec<Value>,
    #[serde(default)]
    pub provider_organizations: Vec<Value>,
    #[serde(rename = "_status")]
    pub status: i32,
}

impl ProfileResponse {
    pub fn from_user(user: UserRow, is_two_factor_enabled: bool) -> Self {
        let created_at = crate::utils::time::format_micros(
            crate::utils::time::parse(&user.created_at)
                .unwrap_or(jiff::Timestamp::UNIX_EPOCH),
        );

        let account_keys =
            crate::service::identity::account_keys::account_keys_response(
                &user,
            );
        Self {
            account_keys,
            id: user.id,
            name: user.name,
            avatar_color: user.avatar_color,
            email: user.email,
            kdf: user.kdf_type,
            kdf_iterations: user.kdf_iterations,
            kdf_memory: user.kdf_memory,
            kdf_parallelism: user.kdf_parallelism,
            master_password_hint: user.master_password_hint,
            security_stamp: user.security_stamp,
            user_key_id: user.user_key_id,
            object: "profile".to_string(),
            has_organization_premium: false,
            must_reset_password: false,
            is_email_verified: user.is_email_verified,
            is_two_factor_enabled,
            is_premium: true,
            uses_key_connector: false,
            created_at,
            private_key: user.private_key,
            key: user.key,
            organizations: Vec::new(),
            providers: Vec::new(),
            provider_organizations: Vec::new(),
            status: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt as _;
    use serde_json::json;

    use super::*;

    fn row() -> serde_json::Value {
        json!({"id":"owner","email":"owner@example.test","is_email_verified":0,"master_password_hash":"hash","key":"key","private_key":"private","public_key":"public","kdf_type":0,"kdf_iterations":600_000,"security_stamp":"stamp","created_at":"now","updated_at":"now"})
    }

    #[test]
    fn old_rows_keep_the_raywarden_cost_without_using_the_client_kdf() {
        let mut value = row();
        value["kdf_type"] = json!(1);
        value["kdf_iterations"] = json!(3);
        let user: UserRow = serde_json::from_value(value)
            .expect("valid password verification fixture");
        assert_eq!(user.password_iterations, 100_000);
        assert_eq!(target_iterations(&user), 600_000);
    }

    #[test]
    fn persisted_cost_is_unsigned_and_higher_costs_are_preserved() {
        for invalid in [json!(-1), json!(4_294_967_296_u64), json!(1.5)] {
            let mut value = row();
            value["password_iterations"] = invalid;
            assert!(serde_json::from_value::<UserRow>(value).is_err());
        }
        let mut value = row();
        value["password_iterations"] = json!(1_200_000);
        let user: UserRow = serde_json::from_value(value)
            .expect("valid password verification fixture");
        assert_eq!(target_iterations(&user), 1_200_000);
    }

    #[test]
    fn empty_credentials_never_authorize_legacy_or_salted_accounts() {
        for (stored, provided) in [
            ("", ""),
            ("", "nonempty"),
            ("nonempty", ""),
            (" \t", " \t"),
            ("nonempty", "\n"),
        ] {
            for salt in [serde_json::Value::Null, json!("salt")] {
                let mut value = row();
                value["master_password_hash"] = json!(stored);
                value["password_salt"] = salt;
                let user: UserRow = serde_json::from_value(value)
                    .expect("valid password verification fixture");
                assert_eq!(
                    verify_master_password(&user, provided)
                        .now_or_never()
                        .expect("invalid credentials must return before crypto")
                        .expect("valid password verification fixture"),
                    PasswordVerification::Mismatch
                );
            }
        }
    }
}
