//! Account requests, credential policy and application-level user workflows.
mod profile;
mod requests;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
pub use profile::ProfileResponse;
pub use requests::{
    AccountKeyPairRequest, AccountVerificationRequest, ChangeKdfRequest, ChangePasswordRequest,
    KdfParams, MasterPasswordUnlockPayload, PreloginResponse, RegisterRequest,
    UpdateAvatarColorRequest, UpdateProfileRequest,
};
use worker::{D1Database, Env};

use crate::{
    errors::{AppError, AppResult, AuthError},
    infra::crypto::random_bytes,
    models::identity::{
        authorization::VerifiedAccountAction,
        email::VerifiedCode,
        user::{StoredPassword, UserRow},
    },
    service::{
        identity::{account_keys, kdf::ValidatedKdfParams, session::Claims},
        notifications::{
            self,
            admin::{self as admin_notify, Event},
        },
        password::{hash_password_for_storage, verify_password},
    },
    utils::constant_time_eq,
};

/// Binds the account snapshot to the same session throughout one credential
/// change.
pub(crate) struct AccountCredentials<'a> {
    db: &'a D1Database,
    env: &'a Env,
    claims: &'a Claims,
    user: UserRow,
}

pub(crate) async fn delete_account(
    db: &D1Database,
    env: &Env,
    authorization: &VerifiedAccountAction<'_>,
) -> AppResult<()> {
    UserRow::delete_user(db, authorization).await?;
    let session = &authorization.session;
    finish_account_deletion(db, env, session.user_id, Some(session.device_id)).await;
    Ok(())
}

pub(crate) async fn delete_account_with_email(
    db: &D1Database,
    env: &Env,
    user: &UserRow,
    verification: &VerifiedCode,
) -> AppResult<()> {
    UserRow::delete_user_with_email(db, user, verification).await?;
    finish_account_deletion(db, env, &user.id, None).await;
    Ok(())
}

/// Both verified deletion routes share the committed account's side effects.
async fn finish_account_deletion(
    db: &D1Database,
    env: &Env,
    user_id: &str,
    device_id: Option<&str>,
) {
    notifications::publish_deleted_account(env, user_id, device_id).await;
    if let Err(error) = crate::service::storage_cleanup::process_batch(env, db).await {
        log::warn!("Account deleted; object cleanup will retry: {error:?}");
    }
    admin_notify::emit(env, Event::AccountDeleted, user_id).await;
}

impl<'a> AccountCredentials<'a> {
    pub(crate) async fn load(
        db: &'a D1Database,
        env: &'a Env,
        claims: &'a Claims,
        context: &'static str,
    ) -> AppResult<Self> {
        let user = UserRow::fetch_by_id_with(db, &claims.sub, context, || {
            AppError::not_found("User not found")
        })
        .await?;
        Ok(Self {
            db,
            env,
            claims,
            user,
        })
    }

    pub(crate) async fn change_password(self, payload: ChangePasswordRequest) -> AppResult<()> {
        require_master_password(&self.user, &payload.master_password_hash).await?;
        let (hash, key, kdf) = payload.resolve(&self.user)?;
        self.apply_change(
            account_keys::CredentialChange {
                hash,
                key,
                kdf,
                hint: payload.master_password_hint.as_deref(),
                keys: payload.user_asymmetric_keys.as_ref(),
            },
            Event::PasswordChange,
        )
        .await
    }

    pub(crate) async fn change_kdf(self, payload: ChangeKdfRequest) -> AppResult<()> {
        require_master_password(&self.user, &payload.master_password_hash).await?;
        let (hash, key, kdf) = payload.resolve(&self.user)?;
        self.apply_change(
            account_keys::CredentialChange {
                hash,
                key,
                kdf: ValidatedKdfParams::try_from(kdf)?.into(),
                hint: self.user.master_password_hint.as_deref(),
                keys: None,
            },
            Event::KdfChange,
        )
        .await
    }

    async fn apply_change(
        &self,
        change: account_keys::CredentialChange<'_>,
        event: Event,
    ) -> AppResult<()> {
        account_keys::change_credentials(self.db, self.claims, &self.user, change).await?;
        admin_notify::emit(self.env, event, &self.claims.sub).await;
        notifications::publish_account_logout(
            self.env,
            self.claims,
            &crate::utils::time::now_rfc3339(),
        )
        .await;
        Ok(())
    }
}

pub const fn is_v2(user: &UserRow) -> bool {
    user.signed_public_key.is_some()
        && user.security_state.is_some()
        && user.security_version.is_some()
}

pub fn has_v2_encryption(user: &UserRow) -> bool {
    user.security_version == Some(2) && user.private_key.starts_with("7.")
}

pub async fn fetch_by_email_with<F>(
    db: &D1Database,
    email: &str,
    context: &'static str,
    not_found: F,
) -> AppResult<UserRow>
where
    F: FnOnce() -> AppError,
{
    UserRow::fetch_by_email_with(db, &email.trim().to_lowercase(), context, not_found).await
}

pub async fn revision_date_ms(db: &D1Database, user_id: &str) -> AppResult<i64> {
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

pub async fn new_stored_password(client_hash: &str) -> AppResult<StoredPassword> {
    password_at_cost(client_hash, PASSWORD_HASH_ITERATIONS).await
}

/// Changing credentials never lowers an account's existing hashing cost.
pub async fn stored_password_for_user(
    client_hash: &str,
    user: &UserRow,
) -> AppResult<StoredPassword> {
    password_at_cost(client_hash, target_iterations(user)).await
}

async fn password_at_cost(client_hash: &str, iterations: u32) -> AppResult<StoredPassword> {
    if client_hash.trim().is_empty() {
        return Err(AppError::bad_request(
            "Master password authentication hash must not be empty",
        ));
    }
    let salt = BASE64.encode(random_bytes(PASSWORD_SALT_BYTES, "generate password salt")?);
    let hash = hash_password_for_storage(client_hash, &salt, iterations).await?;
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

pub(crate) async fn require_master_password(
    user: &UserRow,
    hash: &str,
) -> AppResult<PasswordVerification> {
    let proof = verify_master_password(user, hash).await?;
    if proof.is_valid() {
        Ok(proof)
    } else {
        Err(AuthError::InvalidPassword.into())
    }
}

pub async fn verify_master_password(
    user: &UserRow,
    provided_hash: &str,
) -> AppResult<PasswordVerification> {
    if user.master_password_hash.trim().is_empty() || provided_hash.trim().is_empty() {
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

#[cfg(test)]
mod tests {
    use futures_util::FutureExt as _;
    use serde_json::json;

    use super::*;

    #[test]
    fn password_verifier_preserves_costs_and_rejects_empty_hashes() {
        let base = json!({
            "id": "owner", "email": "owner@example.test", "is_email_verified": 0,
            "master_password_hash": "", "key": "key", "private_key": "private",
            "public_key": "public", "kdf_type": 1, "kdf_iterations": 3,
            "security_stamp": "stamp", "created_at": "now", "updated_at": "now"
        });
        let user: UserRow = serde_json::from_value(base.clone()).expect("user");
        assert_eq!(
            (user.password_iterations, target_iterations(&user)),
            (100_000, 600_000)
        );
        assert_eq!(
            verify_master_password(&user, "")
                .now_or_never()
                .expect("ready")
                .expect("ok"),
            PasswordVerification::Mismatch
        );

        let mut bad = base;
        bad["password_iterations"] = json!(-1);
        assert!(serde_json::from_value::<UserRow>(bad).is_err());
    }
}
