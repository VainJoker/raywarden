use std::borrow::Cow;

use axum::{
    extract::{
        Query,
        State,
    },
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        common::response::RawJson,
    },
    errors::{
        AppError,
        AppResult,
        AuthError,
    },
    models::{
        identity::{
            account_keys::AccountSnapshot,
            user::UserRow,
        },
        vault::folder::FolderRow,
    },
    service::{
        identity::{
            session::Claims,
            user::ProfileResponse,
        },
        notifications::{
            admin as admin_notify,
            admin::Event,
        },
        send,
        vault::{
            attachment,
            cipher,
            domains,
            folder::FolderResponse,
        },
    },
};

#[derive(Debug, Deserialize)]
pub(in crate::api) struct SyncQuery {
    /// If true, omit domains data from sync (vaultwarden sets domains to
    /// null).
    #[serde(rename = "excludeDomains", default)]
    exclude_domains: bool,
}

#[worker::send]
pub(in crate::api) async fn sync_vault(
    claims: Claims,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> AppResult<RawJson> {
    let show_ssh_keys = headers
        .get("bitwarden-client-version")
        .and_then(|value| value.to_str().ok())
        .and_then(crate::utils::version::parse)
        .is_some_and(|(version, prerelease)| {
            !prerelease && version >= (2024, 12, 0)
        });

    VaultSync {
        state:  &state,
        claims: &claims,
    }
    .respond(show_ssh_keys, query.exclude_domains)
    .await
}

/// Validate the source account and session again before releasing a response
/// assembled from multiple reads.
struct VaultSync<'a> {
    state:  &'a AppState,
    claims: &'a Claims,
}

impl VaultSync<'_> {
    async fn user(&self, context: &str) -> AppResult<UserRow> {
        UserRow::fetch_by_id_with(
            self.state.database(),
            &self.claims.sub,
            context,
            || AppError::Auth(AuthError::UserNotFound),
        )
        .await
    }

    async fn respond(
        self,
        show_ssh_keys: bool,
        exclude_domains: bool,
    ) -> AppResult<RawJson> {
        let user = self.user("Failed to fetch user for sync").await?;
        let account = AccountSnapshot::from_user(&user);
        let revision = user.updated_at.clone();
        let response =
            self.render(user, show_ssh_keys, exclude_domains).await?;

        let current = self.user("Failed to verify sync snapshot").await?;
        if account != AccountSnapshot::from_user(&current) ||
            revision != current.updated_at
        {
            return Err(AppError::conflict(
                "Account or vault changed during sync. Retry sync.",
            ));
        }
        self.claims
            .validate_session(self.state.database(), "access")
            .await?;
        admin_notify::emit(&self.state.env, Event::Sync, &self.claims.sub)
            .await;
        Ok(RawJson(response))
    }

    async fn render(
        &self,
        user: UserRow,
        show_ssh_keys: bool,
        exclude_domains: bool,
    ) -> AppResult<String> {
        let db = self.state.database();
        let user_id = &self.claims.sub;
        let is_two_factor_enabled =
            crate::service::identity::two_factor::is_two_factor_enabled(
                db, user_id,
            )
            .await?;
        let has_master_password = !user.master_password_hash.is_empty();
        let decryption = user_decryption(&user, has_master_password);

        let folders_db = FolderRow::list_for_user(db, user_id).await?;
        let folders: Vec<FolderResponse> = folders_db
            .into_iter()
            .map(std::convert::Into::into)
            .collect();

        let include_attachments = attachment::is_enabled(&self.state.env);
        let ciphers_json = cipher::list_cipher_responses_json(
            db,
            user_id,
            include_attachments,
            show_ssh_keys,
            false,
            self.state.domain(),
        )
        .await?;

        let folders_json = serde_json::to_string(&folders).map_err(|err| {
            AppError::internal_with_context(
                "api",
                "Failed to serialize folders for sync",
                err,
            )
        })?;

        let user_decryption_json =
            serde_json::to_string(&decryption).map_err(|err| {
                AppError::internal_with_context(
                    "api",
                    "Failed to serialize user decryption data",
                    err,
                )
            })?;

        let sends_json = serde_json::to_string(
            &send::list_send_responses(db, user_id).await?,
        )
        .map_err(AppError::internal_error)?;
        let domains_json = if exclude_domains {
            Cow::Borrowed("null")
        } else {
            // Match vaultwarden sync semantics:
            // - mark excluded in /api/settings/domains
            // - filter excluded out of sync payload
            let global_equivalent_domains =
                domains::global_equivalent_domains_json(
                    db,
                    &user.excluded_globals,
                    false,
                )
                .await;
            Cow::Owned(format!(
                r#"{{"equivalentDomains":{},"globalEquivalentDomains":{global_equivalent_domains},"object":"domains"}}"#,
                user.equivalent_domains,
            ))
        };
        let mut profile =
            ProfileResponse::from_user(user, is_two_factor_enabled);
        // Clients expect the Invited status before a master password exists.
        profile.status = i32::from(!has_master_password);
        let profile_json = serde_json::to_string(&profile).map_err(|err| {
            AppError::internal_with_context(
                "api",
                "Failed to serialize profile for sync",
                err,
            )
        })?;
        Ok(format!(
            r#"{{"profile":{profile_json},"folders":{folders_json},"collections":[],"policies":[],"policiesNew":[],"ciphers":{ciphers_json},"domains":{domains_json},"sends":{sends_json},"userDecryption":{user_decryption_json},"object":"sync"}}"#
        ))
    }
}

fn user_decryption(user: &UserRow, has_master_password: bool) -> Value {
    let v2_upgrade_token = user
        .v2_upgrade_token
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
    let master_password_unlock = if has_master_password {
        // Mirrors vaultwarden's `cipher::sync` casing (lower camelCase).
        // We don't support SSO, so this is always derived from the current user
        // record.
        json!({
            "kdf": {
                "kdfType": user.kdf_type,
                "iterations": user.kdf_iterations,
                "memory": user.kdf_memory,
                "parallelism": user.kdf_parallelism
            },
            // This field is named inconsistently and will be removed and replaced by the "wrapped" variant in the apps.
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "masterKeyEncryptedUserKey": user.key,
            "masterKeyWrappedUserKey": user.key,
            "salt": user.email,
            "containedKeyId": user.user_key_id
        })
    } else {
        Value::Null
    };

    json!({
        "masterPasswordUnlock": master_password_unlock,
        "userKeyId": user.user_key_id,
        "v2UpgradeToken": v2_upgrade_token
    })
}
