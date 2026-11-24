use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    api::{
        AppState,
        common::{
            extract::ClientVersionHeader,
            snapshot::{ReadSnapshot, SnapshotJson},
        },
    },
    errors::AppResult,
    models::identity::user::UserRow,
    service::{
        identity::{session::Claims, user::ProfileResponse},
        notifications::{admin as admin_notify, admin::Event},
        send,
        vault::{attachment, cipher, domains, folder},
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
    State(state): State<Arc<AppState>>,
    ClientVersionHeader(version): ClientVersionHeader,
    Query(query): Query<SyncQuery>,
) -> AppResult<Response> {
    let show_ssh_keys = version
        .is_some_and(|version| !version.is_prerelease && version.satisfies_minimum(2024, 12, 0));

    VaultSync {
        state: &state,
        claims: &claims,
    }
    .respond(show_ssh_keys, query.exclude_domains)
    .await
}

/// Validate the source account and session again before releasing a response
/// assembled from multiple reads.
struct VaultSync<'a> {
    state: &'a AppState,
    claims: &'a Claims,
}

impl VaultSync<'_> {
    async fn respond(self, show_ssh_keys: bool, exclude_domains: bool) -> AppResult<Response> {
        let db = self.state.database();
        let user = ReadSnapshot::user(db, self.claims, "Failed to fetch user for sync").await?;
        let snapshot = ReadSnapshot::from_user(&user);
        let response = self.render(user, show_ssh_keys, exclude_domains).await?;
        snapshot.verify(db, self.claims).await?;
        admin_notify::emit(&self.state.env, Event::Sync, &self.claims.sub).await;
        Ok(response)
    }

    async fn render(
        &self,
        mut user: UserRow,
        show_ssh_keys: bool,
        exclude_domains: bool,
    ) -> AppResult<Response> {
        let db = self.state.database();
        let user_id = &self.claims.sub;
        let is_two_factor_enabled =
            crate::service::identity::two_factor::is_two_factor_enabled(db, user_id).await?;
        let has_master_password = !user.master_password_hash.is_empty();
        let decryption = user_decryption(&user, has_master_password);

        let equivalent_domains = std::mem::take(&mut user.equivalent_domains);
        let excluded_globals = std::mem::take(&mut user.excluded_globals);
        let mut profile = ProfileResponse::from_user(user, is_two_factor_enabled);
        profile.status = i32::from(!has_master_password);

        let mut response = SnapshotJson::new();
        response.field("profile", &profile)?;
        let mut folders = response.array("folders")?;
        folder::visit_folder_responses(db, user_id, |folder| folders.push(&folder)).await?;
        folders.finish()?;
        response.field("collections", &[] as &[()])?;
        response.field("policies", &[] as &[()])?;
        response.field("policiesNew", &[] as &[()])?;

        let mut ciphers = response.array("ciphers")?;
        cipher::visit_cipher_responses(
            db,
            user_id,
            attachment::include_metadata(&self.state.env),
            show_ssh_keys,
            false,
            self.state.domain(),
            |cipher| ciphers.push(&cipher),
        )
        .await?;
        ciphers.finish()?;

        let domains = if exclude_domains {
            None
        } else {
            Some(domains::render_settings(db, &equivalent_domains, &excluded_globals, false).await)
        };
        response.field("domains", &domains)?;
        let mut sends = response.array("sends")?;
        send::visit_send_responses(db, user_id, |send| sends.push(&send)).await?;
        sends.finish()?;
        response.field("userDecryption", &decryption)?;
        response.field("object", &"sync")?;
        response.finish()
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
