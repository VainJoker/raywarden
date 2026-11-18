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
        RawJson,
        service::claims::Claims,
    },
    errors::{
        AppError,
        AuthError,
    },
    infra::admin_notify::{
        self,
        Event,
    },
    models::{
        attachment::AttachmentDB,
        cipher::CipherDB,
        domains::EquivDomainData,
        folder::{
            FolderDB,
            FolderResponse,
        },
        sync::Profile,
        twofactor::TwoFactorDB,
        user::UserDB,
    },
    send,
};

#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    /// If true, omit domains data from sync (vaultwarden sets domains to
    /// null).
    #[serde(rename = "excludeDomains", default)]
    pub exclude_domains: bool,
}

#[worker::send]
pub async fn get_sync_data(
    claims: Claims,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> Result<RawJson, AppError> {
    let user_id = claims.sub.clone();
    let db = state.get_db();
    let show_ssh_keys = headers
        .get("bitwarden-client-version")
        .and_then(|value| value.to_str().ok())
        .and_then(crate::api::service::auth::parse_client_version)
        .is_some_and(|(version, prerelease)| {
            !prerelease && version >= (2024, 12, 0)
        });

    // Fetch profile
    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user for sync",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    let source_snapshot =
        crate::models::account_keys::AccountSnapshot::from_user(&user);
    let source_revision = user.updated_at.clone();
    let two_factor_enabled =
        TwoFactorDB::two_factor_enabled(&db, &user_id).await?;

    let user_key_id = user.user_key_id.clone();
    let v2_upgrade_token = user
        .v2_upgrade_token
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
    let has_master_password = !user.master_password_hash.is_empty();
    let equivalent_domains = user.equivalent_domains.clone();
    let excluded_globals = user.excluded_globals.clone();
    let master_password_unlock = if has_master_password {
        // Mirrors vaultwarden's `ciphers::sync` casing (lower camelCase).
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

    // Fetch folders
    let folders_db = FolderDB::list_for_user(&db, &user_id).await?;
    let folders: Vec<FolderResponse> = folders_db
        .into_iter()
        .map(std::convert::Into::into)
        .collect();

    // Fetch ciphers as raw JSON array string (no parsing in Rust!)
    let include_attachments = AttachmentDB::attachments_enabled(&state.env);
    let ciphers_json = CipherDB::fetch_cipher_json_array_raw(
        &db,
        include_attachments,
        "WHERE c.user_id = ?1 AND (?2 = 1 OR c.type != 5)",
        &[user_id.clone().into(), i32::from(show_ssh_keys).into()],
        "",
        state.get_domain(),
    )
    .await?;

    // Serialize profile and folders (small data, acceptable CPU cost)
    let mut profile = Profile::from_user(user, two_factor_enabled);
    // Match vaultwarden semantics: `_status` is `Invited` when no master
    // password is set. We don't implement org invitations, but this helps
    // clients interpret the account state.
    profile.status = i32::from(!has_master_password);
    let profile_json = serde_json::to_string(&profile).map_err(|err| {
        log::error!("Failed to serialize profile for sync: {err}");
        AppError::Internal
    })?;
    let folders_json = serde_json::to_string(&folders).map_err(|err| {
        log::error!("Failed to serialize folders for sync: {err}");
        AppError::Internal
    })?;

    // Build response JSON via string concatenation (ciphers already raw JSON)
    let user_decryption_json = serde_json::to_string(&json!({
        "masterPasswordUnlock": master_password_unlock, "userKeyId": user_key_id, "v2UpgradeToken": v2_upgrade_token
    }))
    .map_err(|err| {
        log::error!("Failed to serialize user decryption data: {err}");
        AppError::Internal
    })?;

    let sends_json =
        serde_json::to_string(&send::list_json(&db, &user_id).await?)
            .map_err(|_| AppError::Internal)?;
    let response = if query.exclude_domains {
        format!(
            r#"{{"profile":{profile_json},"folders":{folders_json},"collections":[],"policies":[],"ciphers":{ciphers_json},"domains":null,"sends":{sends_json},"userDecryption":{user_decryption_json},"object":"sync"}}"#
        )
    } else {
        // Match vaultwarden sync semantics:
        // - mark excluded in /api/settings/domains
        // - filter excluded out of sync payload
        let global_equivalent_domains =
            EquivDomainData::global_equivalent_domains_json(
                &db,
                &excluded_globals,
                false,
            )
            .await;
        let domains_json = format!(
            r#"{{"equivalentDomains":{equivalent_domains},"globalEquivalentDomains":{global_equivalent_domains},"object":"domains"}}"#
        );
        format!(
            r#"{{"profile":{profile_json},"folders":{folders_json},"collections":[],"policies":[],"ciphers":{ciphers_json},"domains":{domains_json},"sends":{sends_json},"userDecryption":{user_decryption_json},"object":"sync"}}"#
        )
    };

    let current = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to verify sync snapshot",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;
    if source_snapshot !=
        crate::models::account_keys::AccountSnapshot::from_user(&current) ||
        source_revision != current.updated_at
    {
        return Err(AppError::conflict(
            "Account or vault changed during sync. Retry sync.",
        ));
    }
    claims.validate_session(&db, "access").await?;
    admin_notify::emit(&state.env, Event::Sync, &claims.sub).await;
    Ok(RawJson(response))
}
