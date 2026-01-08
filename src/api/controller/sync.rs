use axum::{
    Json,
    extract::{
        Query,
        State,
    },
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::{
        AppError,
        AuthError,
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
    Query(query): Query<SyncQuery>,
) -> Result<Json<Value>, AppError> {
    let user_id = claims.sub;
    let db = state.get_db();

    // Fetch profile
    let user = UserDB::fetch_by_id_with(
        &db,
        &user_id,
        "Failed to fetch user for sync",
        || AppError::Auth(AuthError::UserNotFound),
    )
    .await?;

    let two_factor_enabled =
        TwoFactorDB::two_factor_enabled(&db, &user_id).await?;

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
            "salt": user.email
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
        "WHERE c.user_id = ?1",
        &[user_id.clone().into()],
        "",
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
        "masterPasswordUnlock": master_password_unlock
    }))
    .map_err(|err| {
        log::error!("Failed to serialize user decryption data: {err}");
        AppError::Internal
    })?;

    let response = if query.exclude_domains {
        format!(
            r#"{{"profile":{profile_json},"folders":{folders_json},"collections":[],"policies":[],"ciphers":{ciphers_json},"sends":[],"userDecryption":{user_decryption_json},"object":"sync"}}"#
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
            r#"{{"profile":{profile_json},"folders":{folders_json},"collections":[],"policies":[],"ciphers":{ciphers_json},"domains":{domains_json},"sends":[],"userDecryption":{user_decryption_json},"object":"sync"}}"#
        )
    };

    Ok(Json(json!(
        serde_json::from_str::<Value>(&response).map_err(|err| {
            log::error!("Failed to parse sync response JSON: {err}");
            AppError::Internal
        })?
    )))
}
