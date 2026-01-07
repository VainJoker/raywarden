use chrono::SecondsFormat;
use serde::Serialize;
use serde_json::Value;

use super::{
    folder::FolderResponse,
    user::User,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct Profile {
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
    pub object: String,
    pub premium_from_organization: bool,
    pub force_password_reset: bool,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub premium: bool,
    pub uses_key_connector: bool,
    pub creation_date: String,
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

impl Profile {
    pub fn from_user(user: User, two_factor_enabled: bool) -> Self {
        let creation_date =
            chrono::DateTime::parse_from_rfc3339(&user.created_at)
                .unwrap_or_default()
                .to_rfc3339_opts(SecondsFormat::Micros, true);

        Self {
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
            object: "profile".to_string(),
            premium_from_organization: false,
            force_password_reset: false,
            email_verified: true,
            two_factor_enabled,
            premium: true,
            uses_key_connector: false,
            creation_date,
            private_key: user.private_key,
            key: user.key,
            organizations: Vec::new(),
            providers: Vec::new(),
            provider_organizations: Vec::new(),
            status: 0,
        }
    }
}

/// Response for sync (GET /api/sync)
/// Now we don't use this struct, we use `RawJson` instead. But we keep it here
/// for reference.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SyncResponse {
    pub profile:     Profile,
    pub folders:     Vec<FolderResponse>,
    #[serde(default)]
    pub collections: Vec<Value>,
    #[serde(default)]
    pub policies:    Vec<Value>,
    pub ciphers:     Vec<Value>,
    pub domains:     Value,
    #[serde(default)]
    pub sends:       Vec<Value>,
    pub object:      String,
}
