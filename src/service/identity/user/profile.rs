use serde::Serialize;
use serde_json::Value;

use crate::{models::identity::user::UserRow, service::identity::account_keys};

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
    pub object: &'static str,
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
            crate::utils::time::parse(&user.created_at).unwrap_or(jiff::Timestamp::UNIX_EPOCH),
        );

        let account_keys = account_keys::account_keys_response(&user, "object");
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
            object: "profile",
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
