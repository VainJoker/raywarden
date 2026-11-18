use serde::{
    Deserialize,
    Serialize,
};

use crate::models::serde_helpers::bool_from_int;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDB {
    pub id: String,
    pub name: Option<String>,
    pub avatar_color: Option<String>,
    pub email: String,
    #[serde(with = "bool_from_int")]
    pub email_verified: bool,
    pub master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub password_salt: Option<String>, /* Salt for server-side PBKDF2
                                        * (NULL for legacy users) */
    pub key: String,
    pub private_key: String,
    pub public_key: String,
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>, /* Argon2 memory parameter
                                  * (15-1024 MB) */
    pub kdf_parallelism: Option<i32>, /* Argon2 parallelism parameter
                                       * (1-16) */
    #[serde(default)]
    pub user_key_id: Option<String>,
    #[serde(default)]
    pub signed_public_key: Option<String>,
    #[serde(default)]
    pub security_state: Option<String>,
    #[serde(default)]
    pub security_version: Option<i32>,
    #[serde(default)]
    pub signature_key_pair: Option<String>,
    #[serde(default)]
    pub v2_upgrade_token: Option<String>,
    #[serde(default)]
    pub security_stamp_exceptions: Option<String>,
    pub security_stamp: String,
    /// JSON string of `Vec<Vec<String>>` storing user-defined equivalent
    /// domain groups.
    #[serde(default = "default_json_array_string")]
    pub equivalent_domains: String,
    /// JSON string of `Vec<i32>` storing excluded global group IDs (reserved
    /// for future global groups).
    #[serde(default = "default_json_array_string")]
    pub excluded_globals: String,
    pub totp_recover: Option<String>, // Recovery code for 2FA
    pub created_at: String,
    pub updated_at: String,
}

fn default_json_array_string() -> String {
    "[]".to_string()
}

impl UserDB {
    pub fn is_v2(&self) -> bool {
        self.signed_public_key.is_some() &&
            self.security_state.is_some() &&
            self.security_version.is_some()
    }
    pub fn has_v2_encryption(&self) -> bool {
        self.security_version == Some(2) && self.private_key.starts_with("7.")
    }
}

pub struct UserKdfParams {
    pub kdf_type:        Option<i32>,
    pub kdf_iterations:  Option<i32>,
    pub kdf_memory:      Option<i32>,
    pub kdf_parallelism: Option<i32>,
}
