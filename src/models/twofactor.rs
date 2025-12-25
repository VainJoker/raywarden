use chrono::{
    Duration,
    Utc,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::models::serde_helpers::bool_from_int;

/// Remember token expiration in days
const REMEMBER_TOKEN_EXPIRATION_DAYS: i64 = 30;

/// Two-factor authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TwoFactorType {
    Authenticator = 0, // TOTP
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    Webauthn = 7,
    RecoveryCode = 8,
}

impl TwoFactorType {
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Authenticator),
            1 => Some(Self::Email),
            2 => Some(Self::Duo),
            3 => Some(Self::YubiKey),
            4 => Some(Self::U2f),
            5 => Some(Self::Remember),
            6 => Some(Self::OrganizationDuo),
            7 => Some(Self::Webauthn),
            8 => Some(Self::RecoveryCode),
            _ => None,
        }
    }
}

/// `TwoFactor` database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub uuid:      String,
    pub user_uuid: String,
    pub atype:     i32,
    #[serde(with = "bool_from_int")]
    pub enabled:   bool,
    pub data:      String,
    pub last_used: i64,
}

impl TwoFactor {
    pub fn new(user_uuid: String, atype: TwoFactorType, data: String) -> Self {
        Self {
            uuid: uuid::Uuid::new_v4().to_string(),
            user_uuid,
            atype: atype as i32,
            enabled: true,
            data,
            last_used: 0,
        }
    }

    pub fn to_json_provider(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "type": self.atype,
            "object": "twoFactorProvider"
        })
    }
}

/// POST /api/two-factor/authenticator - Enable TOTP
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorData {
    pub key:                  String,
    pub token:                String,
    pub master_password_hash: Option<String>,
    pub otp:                  Option<String>,
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorData {
    pub master_password_hash: Option<String>,
    pub otp:                  Option<String>,
    #[serde(rename = "type")]
    pub r#type:               i32,
}

/// POST /api/two-factor/get-recover - Get recovery code
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverTwoFactor {
    pub master_password_hash: String,
    pub email:                String,
    pub recovery_code:        String,
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorData {
    pub key:                  String,
    pub master_password_hash: Option<String>,
    pub otp:                  Option<String>,
    #[serde(rename = "type")]
    pub r#type:               i32,
}

// ============================================================================
// Remember Token Storage (supports multiple devices with expiration)
// ============================================================================

/// Single device remember token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RememberTokenEntry {
    pub device_id:  String,
    pub token:      String,
    pub created_at: i64, // Unix timestamp
}

/// Container for multiple device remember tokens
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RememberTokenData {
    pub tokens: Vec<RememberTokenEntry>,
}

impl RememberTokenData {
    /// Parse from JSON string stored in database
    pub fn from_json(data: &str) -> Self {
        serde_json::from_str(data).unwrap_or_default()
    }

    /// Serialize to JSON string for database storage
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Remove expired tokens (older than 30 days)
    pub fn remove_expired(&mut self) {
        let now = Utc::now().timestamp();
        let expiration_seconds =
            Duration::days(REMEMBER_TOKEN_EXPIRATION_DAYS).num_seconds();
        self.tokens
            .retain(|t| now - t.created_at < expiration_seconds);
    }

    /// Validate a token for a specific device
    /// Returns true if valid and not expired
    pub fn validate(&self, device_id: &str, token: &str) -> bool {
        let now = Utc::now().timestamp();
        let expiration_seconds =
            Duration::days(REMEMBER_TOKEN_EXPIRATION_DAYS).num_seconds();

        self.tokens.iter().any(|t| {
            t.device_id == device_id &&
                t.token == token &&
                now - t.created_at < expiration_seconds
        })
    }

    /// Add or update a token for a device
    /// If the device already has a token, it will be replaced
    pub fn upsert(&mut self, device_id: String, token: String) {
        // Remove existing token for this device
        self.tokens.retain(|t| t.device_id != device_id);

        // Add new token
        self.tokens.push(RememberTokenEntry {
            device_id,
            token,
            created_at: Utc::now().timestamp(),
        });
    }
}
