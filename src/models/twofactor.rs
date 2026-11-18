use jiff::SignedDuration;
use serde::{
    Deserialize,
    Serialize,
};
use uuid::Uuid;
use worker::query;

use crate::{
    errors::{
        AppError,
        DatabaseError,
    },
    infra::db,
    models::{
        device::SessionSnapshot,
        serde_helpers::bool_from_int,
    },
};

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

/// `TwoFactorDB` database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorDB {
    pub uuid:      String,
    pub user_uuid: String,
    pub atype:     i32,
    #[serde(with = "bool_from_int")]
    pub enabled:   bool,
    pub data:      String,
    pub last_used: i64,
}

impl TwoFactorDB {
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

    /// List all 2FA records for a user (includes Remember tokens, excludes
    /// atype >= 1000).
    pub async fn list_user_twofactors(
        db: &worker::D1Database,
        user_id: &str,
    ) -> Result<Vec<Self>, AppError> {
        db.prepare(
            "SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000",
        )
        .bind(&[user_id.to_string().into()])?
        .all()
        .await
        .map_err(|err| {
            log::error!(
                "Failed to query twofactor records for user {user_id}: {err}"
            );
            AppError::Database(DatabaseError::QueryFailed(
                "list_user_twofactors".to_string(),
            ))
        })?
        .results::<Self>()
        .map_err(|err| {
            log::error!(
                "Failed to deserialize twofactor records for user {user_id}: \
                 {err}"
            );
            AppError::Database(DatabaseError::QueryFailed(
                "list_user_twofactors".to_string(),
            ))
        })
    }

    /// Keep the existing login policy, including unknown legacy providers.
    /// Remember-device tokens and internal records do not require a challenge.
    pub const fn requires_login_challenge(&self) -> bool {
        self.enabled &&
            self.atype != TwoFactorType::Remember as i32 &&
            self.atype < 1000
    }

    /// Whether the same providers used during login require a second factor.
    pub fn is_twofactor_enabled(twofactors: &[Self]) -> bool {
        twofactors.iter().any(Self::requires_login_challenge)
    }

    pub async fn two_factor_enabled(
        db: &worker::D1Database,
        user_id: &str,
    ) -> Result<bool, AppError> {
        let twofactors = Self::list_user_twofactors(db, user_id).await?;
        Ok(Self::is_twofactor_enabled(&twofactors))
    }

    pub async fn get_for_user_by_type(
        db: &worker::D1Database,
        user_id: &str,
        atype: i32,
    ) -> Result<Option<Self>, AppError> {
        db.prepare(
            "SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        )
        .bind(&[user_id.to_string().into(), atype.into()])?
        .first(None)
        .await
        .map_err(|err| {
            log::error!(
                "Failed to fetch twofactor type {atype} for user {user_id}: \
                 {err}"
            );
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to fetch twofactor record".to_string(),
            ))
        })?
        .map(|value| {
            serde_json::from_value(value).map_err(|err| {
                log::error!("Failed to deserialize twofactor record: {err}");
                AppError::Internal
            })
        })
        .transpose()
    }

    pub async fn delete_types_for_user(
        db: &worker::D1Database,
        user_id: &str,
        types: &[i32],
    ) -> Result<(), AppError> {
        if types.is_empty() {
            return Ok(());
        }

        let placeholders = vec!["?"; types.len()].join(",");
        let sql = format!(
            "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype IN \
             ({placeholders})"
        );

        let mut binds = vec![user_id.to_string().into()];
        binds.extend(types.iter().copied().map(Into::into));

        db::run_query(
            async { db.prepare(sql).bind(&binds)?.run().await.map(|_| ()) },
            "Failed to delete twofactor entries",
        )
        .await
    }

    pub async fn delete_type_for_user(
        db: &worker::D1Database,
        user_id: &str,
        atype: i32,
    ) -> Result<(), AppError> {
        Self::delete_types_for_user(db, user_id, &[atype]).await
    }

    pub async fn insert_twofactor(
        db: &worker::D1Database,
        tf: &Self,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, \
                     data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    tf.uuid,
                    tf.user_uuid,
                    tf.atype,
                    i32::from(tf.enabled),
                    tf.data,
                    tf.last_used
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to insert twofactor record",
        )
        .await
    }

    pub async fn update_last_used(
        db: &worker::D1Database,
        uuid: &str,
        last_used: i64,
    ) -> Result<(), AppError> {
        let result = query!(
            db,
            "UPDATE twofactor SET last_used = ?1 WHERE uuid = ?2 AND enabled \
             = 1 AND last_used < ?1",
            last_used,
            uuid
        )?
        .run()
        .await?;
        if result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) != 1 {
            return Err(crate::errors::AuthError::InvalidTotp.into());
        }
        Ok(())
    }

    pub async fn replace_authenticator(
        db: &worker::D1Database,
        session: &SessionSnapshot<'_>,
        previous: Option<&Self>,
        value: &Self,
    ) -> Result<(), AppError> {
        let previous = previous
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| AppError::Internal)?;
        let statements = vec![
            query!(
                db,
                "INSERT INTO \
                 twofactor(uuid,user_uuid,atype,enabled,data,last_used) \
                 SELECT ?1,?2,0,?3,?4,?5 WHERE EXISTS (SELECT 1 FROM users u \
                 JOIN devices d ON d.user_id=u.id WHERE u.id=?2 AND \
                 u.security_stamp=?7 AND d.identifier=?8 AND \
                 d.session_token=?9) AND ((?6 IS NULL AND NOT EXISTS (SELECT \
                 1 FROM twofactor WHERE user_uuid=?2 AND atype=0)) OR EXISTS \
                 (SELECT 1 FROM twofactor WHERE user_uuid=?2 AND atype=0 AND \
                 uuid=json_extract(?6,'$.uuid') AND \
                 data=json_extract(?6,'$.data') AND \
                 enabled=json_extract(?6,'$.enabled') AND \
                 last_used=json_extract(?6,'$.last_used'))) ON \
                 CONFLICT(user_uuid,atype) DO UPDATE SET \
                 uuid=excluded.uuid,enabled=excluded.enabled, \
                 data=excluded.data,last_used=excluded.last_used",
                value.uuid,
                session.user_id,
                i32::from(value.enabled),
                value.data,
                value.last_used,
                previous,
                session.security_stamp,
                session.device_id,
                session.session_token
            )?,
            db.prepare(
                "SELECT CASE WHEN changes()=1 THEN 1 ELSE json_extract('[]', \
                 'RAY_TOTP_WRITE_CONFLICT') END",
            ),
            query!(
                db,
                "DELETE FROM twofactor WHERE user_uuid=?1 AND atype=5 AND \
                 EXISTS (SELECT 1 FROM twofactor WHERE uuid=?2)",
                session.user_id,
                value.uuid
            )?,
        ];
        let result = db.batch(statements).await.map_err(totp_write_error)?;
        if result
            .first()
            .and_then(|r| r.meta().ok().flatten())
            .and_then(|m| m.changes)
            .unwrap_or(0) !=
            1
        {
            return Err(AppError::conflict(
                "Authenticator configuration changed; retry",
            ));
        }
        Ok(())
    }

    pub async fn delete_authenticator_snapshot(
        db: &worker::D1Database,
        session: &SessionSnapshot<'_>,
        previous: &Self,
    ) -> Result<(), AppError> {
        let result = db
            .batch(vec![
                query!(
                    db,
                    "DELETE FROM twofactor WHERE uuid=?1 AND user_uuid=?2 AND \
                     atype=0 AND data=?3 AND enabled=?4 AND last_used=?5 AND \
                     EXISTS (SELECT 1 FROM users u JOIN devices d ON \
                     d.user_id=u.id WHERE u.id=?2 AND u.security_stamp=?6 AND \
                     d.identifier=?7 AND d.session_token=?8)",
                    previous.uuid,
                    session.user_id,
                    previous.data,
                    i32::from(previous.enabled),
                    previous.last_used,
                    session.security_stamp,
                    session.device_id,
                    session.session_token
                )?,
                db.prepare(
                    "SELECT CASE WHEN changes()=1 THEN 1 ELSE \
                     json_extract('[]', 'RAY_TOTP_WRITE_CONFLICT') END",
                ),
                query!(
                    db,
                    "DELETE FROM twofactor WHERE user_uuid=?1 AND atype=5 AND \
                     NOT EXISTS (SELECT 1 FROM twofactor WHERE user_uuid=?1 \
                     AND atype=0)",
                    session.user_id
                )?,
            ])
            .await
            .map_err(totp_write_error)?;
        if result
            .first()
            .and_then(|r| r.meta().ok().flatten())
            .and_then(|m| m.changes)
            .unwrap_or(0) !=
            1
        {
            return Err(AppError::conflict(
                "Authenticator configuration changed; retry",
            ));
        }
        Ok(())
    }

    pub async fn update_data(
        db: &worker::D1Database,
        uuid: &str,
        data: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
                    data,
                    uuid
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update twofactor data",
        )
        .await
    }

    pub async fn delete_for_user(
        db: &worker::D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM twofactor WHERE user_uuid = ?1",
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to delete twofactor entries",
        )
        .await
    }

    pub async fn upsert_remember_token(
        db: &worker::D1Database,
        user_id: &str,
        json_data: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, \
                     data, last_used)
                         VALUES (?1, ?2, ?3, 1, ?4, 0)
                         ON CONFLICT(user_uuid, atype) DO UPDATE SET data = ?4",
                    Uuid::new_v4().to_string(),
                    user_id,
                    TwoFactorType::Remember as i32,
                    json_data
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to upsert remember token",
        )
        .await
    }
}

fn totp_write_error(error: worker::Error) -> AppError {
    if error.to_string().contains("RAY_TOTP_WRITE_CONFLICT") {
        AppError::conflict("Authenticator configuration changed; retry")
    } else {
        error.into()
    }
}

/// POST /api/two-factor/authenticator - Enable TOTP
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorData {
    pub key:                     String,
    pub token:                   String,
    pub master_password_hash:    Option<String>,
    pub otp:                     Option<String>,
    pub user_verification_token: Option<String>,
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorData {
    pub master_password_hash:    Option<String>,
    pub otp:                     Option<String>,
    pub user_verification_token: Option<String>,
    #[serde(rename = "type")]
    pub r#type:                  i32,
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
    pub key:                     String,
    pub master_password_hash:    Option<String>,
    pub otp:                     Option<String>,
    pub user_verification_token: Option<String>,
    #[serde(rename = "type")]
    pub r#type:                  i32,
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
        let now = crate::infra::time::now_seconds();
        let expiration_seconds =
            SignedDuration::from_secs(REMEMBER_TOKEN_EXPIRATION_DAYS * 86_400)
                .as_secs();
        self.tokens
            .retain(|t| now.saturating_sub(t.created_at) < expiration_seconds);
    }

    /// Validate a token for a specific device
    /// Returns true if valid and not expired
    pub fn validate(&self, device_id: &str, token: &str) -> bool {
        let now = crate::infra::time::now_seconds();
        let expiration_seconds =
            SignedDuration::from_secs(REMEMBER_TOKEN_EXPIRATION_DAYS * 86_400)
                .as_secs();

        self.tokens.iter().any(|t| {
            t.device_id == device_id &&
                t.token == token &&
                now.saturating_sub(t.created_at) < expiration_seconds
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
            created_at: crate::infra::time::now_seconds(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::TwoFactorDB;

    #[test]
    fn challenge_classification_matches_login_for_supported_and_legacy_factors()
    {
        for (atype, enabled, expected) in [
            (0, true, true),
            (1, true, true),
            (7, true, true),
            (0, false, false),
            (1, false, false),
            (7, false, false),
            (5, true, false),
            (1000, true, false),
            (1005, true, false),
            // Unknown and unsupported legacy factors still trigger the same
            // login challenge; this predicate must not bypass their handling.
            (2, true, true),
            (8, true, true),
            (42, true, true),
            (999, true, true),
            (-1, true, true),
        ] {
            let factor = TwoFactorDB {
                uuid: "factor".into(),
                user_uuid: "owner".into(),
                atype,
                enabled,
                data: "{}".into(),
                last_used: 0,
            };
            assert_eq!(
                factor.requires_login_challenge(),
                expected,
                "type {atype}, enabled {enabled}"
            );
            assert_eq!(
                TwoFactorDB::is_twofactor_enabled(std::slice::from_ref(
                    &factor
                )),
                expected
            );
        }
    }
}
