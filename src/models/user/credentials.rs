use constant_time_eq::constant_time_eq;

use super::UserDB;
use crate::{
    errors::AppError,
    infra::crypto::verify_password,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerification {
    MatchCurrentScheme,
    MatchLegacyScheme,
    Mismatch,
}

impl PasswordVerification {
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::MatchCurrentScheme | Self::MatchLegacyScheme)
    }

    pub const fn needs_migration(&self) -> bool {
        matches!(self, Self::MatchLegacyScheme)
    }
}

impl UserDB {
    pub async fn verify_master_password(
        &self,
        provided_hash: &str,
    ) -> Result<PasswordVerification, AppError> {
        if let Some(ref salt) = self.password_salt {
            let is_valid = verify_password(
                provided_hash,
                &self.master_password_hash,
                salt,
            )
            .await?;
            Ok(if is_valid {
                PasswordVerification::MatchCurrentScheme
            } else {
                PasswordVerification::Mismatch
            })
        } else {
            let is_valid = constant_time_eq(
                self.master_password_hash.as_bytes(),
                provided_hash.as_bytes(),
            );

            Ok(if is_valid {
                PasswordVerification::MatchLegacyScheme
            } else {
                PasswordVerification::Mismatch
            })
        }
    }
}
