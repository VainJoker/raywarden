use std::fmt::Display;

use super::{
    AppError,
    DatabaseError,
};

impl DatabaseError {
    pub(crate) fn query_failed(message: impl Into<String>) -> AppError {
        Self::QueryFailed(message.into()).into()
    }

    pub(crate) fn query(
        context: impl Display,
        error: impl Display,
    ) -> AppError {
        Self::query_failed(format!("{context}: {error}"))
    }

    pub(crate) fn invalid_result(
        context: impl Display,
        error: impl Display,
    ) -> AppError {
        AppError::InternalFailure(format!("{context}: {error}"))
    }

    pub(crate) fn missing_cipher() -> AppError {
        Self::query_failed("Cipher not found")
    }

    pub(crate) fn invalid_folder() -> AppError {
        AppError::Params(
            "Invalid folder: Folder does not exist or belongs to another user"
                .into(),
        )
    }

    pub(crate) fn vault_write(
        error: worker::Error,
        session_sentinel: &str,
        conflict_sentinel: &str,
        quota_sentinel: &str,
    ) -> AppError {
        let message = error.to_string();
        if message.contains(session_sentinel) {
            AppError::Unauthorized {
                message: "Session expired. Please log in again.".into(),
            }
        } else if message.contains(conflict_sentinel) {
            AppError::bad_request(
                "The vault changed during this request. Please retry.",
            )
        } else if message.contains(quota_sentinel) {
            AppError::Params("Attachment storage limit reached".into())
        } else {
            error.into()
        }
    }

    pub(crate) fn account_rotation(
        error: worker::Error,
        conflict_sentinel: &str,
        fallback: impl FnOnce(worker::Error) -> AppError,
    ) -> AppError {
        if error.to_string().contains(conflict_sentinel) {
            Self::account_rotation_conflict()
        } else {
            fallback(error)
        }
    }

    pub(crate) fn account_rotation_conflict() -> AppError {
        AppError::conflict(
            "The vault changed during key rotation. Sync and retry.",
        )
    }

    pub(crate) fn totp_write(error: worker::Error) -> AppError {
        if error.to_string().contains("RAY_TOTP_WRITE_CONFLICT") {
            AppError::conflict("Authenticator configuration changed; retry")
        } else {
            error.into()
        }
    }

    pub(crate) fn send_access(error: worker::Error) -> AppError {
        if error.to_string().contains("RW_SEND_ACCESS_DENIED") {
            AppError::send_unavailable()
        } else {
            error.into()
        }
    }

    pub(crate) fn api_key_session(error: worker::Error) -> AppError {
        if error.to_string().contains("RAY_API_KEY_SESSION_CONFLICT") {
            AppError::bad_request("API key was rotated or session changed")
        } else {
            Self::query("Failed to bind API key session", error)
        }
    }

    pub(crate) fn registration(error: worker::Error) -> AppError {
        if registration_email_conflict(&error.to_string()) {
            AppError::conflict("An account with this email already exists")
        } else {
            Self::query("Failed to insert user", error)
        }
    }
}

fn registration_email_conflict(message: &str) -> bool {
    message.contains("UNIQUE constraint failed") &&
        message.contains("users.email")
}

#[cfg(test)]
mod tests {
    use super::registration_email_conflict;

    #[test]
    fn only_email_uniqueness_conflicts_map_to_account_exists() {
        assert!(registration_email_conflict(
            "UNIQUE constraint failed: users.email"
        ));
        for other in [
            "UNIQUE constraint failed: users.id",
            "FOREIGN KEY constraint failed",
            "no such table: users",
            "network unavailable",
        ] {
            assert!(!registration_email_conflict(other));
        }
    }
}
