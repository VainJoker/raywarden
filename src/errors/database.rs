use std::fmt::Display;

use wasm_bindgen::JsCast as _;

use super::{AppError, DatabaseError};

macro_rules! db_sentinels {
    ($($variant:ident => $value:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum DbSentinel { $($variant),+ }

        impl DbSentinel {
            pub(crate) const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }

            pub(crate) const fn sql_abort_expr(self) -> &'static str {
                match self { $(Self::$variant => concat!("json_extract('[]', '", $value, "')")),+ }
            }
        }
    };
}

db_sentinels! {
    VaultWriteConflict => "RAY_VAULT_WRITE_CONFLICT",
    VaultWriteSession => "RAY_VAULT_WRITE_SESSION",
    AttachmentQuotaExceeded => "RAY_ATTACHMENT_QUOTA_EXCEEDED",
    TotpWriteConflict => "RAY_TOTP_WRITE_CONFLICT",
    LoginRecoveryConflict => "RAY_LOGIN_RECOVERY_CONFLICT",
    LoginPasswordConflict => "RAY_LOGIN_PASSWORD_CONFLICT",
    LoginPasskeyConflict => "RAY_LOGIN_PASSKEY_CONFLICT",
    LoginMfaConflict => "RAY_LOGIN_MFA_CONFLICT",
    LoginApprovalConflict => "RAY_LOGIN_APPROVAL_CONFLICT",
    LoginRememberConflict => "RAY_LOGIN_REMEMBER_CONFLICT",
    ApiKeySessionConflict => "RAY_API_KEY_SESSION_CONFLICT",
    SendAccessDenied => "RAY_SEND_ACCESS_DENIED",
    InvalidVerification => "RAY_INVALID_VERIFICATION",
    EmailChangeConflict => "RAY_EMAIL_CHANGE_CONFLICT",
    EmailProviderSessionConflict => "RAY_EMAIL_PROVIDER_SESSION_CONFLICT",
    EmailVerificationConflict => "RAY_EMAIL_VERIFICATION_CONFLICT",
    EnableEmailProviderFailed => "RAY_ENABLE_EMAIL_PROVIDER_FAILED",
    RegistrationInsertFailed => "RAY_REGISTRATION_INSERT_FAILED",
}

use DbSentinel::{
    ApiKeySessionConflict, AttachmentQuotaExceeded, LoginMfaConflict, LoginPasskeyConflict,
    LoginPasswordConflict, LoginRecoveryConflict, SendAccessDenied, TotpWriteConflict,
    VaultWriteConflict, VaultWriteSession,
};

struct D1ErrorText {
    cause: Option<String>,
    outer: Option<String>,
}

impl D1ErrorText {
    fn messages(&self) -> impl Iterator<Item = &str> {
        [self.cause.as_deref(), self.outer.as_deref()]
            .into_iter()
            .flatten()
    }
}

impl DatabaseError {
    pub(crate) fn find_sentinel(
        error: &worker::Error,
        candidates: &[DbSentinel],
    ) -> Option<DbSentinel> {
        let text = database_error_messages(error);
        candidates.iter().copied().find(|candidate| {
            text.messages()
                .any(|message| message.contains(candidate.as_str()))
        })
    }

    pub(crate) fn has_marker(error: &worker::Error, marker: DbSentinel) -> bool {
        Self::find_sentinel(error, &[marker]).is_some()
    }

    pub(crate) fn query_failed(message: impl Into<String>) -> AppError {
        Self::QueryFailed(message.into()).into()
    }

    pub(crate) fn query(context: impl Display, error: &worker::Error) -> AppError {
        Self::query_failed(format!("{context}: {}", d1_error_diagnostic(error)))
    }

    pub(crate) fn invalid_result(context: impl Display, error: impl Display) -> AppError {
        AppError::InternalFailure(format!("{context}: {error}"))
    }

    pub(crate) fn invalid_folder() -> AppError {
        AppError::Params("Invalid folder: Folder does not exist or belongs to another user".into())
    }

    pub(crate) fn vault_write(error: worker::Error) -> AppError {
        match Self::find_sentinel(&error, &[
            VaultWriteSession,
            VaultWriteConflict,
            AttachmentQuotaExceeded,
        ]) {
            Some(VaultWriteSession) => AppError::Unauthorized {
                message: "Session expired. Please log in again.".into(),
            },
            Some(VaultWriteConflict) => {
                AppError::bad_request("The vault changed during this request. Please retry.")
            }
            Some(AttachmentQuotaExceeded) => {
                AppError::Params("Attachment storage limit reached".into())
            }
            _ => error.into(),
        }
    }

    pub(crate) fn account_rotation(
        error: worker::Error,
        fallback: impl FnOnce(worker::Error) -> AppError,
    ) -> AppError {
        if Self::has_marker(&error, VaultWriteConflict) {
            Self::account_rotation_conflict()
        } else {
            fallback(error)
        }
    }

    pub(crate) fn account_rotation_conflict() -> AppError {
        AppError::conflict("The vault changed during key rotation. Sync and retry.")
    }

    pub(crate) fn totp_write(error: worker::Error) -> AppError {
        if Self::has_marker(&error, TotpWriteConflict) {
            AppError::conflict("Authenticator configuration changed; retry")
        } else {
            error.into()
        }
    }

    pub(crate) fn send_access(error: worker::Error) -> AppError {
        if Self::has_marker(&error, SendAccessDenied) {
            AppError::send_unavailable()
        } else {
            error.into()
        }
    }

    pub(crate) fn api_key_session(error: &worker::Error) -> AppError {
        match Self::find_sentinel(error, &[VaultWriteConflict, ApiKeySessionConflict]) {
            Some(VaultWriteConflict) => login_account_changed(),
            Some(ApiKeySessionConflict) => {
                AppError::bad_request("API key was rotated or session changed")
            }
            _ => Self::query("Failed to bind API key session", error),
        }
    }

    pub(crate) fn login_session(error: &worker::Error) -> AppError {
        match Self::find_sentinel(error, &[
            VaultWriteConflict,
            LoginRecoveryConflict,
            LoginPasswordConflict,
            LoginPasskeyConflict,
            LoginMfaConflict,
            DbSentinel::LoginApprovalConflict,
            DbSentinel::LoginRememberConflict,
            TotpWriteConflict,
        ]) {
            Some(VaultWriteConflict) => login_account_changed(),
            Some(LoginRecoveryConflict) => {
                AppError::conflict("Account or recovery code changed; retry recovery")
            }
            Some(LoginPasswordConflict) => {
                AppError::conflict("Account changed while upgrading password verifier")
            }
            Some(LoginPasskeyConflict) => {
                AppError::bad_request("WebAuthn challenge expired, used or counter changed")
            }
            Some(LoginMfaConflict) => AppError::conflict(
                "Second-factor state changed during authentication. Retry login.",
            ),
            Some(DbSentinel::LoginApprovalConflict) => {
                AppError::bad_request("Authentication request expired or already used")
            }
            Some(DbSentinel::LoginRememberConflict) => {
                AppError::conflict("Second-factor or account state changed during remembered login")
            }
            Some(TotpWriteConflict) => super::AuthError::InvalidTotp.into(),
            _ => Self::query("Failed to start device session", error),
        }
    }

    pub(crate) fn registration(error: &worker::Error) -> AppError {
        if database_error_messages(error)
            .messages()
            .any(registration_email_conflict)
        {
            AppError::conflict("An account with this email already exists")
        } else {
            Self::query("Failed to insert user", error)
        }
    }
}

fn login_account_changed() -> AppError {
    AppError::conflict("Account encryption changed during authentication. Retry login.")
}

pub(super) fn worker_error_diagnostic(error: &worker::Error) -> String {
    match error {
        worker::Error::D1(_) => d1_error_diagnostic(error),
        // Some SDK D1 methods convert rejections through the general JS path.
        worker::Error::UnknownJsError { message, .. } | worker::Error::JsError(message)
            if matches!(
                message.split(':').next().map(str::trim),
                Some("D1_ERROR" | "D1_TYPE_ERROR" | "D1_COLUMN_NOTFOUND")
            ) =>
        {
            d1_error_diagnostic(error)
        }
        _ => error.to_string(),
    }
}

fn d1_error_diagnostic(error: &worker::Error) -> String {
    let reason = database_error_messages(error)
        .messages()
        .find_map(safe_d1_reason)
        .unwrap_or("D1_ERROR");
    format!("D1: {reason}")
}

fn safe_d1_reason(message: &str) -> Option<&'static str> {
    const SQLITE_CODES: &[&str] = &[
        "SQLITE_ERROR",
        "SQLITE_CONSTRAINT",
        "SQLITE_BUSY",
        "SQLITE_LOCKED",
        "SQLITE_FULL",
        "SQLITE_IOERR",
        "SQLITE_READONLY",
        "SQLITE_CORRUPT",
    ];
    match message.split(':').next()?.trim() {
        "D1_TYPE_ERROR" => Some("D1_TYPE_ERROR"),
        "D1_COLUMN_NOTFOUND" => Some("D1_COLUMN_NOTFOUND"),
        _ => {
            // SQLite detail may include names or values. Retain its code only.
            let suffix = message.rsplit(':').next()?.trim();
            SQLITE_CODES.iter().copied().find(|code| *code == suffix)
        }
    }
}

fn database_error_messages(error: &worker::Error) -> D1ErrorText {
    // Classify D1 sentinel failures without formatting the underlying stack.
    match error {
        worker::Error::D1(error) => {
            let outer: &js_sys::Error = error.as_ref();
            let cause = outer.cause();
            let cause_message = cause.as_string().or_else(|| {
                cause
                    .dyn_ref::<js_sys::Error>()
                    .map(|error| error.message().into())
            });
            D1ErrorText {
                cause: cause_message,
                outer: Some(outer.message().into()),
            }
        }
        worker::Error::UnknownJsError { message, cause, .. } => {
            let cause = cause.as_deref().map(|error| match error {
                worker::Error::UnknownJsError { message, .. } | worker::Error::JsError(message) => {
                    message.clone()
                }
                _ => error.to_string(),
            });
            D1ErrorText {
                cause,
                outer: Some(message.clone()),
            }
        }
        _ => D1ErrorText {
            cause: None,
            outer: Some(error.to_string()),
        },
    }
}

fn registration_email_conflict(message: &str) -> bool {
    let Some((_, columns)) = message.split_once("UNIQUE constraint failed:") else {
        return false;
    };
    let Some(suffix) = columns.trim_start().strip_prefix("users.email") else {
        return false;
    };
    suffix
        .chars()
        .next()
        .is_none_or(|next| !next.is_ascii_alphanumeric() && !matches!(next, '_' | '.'))
        && !suffix.trim_start().starts_with(',')
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseError, registration_email_conflict, safe_d1_reason, worker_error_diagnostic,
    };

    #[test]
    fn d1_outer_diagnostics_keep_known_codes_without_details() {
        assert_eq!(
            safe_d1_reason("D1_ERROR: no such table: private_name: SQLITE_ERROR"),
            Some("SQLITE_ERROR")
        );
        assert_eq!(
            safe_d1_reason("D1_TYPE_ERROR: invalid binding detail"),
            Some("D1_TYPE_ERROR")
        );
        assert_eq!(
            safe_d1_reason("constraint failed on a private value: SQLITE_CONSTRAINT"),
            Some("SQLITE_CONSTRAINT")
        );
        assert_eq!(safe_d1_reason("D1_ERROR: private detail"), None);
    }

    #[test]
    fn d1_diagnostics_are_bounded_for_generic_sdk_errors() {
        let error = worker::Error::JsError("D1_ERROR: private detail: SQLITE_BUSY".into());
        assert_eq!(worker_error_diagnostic(&error), "D1: SQLITE_BUSY");

        let error = worker::Error::JsError("private detail".into());
        let error = DatabaseError::query("Failed to read", &error);
        assert_eq!(
            error.to_string(),
            "Query failed: Failed to read: D1: D1_ERROR"
        );
    }

    #[test]
    fn only_email_uniqueness_conflicts_map_to_account_exists() {
        assert!(registration_email_conflict(
            "UNIQUE constraint failed: users.email"
        ));
        assert!(registration_email_conflict(
            "D1_ERROR: UNIQUE constraint failed: users.email: \
             SQLITE_CONSTRAINT"
        ));
        for other in [
            "UNIQUE constraint failed: users.id",
            "UNIQUE constraint failed: users.id (UPDATE users.email)",
            "UNIQUE constraint failed: users.email_verified_at",
            "UNIQUE constraint failed: users.email, users.name",
            "FOREIGN KEY constraint failed",
            "no such table: users",
            "network unavailable",
        ] {
            assert!(!registration_email_conflict(other));
        }
    }
}
