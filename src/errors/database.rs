use std::{
    borrow::Cow,
    fmt::{self, Display},
};

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

struct D1ErrorText<'a> {
    cause: Option<Cow<'a, str>>,
    outer: Option<Cow<'a, str>>,
}

impl D1ErrorText<'_> {
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

    pub(crate) const fn query_failed(context: &'static str, d1_code: &'static str) -> AppError {
        AppError::Database(Self::QueryFailed { context, d1_code })
    }

    pub(crate) fn query(context: &'static str, error: &worker::Error) -> AppError {
        Self::query_failed(context, d1_code(error))
    }

    pub(crate) fn invalid_result(context: impl Display, error: impl Display) -> AppError {
        AppError::internal_with_context(
            "Stored database record does not match expected schema",
            format_args!("{context}: {error}"),
        )
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

pub(super) fn worker_display_message(
    summary: Option<&'static str>,
    error: &worker::Error,
) -> Cow<'static, str> {
    if let Some(code) = d1_reason_if_d1(error) {
        Cow::Owned(format!("Database operation failed (D1: {code})"))
    } else if let Some(summary) = summary {
        Cow::Owned(format!("Worker runtime error: {summary}"))
    } else if matches!(error, worker::Error::BindingError(_)) {
        Cow::Borrowed("Worker runtime error: Required Cloudflare binding is missing or invalid")
    } else {
        Cow::Borrowed("Worker runtime error: Cloudflare platform operation failed")
    }
}

pub(super) fn fmt_worker_debug(error: &worker::Error, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Some(code) = d1_reason_if_d1(error) {
        f.debug_tuple("D1").field(&code).finish()
    } else if let worker::Error::BindingError(name) = error {
        f.debug_tuple("BindingError").field(name).finish()
    } else {
        f.debug_tuple("WorkerError")
            .field(&error.to_string())
            .finish()
    }
}

fn d1_reason_if_d1(error: &worker::Error) -> Option<&'static str> {
    match error {
        worker::Error::D1(_) => Some(d1_code(error)),
        // Some SDK D1 methods convert rejections through the general JS path.
        worker::Error::UnknownJsError { message, .. } | worker::Error::JsError(message)
            if matches!(
                message.split(':').next().map(str::trim),
                Some("D1_ERROR" | "D1_TYPE_ERROR" | "D1_COLUMN_NOTFOUND")
            ) =>
        {
            Some(d1_code(error))
        }
        _ => None,
    }
}

fn d1_code(error: &worker::Error) -> &'static str {
    database_error_messages(error)
        .messages()
        .find_map(safe_d1_reason)
        .unwrap_or("D1_ERROR")
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

fn database_error_messages(error: &worker::Error) -> D1ErrorText<'_> {
    // Classify D1 sentinel failures without formatting the underlying stack.
    match error {
        worker::Error::D1(error) => {
            let outer: &js_sys::Error = error.as_ref();
            let cause = outer.cause();
            let cause_message = cause
                .as_string()
                .or_else(|| {
                    cause
                        .dyn_ref::<js_sys::Error>()
                        .map(|error| error.message().into())
                })
                .map(Cow::Owned);
            D1ErrorText {
                cause: cause_message,
                outer: Some(Cow::Owned(outer.message().into())),
            }
        }
        worker::Error::UnknownJsError { message, cause, .. } => {
            let cause = cause.as_deref().map(|error| match error {
                worker::Error::UnknownJsError { message, .. } | worker::Error::JsError(message) => {
                    Cow::Borrowed(message.as_str())
                }
                _ => Cow::Owned(error.to_string()),
            });
            D1ErrorText {
                cause,
                outer: Some(Cow::Borrowed(message.as_str())),
            }
        }
        worker::Error::JsError(message) => D1ErrorText {
            cause: None,
            outer: Some(Cow::Borrowed(message.as_str())),
        },
        _ => D1ErrorText {
            cause: None,
            outer: Some(Cow::Owned(error.to_string())),
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
    use super::{AppError, DatabaseError, registration_email_conflict, safe_d1_reason};

    #[test]
    fn d1_reasons_and_email_conflicts_scrub_sensitive_details() {
        assert_eq!(
            safe_d1_reason("D1_ERROR: no such table: secret: SQLITE_ERROR"),
            Some("SQLITE_ERROR")
        );
        assert_eq!(
            safe_d1_reason("D1_TYPE_ERROR: invalid binding"),
            Some("D1_TYPE_ERROR")
        );
        assert_eq!(safe_d1_reason("D1_ERROR: private detail"), None);

        let app_err = AppError::from(worker::Error::JsError(
            "D1_ERROR: private detail: SQLITE_BUSY".into(),
        ));
        assert_eq!(
            app_err.to_string(),
            "Database operation failed (D1: SQLITE_BUSY)"
        );
        assert!(!format!("{app_err:?}").contains("private detail"));
        assert_eq!(
            DatabaseError::query("Failed", &worker::Error::JsError("private".into())).to_string(),
            "Database query failed: Failed (D1: D1_ERROR)"
        );

        assert!(registration_email_conflict(
            "D1_ERROR: UNIQUE constraint failed: users.email: SQLITE_CONSTRAINT"
        ));
        assert!(!registration_email_conflict(
            "UNIQUE constraint failed: users.id"
        ));
        assert!(!registration_email_conflict(
            "UNIQUE constraint failed: users.email, users.name"
        ));
    }
}
