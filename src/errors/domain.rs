use std::fmt::Display;

use serde_json::{
    Map,
    Value,
    json,
};

use super::{
    AppError,
    AuthError,
};

impl AppError {
    pub(crate) fn send_unavailable() -> Self {
        Self::not_found("Send does not exist or is no longer available")
    }

    pub(crate) fn auth_request_unavailable() -> Self {
        Self::bad_request("Authentication request is unavailable")
    }

    pub(crate) fn invalid_credentials(message: impl Into<String>) -> Self {
        AuthError::InvalidCredentials(message.into()).into()
    }

    pub(crate) fn invalid_api_credentials() -> Self {
        Self::invalid_credentials("Invalid API credentials")
    }

    pub(crate) fn setup_authorization_required() -> Self {
        Self::Unauthorized {
            message: "Owner setup authorization is required".into(),
        }
    }

    pub(crate) const fn invalid_refresh_token() -> Self {
        Self::OAuth {
            error:       "invalid_grant",
            description: "Invalid or expired refresh token",
        }
    }

    pub(crate) const fn client_version_header_missing() -> Self {
        Self::OAuth {
            error:       "version_header_missing",
            description: "No client version header found, required to prevent \
                          encryption errors. Please confirm your client is \
                          supplying the header: \"Bitwarden-Client-Version\"",
        }
    }

    pub(crate) const fn invalid_client_version() -> Self {
        Self::OAuth {
            error:       "invalid_client_version",
            description: "Please update your app to continue using Bitwarden",
        }
    }

    pub(crate) fn identity_challenge(
        providers: &[i32],
        provider_details: &Map<String, Value>,
    ) -> Self {
        Self::IdentityChallenge(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": providers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "TwoFactorProviders2": provider_details,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        }))
    }

    pub(crate) fn invalid_multipart(error: impl Display) -> Self {
        Self::bad_request(format!("Invalid multipart body: {error}"))
    }
}
