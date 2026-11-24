use axum::http::HeaderMap;

use crate::{
    errors::{AppError, AppResult},
    service::identity::{oauth, two_factor::TwoFactorProvider},
    utils::constant_time_eq,
};

pub(super) enum GrantRequest {
    Password(PasswordGrant),
    Refresh(Option<String>),
    ApiKey(ApiKeyGrant),
    Webauthn(WebauthnGrant),
    Send(SendGrant),
}

pub(super) struct DeviceForm {
    pub id: Option<String>,
    pub name: Option<String>,
    pub kind: Option<i32>,
}

pub(super) struct PasswordGrant {
    pub username: Option<String>,
    pub password: Option<String>,
    pub two_factor_token: Option<String>,
    pub two_factor_provider: Option<i32>,
    pub remember_second_factor: bool,
    pub auth_request_id: Option<String>,
    pub access_code: Option<String>,
    pub device: DeviceForm,
}

pub(super) struct ApiKeyGrant {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub device: DeviceForm,
}

pub(super) struct WebauthnGrant {
    pub token: Option<String>,
    pub device_response: Option<String>,
    pub device: DeviceForm,
}

pub(super) struct SendGrant {
    pub id: Option<String>,
    pub password: Option<String>,
}

#[derive(Default)]
struct TokenFormBuilder {
    grant_type: Option<String>,
    username: Option<String>,
    password: Option<String>,
    refresh_token: Option<String>,
    two_factor_token: Option<String>,
    two_factor_provider: Option<String>,
    two_factor_remember: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    device_type: Option<String>,
    auth_request_id: Option<String>,
    access_code: Option<String>,
    send_id: Option<String>,
    access_id: Option<String>,
    password_hash_b64: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
    token: Option<String>,
    device_response: Option<String>,
}

impl TokenFormBuilder {
    fn add(&mut self, key: &str, value: String) -> AppResult<()> {
        let (name, field) = match oauth::normalize_form_key(key).as_str() {
            "granttype" => ("grant_type", &mut self.grant_type),
            "username" => ("username", &mut self.username),
            "password" => ("password", &mut self.password),
            "refreshtoken" => ("refresh_token", &mut self.refresh_token),
            "token" => ("token", &mut self.token),
            "deviceresponse" => ("deviceResponse", &mut self.device_response),
            "scope" => ("scope", &mut self.scope),
            "clientid" => ("client_id", &mut self.client_id),
            "clientsecret" => ("client_secret", &mut self.client_secret),
            "sendid" => ("send_id", &mut self.send_id),
            "accessid" => ("access_id", &mut self.access_id),
            "passwordhashb64" => ("password_hash_b64", &mut self.password_hash_b64),
            "deviceidentifier" | "deviceid" => ("deviceIdentifier", &mut self.device_id),
            "devicename" => ("deviceName", &mut self.device_name),
            "devicetype" => ("deviceType", &mut self.device_type),
            "twofactortoken" => ("twoFactorToken", &mut self.two_factor_token),
            "twofactorprovider" => ("twoFactorProvider", &mut self.two_factor_provider),
            "twofactorremember" => ("twoFactorRemember", &mut self.two_factor_remember),
            "authrequest" => ("authRequest", &mut self.auth_request_id),
            "code" | "accesscode" => ("access_code", &mut self.access_code),
            _ => return Ok(()),
        };
        if field.replace(value).is_some() {
            return Err(AppError::invalid_token_request(format!(
                "Duplicate token field: {name}"
            )));
        }
        Ok(())
    }

    fn finish(self, headers: &HeaderMap, allow_cookies: bool) -> AppResult<GrantRequest> {
        let grant = self
            .grant_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::invalid_token_request("Missing grant_type"))?;
        // The former form decoder validated integers across all grants and reported
        // malformed fields before rejecting an unsupported grant.
        let two_factor_provider = integer(self.two_factor_provider.as_deref())?;
        let remember_second_factor = match self.two_factor_remember.as_deref().map(str::trim) {
            Some(value) if value.eq_ignore_ascii_case("true") => true,
            Some(value) if value.eq_ignore_ascii_case("false") => false,
            value => integer(value)? == Some(1),
        };
        let device = DeviceForm {
            id: self.device_id,
            name: self.device_name,
            kind: integer(self.device_type.as_deref())?,
        };
        match grant {
            "password" => Ok(GrantRequest::Password(
                PasswordGrant {
                    username: self.username,
                    password: self.password,
                    two_factor_token: self
                        .two_factor_token
                        .filter(|proof| !proof.trim().is_empty()),
                    two_factor_provider,
                    remember_second_factor,
                    auth_request_id: self.auth_request_id,
                    access_code: self.access_code,
                    device,
                }
                .with_cookie(headers, allow_cookies)?,
            )),
            "refresh_token" => {
                let mut proof = self.refresh_token;
                if proof.is_none() {
                    require_cookie_origin(allow_cookies)?;
                    proof = oauth::read_token_cookie(headers, "bw_refresh_token")?;
                }
                Ok(GrantRequest::Refresh(proof))
            }
            "client_credentials" => Ok(GrantRequest::ApiKey(ApiKeyGrant {
                client_id: self.client_id,
                client_secret: self.client_secret,
                scope: self.scope,
                device,
            })),
            "webauthn" => Ok(GrantRequest::Webauthn(WebauthnGrant {
                token: self.token,
                device_response: self.device_response,
                device,
            })),
            "send_access" | "access_token" => Ok(GrantRequest::Send(SendGrant {
                id: self.send_id.or(self.access_id),
                password: self.password_hash_b64.or(self.password),
            })),
            _ => Err(AppError::UnsupportedGrantType),
        }
    }
}

impl PasswordGrant {
    fn with_cookie(mut self, headers: &HeaderMap, allow_cookies: bool) -> AppResult<Self> {
        let remember_provider = i32::from(TwoFactorProvider::Remember);
        if self.two_factor_token.is_some()
            || self
                .two_factor_provider
                .is_some_and(|provider| provider != remember_provider)
        {
            return Ok(self);
        }
        let primary = oauth::read_token_cookie(headers, "twoFactorRemember")?;
        let alias = oauth::read_token_cookie(headers, "TwoFactorRemember")?;
        if primary
            .as_ref()
            .zip(alias.as_ref())
            .is_some_and(|(left, right)| !constant_time_eq(left.as_bytes(), right.as_bytes()))
        {
            return Err(AppError::bad_request(
                "Conflicting remembered-login cookies",
            ));
        }
        if let Some(token) = primary.or(alias) {
            require_cookie_origin(allow_cookies)?;
            self.two_factor_token = Some(token);
            self.two_factor_provider = Some(remember_provider);
        }
        Ok(self)
    }
}

impl GrantRequest {
    pub(super) fn parse(
        fields: Vec<(String, String)>,
        headers: &HeaderMap,
        allow_cookies: bool,
    ) -> AppResult<Self> {
        let mut builder = TokenFormBuilder::default();
        for (key, value) in fields {
            builder.add(&key, value)?;
        }
        builder.finish(headers, allow_cookies)
    }

    pub(super) const fn is_login(&self) -> bool {
        matches!(
            self,
            Self::Password(_) | Self::ApiKey(_) | Self::Webauthn(_)
        )
    }
}

fn integer(value: Option<&str>) -> AppResult<Option<i32>> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse)
        .transpose()
        .map_err(|_error| AppError::invalid_token_request("Invalid token form"))
}

fn require_cookie_origin(allowed: bool) -> AppResult<()> {
    if allowed {
        Ok(())
    } else {
        Err(AppError::Unauthorized {
            message: "Token cookie requires the same origin".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(fields: &[(&str, &str)]) -> AppResult<GrantRequest> {
        GrantRequest::parse(
            fields
                .iter()
                .map(|&(name, value)| (name.into(), value.into()))
                .collect(),
            &HeaderMap::new(),
            true,
        )
    }

    #[test]
    fn token_form_normalizes_aliases_and_trims_numbers_only() {
        for (id, kind, provider, proof) in [
            (
                "device_id",
                "device_type",
                "two_factor_provider",
                "two_factor_token",
            ),
            (
                "deviceIdentifier",
                "deviceType",
                "twoFactorProvider",
                "twoFactorToken",
            ),
        ] {
            let GrantRequest::Password(request) = parse(&[
                ("GrAnT_TyPe", " password "),
                ("Password", " opaque password "),
                (id, "device"),
                (kind, "2 "),
                (provider, "0 "),
                (proof, " opaque proof "),
                ("two_factor_remember", "TrUe "),
            ])
            .expect("valid identity fixture") else {
                panic!("expected password grant");
            };
            assert_eq!(request.device.id.as_deref(), Some("device"));
            assert_eq!(request.device.kind, Some(2));
            assert_eq!(request.two_factor_provider, Some(0));
            assert_eq!(request.two_factor_token.as_deref(), Some(" opaque proof "));
            assert_eq!(request.password.as_deref(), Some(" opaque password "));
            assert!(request.remember_second_factor);
        }
    }

    #[test]
    fn blank_proofs_still_occupy_duplicate_fields() {
        assert!(matches!(
            parse(&[
                ("grant_type", "password"),
                ("TWO_FACTOR_TOKEN", "  "),
                ("twoFactorToken", "opaque")
            ]),
            Err(AppError::InvalidTokenRequest { .. })
        ));
    }
}
