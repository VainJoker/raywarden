//! Application settings read from the current Worker environment.
pub(crate) mod files;

use worker::Env;

use crate::{
    errors::{
        AppError,
        AppResult,
        ConfigError,
    },
    infra::env::{
        env_bool,
        env_text,
    },
};

/// Application configuration loaded from Worker environment variables and
/// secrets.
pub(crate) struct Config {
    pub domain:               String,
    pub jwt_duration_seconds: u64,

    /// Whether user registration is disabled (from
    /// `DISABLE_USER_REGISTRATION`).
    pub registration_disabled: bool,

    /// Import batch size (from `IMPORT_BATCH_SIZE`).
    pub import_batch_size: u32,

    /// Whether TOTP validation should reject ±1 time step drift.
    pub authenticator_time_drift_disabled: bool,

    pub two_factor_remember_days: i64,

    pub allowed_emails: Option<Vec<String>>,
}

impl Config {
    pub(crate) fn from_env(env: &Env) -> AppResult<Self> {
        let env_value_or = |key: &str, default: &str| -> String {
            env.var(key)
                .map_or_else(|_| default.to_string(), |v| v.to_string())
        };

        let domain = env
            .var("DOMAIN")
            .map_err(|e| {
                log::error!("DOMAIN load failed: {e}");
                AppError::Config(ConfigError::Missing("DOMAIN".to_string()))
            })?
            .to_string();

        let domain = parse_domain_origin(&domain)?;

        let import_batch_size = env_value_or("IMPORT_BATCH_SIZE", "30");

        let allowed_emails = env_text(env, "ALLOWED_EMAILS")
            .map(|raw| parse_allowed_emails(&raw))
            .transpose()?;

        let jwt_duration_seconds = parse_jwt_duration_seconds(
            &env_value_or("JWT_DURATION_SECONDS", "3600"),
            crate::utils::time::now_seconds(),
        )?;
        Ok(Self {
            domain,
            jwt_duration_seconds,
            registration_disabled: env_bool(
                env,
                "DISABLE_USER_REGISTRATION",
                true,
            ),
            import_batch_size: import_batch_size.parse().unwrap_or(30),
            authenticator_time_drift_disabled: env_bool(
                env,
                "AUTHENTICATOR_DISABLE_TIME_DRIFT",
                false,
            ),
            two_factor_remember_days: env_value_or(
                "TWO_FACTOR_REMEMBER_DAYS",
                "30",
            )
            .trim()
            .parse::<i64>()
            .unwrap_or(30)
            .clamp(1, 90),

            allowed_emails,
        })
    }
}

pub(crate) fn cors_allowed_origins(env: &Env) -> Option<String> {
    env_text(env, "CORS_ALLOWED_ORIGINS")
}

fn parse_jwt_duration_seconds(
    value: &str,
    now: i64,
) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .filter(|seconds| {
            i64::try_from(*seconds)
                .ok()
                .and_then(|seconds| now.checked_add(seconds))
                .is_some()
        })
        .ok_or_else(|| {
            ConfigError::Invalid(
                "JWT_DURATION_SECONDS must be positive and fit a Unix-second \
                 expiration timestamp"
                    .to_string(),
            )
        })
}

fn parse_domain_origin(domain: &str) -> AppResult<String> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Err(ConfigError::Missing("DOMAIN".to_string()).into());
    }
    let value = if domain.contains("://") {
        domain.to_owned()
    } else {
        format!("https://{domain}")
    };
    let invalid = || {
        ConfigError::Invalid(
            "DOMAIN must be an HTTPS origin without credentials, path, query \
             or fragment; HTTP is allowed only for loopback development"
                .to_owned(),
        )
    };
    if value.chars().any(char::is_whitespace) || value.contains('\\') {
        return Err(invalid().into());
    }
    let url = url::Url::parse(&value).map_err(|_error| invalid())?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if url.host().is_none() ||
        !url.username().is_empty() ||
        url.password().is_some() ||
        url.path() != "/" ||
        url.query().is_some() ||
        url.fragment().is_some() ||
        !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        return Err(invalid().into());
    }
    Ok(url.origin().ascii_serialization())
}

pub(crate) fn normalize_account_email(raw: &str) -> AppResult<String> {
    let invalid = || {
        AppError::bad_request(
            "Expected a complete email address without wildcards",
        )
    };
    if raw.chars().any(char::is_control) || !raw.is_ascii() {
        return Err(invalid());
    }
    let email = raw.trim().to_ascii_lowercase();
    let mut parts = email.split('@');
    let local = parts.next().ok_or_else(invalid)?;
    let domain = parts.next().ok_or_else(invalid)?;
    if parts.next().is_some() ||
        email.len() > 254 ||
        local.is_empty() ||
        local.len() > 64 ||
        local.starts_with('.') ||
        local.ends_with('.') ||
        local.contains("..") ||
        !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() ||
                matches!(byte, b'.' | b'_' | b'+' | b'-')
        }) ||
        domain.len() > 253 ||
        !domain.contains('.') ||
        !domain.split('.').all(|label| {
            !label.is_empty() &&
                label.len() <= 63 &&
                !label.starts_with('-') &&
                !label.ends_with('-') &&
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid());
    }
    Ok(email)
}

/// Exact addresses keep private enrollment bounded without a user-management
/// service.
fn parse_allowed_emails(raw: &str) -> AppResult<Vec<String>> {
    let mut emails = raw
        .split([',', '\n'])
        .map(normalize_account_email)
        .collect::<AppResult<Vec<_>>>()?;
    emails.sort_unstable();
    emails.dedup();
    Ok(emails)
}

#[cfg(test)]
mod account_email_tests {
    use super::*;
    #[test]
    fn account_email_is_one_plain_normalized_address() {
        assert_eq!(
            normalize_account_email(" Owner+vault@Example.TEST ")
                .expect("test fixture should be valid"),
            "owner+vault@example.test"
        );
        for invalid in [
            "",
            "*",
            "a*@example.test",
            "a?@example.test",
            "a@b.test,c@d.test",
            "a@b.test\nc@d.test",
            "a@b.test;",
            "a@@b.test",
            "a@localhost",
            ".a@b.test",
            "a..b@b.test",
            "a@-b.test",
            "a@b..test",
            "a @b.test",
        ] {
            assert!(normalize_account_email(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn allowlist_accepts_lists_and_normalizes_scope() {
        assert_eq!(
            parse_allowed_emails(
                " B@Example.test, a@example.test\nb@example.test "
            )
            .expect("test fixture should be valid"),
            vec!["a@example.test", "b@example.test"]
        );
        for raw in [
            "",
            "a@example.test,",
            "*@example.test",
            "a@example.test,,b@example.test",
        ] {
            assert!(parse_allowed_emails(raw).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_duration_rejects_invalid_values_and_expiration_overflow() {
        assert_eq!(
            parse_jwt_duration_seconds("3600", 1_800_000_000).ok(),
            Some(3600)
        );
        for value in [
            "0",
            "-1",
            "nope",
            "",
            "9223372036854775807",
            "18446744073709551615",
        ] {
            assert!(
                parse_jwt_duration_seconds(value, 1_800_000_000).is_err(),
                "{value}"
            );
        }
        assert!(parse_jwt_duration_seconds("1", i64::MAX).is_err());
    }

    #[test]
    fn domain_is_normalized_to_an_origin() {
        assert_eq!(
            parse_domain_origin(" vault.example/ ").ok().as_deref(),
            Some("https://vault.example")
        );
        assert_eq!(
            parse_domain_origin("http://localhost:8787/")
                .ok()
                .as_deref(),
            Some("http://localhost:8787")
        );
        assert!(parse_domain_origin("").is_err());
        assert!(parse_domain_origin("ftp://vault.example").is_err());
        assert_eq!(
            parse_domain_origin("HTTPS://VAULT.EXAMPLE:443/")
                .ok()
                .as_deref(),
            Some("https://vault.example")
        );
        assert!(parse_domain_origin("http://127.0.0.1:8787").is_ok());
        assert!(parse_domain_origin("http://[::1]:8787").is_ok());
        for domain in [
            "https://user:password@vault.example",
            "https://vault.example/path",
            "https://vault.example?token=secret",
            "https://vault.example#fragment",
            "https://vault.exa mple",
            "https://vault.example\\path",
            "http://vault.example",
            "http://localhost.attacker.example",
        ] {
            assert!(parse_domain_origin(domain).is_err(), "{domain}");
        }
    }
}
