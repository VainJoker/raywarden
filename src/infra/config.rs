use worker::Env;

use crate::errors::{
    AppError,
    AppResult,
    ConfigError,
};

/// Application configuration loaded from Worker environment variables and
/// secrets.
#[derive(Clone)]
pub struct Config {
    pub domain: String,

    /// Shared Worker/DO CORS policy, including the legacy variable alias.
    pub cors: super::cors::CorsPolicy,

    /// Stable JWT signing secret loaded from D1.
    pub jwt_secret: String,

    pub jwt_duration_seconds: u64,

    pub jwt_refresh_secret: String,

    /// KDF iterations for client-side key derivation (default: 600000 for
    /// Argon2id).
    pub kdf_iterations: u32,

    /// KDF memory in MB for Argon2id (default: 64).
    pub kdf_memory: u32,

    /// KDF parallelism for Argon2id (default: 4).
    pub kdf_parallelism: u32,

    /// Whether user registration is disabled (from
    /// `DISABLE_USER_REGISTRATION`).
    pub disable_user_registration: bool,

    /// Import batch size (from `IMPORT_BATCH_SIZE`).
    pub import_batch_size: u32,

    /// Whether TOTP validation should reject ±1 time step drift.
    pub authenticator_disable_time_drift: bool,

    pub allowed_emails: Option<Vec<String>>,
}

impl Config {
    /// Read the current environment and D1-owned signing keys without a global
    /// cache.
    pub async fn from_env(env: &Env) -> Result<Self, AppError> {
        // Helper for getting with default
        let get_var_or = |key: &str, default: &str| -> String {
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

        let domain = normalize_domain(&domain)?;
        let cors = super::cors::CorsPolicy::from_env(env);

        let disable_user_registration = env
            .var("DISABLE_USER_REGISTRATION")
            .ok()
            .map(|value| value.to_string().to_lowercase());

        let import_batch_size = get_var_or("IMPORT_BATCH_SIZE", "30");

        let authenticator_disable_time_drift = env
            .var("AUTHENTICATOR_DISABLE_TIME_DRIFT")
            .ok()
            .map(|value| value.to_string().to_lowercase());

        let allowed_emails = match env.secret("ALLOWED_EMAILS") {
            Ok(secret) => {
                let emails_str = secret.to_string();
                let emails: Vec<String> = emails_str
                    .split([',', '\n'])
                    .map(|line| line.trim().to_lowercase())
                    .filter(|line| !line.is_empty())
                    .collect();
                Some(emails)
            }
            Err(_) => env.var("ALLOWED_EMAILS").ok().map(|value| {
                value
                    .to_string()
                    .split([',', '\n'])
                    .map(|line| line.trim().to_lowercase())
                    .filter(|line| !line.is_empty())
                    .collect()
            }),
        };

        let jwt_duration_seconds = parse_jwt_duration(
            &get_var_or("JWT_DURATION_SECONDS", "3600"),
            crate::infra::time::now_seconds(),
        )?;
        let keys = crate::infra::jwt_keys::load(env).await?;

        Ok(Self {
            domain,
            cors,
            jwt_secret: keys.access_secret,
            jwt_refresh_secret: keys.refresh_secret,
            jwt_duration_seconds,
            kdf_iterations: get_var_or("KDF_ITERATIONS", "600000")
                .parse()
                .unwrap_or(600_000),
            kdf_memory: get_var_or("KDF_MEMORY", "64").parse().unwrap_or(64),
            kdf_parallelism: get_var_or("KDF_PARALLELISM", "4")
                .parse()
                .unwrap_or(4),
            disable_user_registration: parse_bool(
                disable_user_registration.as_deref(),
                true,
            ),
            import_batch_size: import_batch_size.parse().unwrap_or(30),
            authenticator_disable_time_drift: parse_bool(
                authenticator_disable_time_drift.as_deref(),
                false,
            ),

            allowed_emails,
        })
    }
}

fn parse_jwt_duration(value: &str, now: i64) -> Result<u64, ConfigError> {
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

fn parse_bool(value: Option<&str>, default: bool) -> bool {
    match value.map(str::trim) {
        Some("1" | "true" | "yes" | "on") => true,
        Some("0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

fn normalize_domain(domain: &str) -> AppResult<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_duration_rejects_invalid_values_and_expiration_overflow() {
        assert_eq!(parse_jwt_duration("3600", 1_800_000_000).ok(), Some(3600));
        for value in [
            "0",
            "-1",
            "nope",
            "",
            "9223372036854775807",
            "18446744073709551615",
        ] {
            assert!(
                parse_jwt_duration(value, 1_800_000_000).is_err(),
                "{value}"
            );
        }
        assert!(parse_jwt_duration("1", i64::MAX).is_err());
    }

    #[test]
    fn booleans_preserve_explicit_values_and_defaults() {
        assert!(parse_bool(Some("true"), false));
        assert!(!parse_bool(Some("false"), true));
        assert!(parse_bool(None, true));
        assert!(!parse_bool(None, false));
    }

    #[test]
    fn domain_is_an_absolute_base_url() {
        assert_eq!(
            normalize_domain(" vault.example/ ").ok().as_deref(),
            Some("https://vault.example")
        );
        assert_eq!(
            normalize_domain("http://localhost:8787/").ok().as_deref(),
            Some("http://localhost:8787")
        );
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("ftp://vault.example").is_err());
        assert_eq!(
            normalize_domain("HTTPS://VAULT.EXAMPLE:443/")
                .ok()
                .as_deref(),
            Some("https://vault.example")
        );
        assert!(normalize_domain("http://127.0.0.1:8787").is_ok());
        assert!(normalize_domain("http://[::1]:8787").is_ok());
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
            assert!(normalize_domain(domain).is_err(), "{domain}");
        }
    }
}

/// Read an optional secret or variable without introducing mandatory bindings.
pub fn env_text(env: &Env, key: &str) -> Option<String> {
    env.secret(key)
        .ok()
        .map(|v| v.to_string())
        .or_else(|| env.var(key).ok().map(|v| v.to_string()))
        .filter(|v| !v.trim().is_empty())
}

pub fn env_bool(env: &Env, key: &str, default: bool) -> bool {
    env_text(env, key)
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
        .map_or(default, |value| parse_bool(Some(value), default))
}
