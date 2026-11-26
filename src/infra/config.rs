//! Application settings read from the current Worker environment.

use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use email_address::{EmailAddress, Options};
use worker::Env;

use crate::errors::{AppError, AppResult, ConfigError};

fn env_var(env: &Env, name: &str) -> Option<String> {
    env.var(name).ok().map(|value| value.to_string())
}

fn env_parse<T: FromStr>(env: &Env, name: &str) -> Option<T> {
    env_var(env, name).and_then(|value| value.parse().ok())
}

/// Application configuration loaded from Worker environment variables and
/// secrets.
pub(crate) struct Config {
    pub domain: String,
    pub jwt_duration_seconds: u64,

    /// Import batch size (from `IMPORT_BATCH_SIZE`).
    pub import_batch_size: u32,

    /// Whether TOTP validation should reject ±1 time step drift.
    pub authenticator_time_drift_disabled: bool,

    pub two_factor_remember_days: i64,

    pub allowed_emails: Option<Vec<String>>,
}

impl Config {
    pub(crate) fn from_env(env: &Env) -> AppResult<Self> {
        let domain = env_var(env, "DOMAIN").ok_or(ConfigError::Missing("DOMAIN"))?;
        let domain = parse_domain_origin(&domain)?;

        let allowed_emails = env_text(env, "ALLOWED_EMAILS")
            .map(|raw| parse_allowed_emails(&raw))
            .transpose()?;

        let jwt_duration = env_var(env, "JWT_DURATION_SECONDS");
        let jwt_duration_seconds = parse_jwt_duration_seconds(
            jwt_duration.as_deref().unwrap_or("3600"),
            crate::utils::time::now_seconds(),
        )?;
        Ok(Self {
            domain,
            jwt_duration_seconds,
            import_batch_size: env_parse(env, "IMPORT_BATCH_SIZE").unwrap_or(30),
            authenticator_time_drift_disabled: env_bool(
                env,
                "AUTHENTICATOR_DISABLE_TIME_DRIFT",
                false,
            ),
            two_factor_remember_days: env_var(env, "TWO_FACTOR_REMEMBER_DAYS")
                .and_then(|value| value.trim().parse::<i64>().ok())
                .unwrap_or(30)
                .clamp(1, 90),

            allowed_emails,
        })
    }
}

pub(crate) fn cors_allowed_origins(env: &Env) -> AppResult<Option<String>> {
    string_binding(env, "CORS_ALLOWED_ORIGINS")
}

pub(crate) fn owner_setup_secret(env: &Env) -> AppResult<String> {
    env.secret("OWNER_SETUP_TOKEN")
        .map(|value| value.to_string())
        .map_err(|_error| AppError::bad_request("Owner setup is not configured"))
}

pub(crate) fn webauthn_allowed_origins(env: &Env) -> String {
    env_var(env, "WEBAUTHN_ALLOWED_ORIGINS").unwrap_or_default()
}

pub(crate) fn registration_disabled(env: &Env) -> bool {
    env_bool(env, "DISABLE_USER_REGISTRATION", true)
}

pub(crate) fn fill_assist_rules_url(env: &Env) -> String {
    env_var(env, "FILL_ASSIST_RULES_URL")
        .filter(|value| is_valid_fill_assist_url(value))
        .unwrap_or_else(|| "https://fillassist.bitwarden.com".into())
}

fn is_valid_fill_assist_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        value.trim() == value
            && url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

pub(crate) fn release_id(env: &Env) -> Option<String> {
    env_var(env, "RAYWARDEN_RELEASE_ID").filter(|id| {
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) const DEFAULT_SEND_TEXT_SIZE_BYTES: usize = 1_887_436;

pub(crate) fn send_text_size_bytes(env: &Env) -> usize {
    let value = env_var(env, "SEND_TEXT_MAX_BYTES");
    parse_send_text_size_bytes(value.as_deref())
}

fn parse_send_text_size_bytes(value: Option<&str>) -> usize {
    const D1_SAFE_BYTES: u64 = 1_900_000;
    value
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEND_TEXT_SIZE_BYTES as u64)
        .min(D1_SAFE_BYTES) as usize
}

/// Read an optional secret or variable without introducing mandatory bindings.
pub fn env_text(env: &Env, key: &str) -> Option<String> {
    env_var(env, key).filter(|v| !v.trim().is_empty())
}

pub(crate) fn trash_retention_days(env: &Env) -> i64 {
    env_parse(env, "TRASH_AUTO_DELETE_DAYS").unwrap_or(30)
}

pub fn env_bool(env: &Env, key: &str, default: bool) -> bool {
    env_text(env, key)
        .as_deref()
        .and_then(parse_bool)
        .unwrap_or(default)
}

fn parse_bool(value: &str) -> Option<bool> {
    let value = value.trim();
    if ["1", "true", "yes", "on"]
        .iter()
        .any(|option| value.eq_ignore_ascii_case(option))
    {
        Some(true)
    } else if ["0", "false", "no", "off"]
        .iter()
        .any(|option| value.eq_ignore_ascii_case(option))
    {
        Some(false)
    } else {
        None
    }
}

pub(crate) fn string_binding(env: &Env, name: &str) -> AppResult<Option<String>> {
    // Distinguish an absent property from a value of the wrong type.
    let value = js_sys::Reflect::get(env, &name.into()).map_err(AppError::internal_discard(
        "Failed to read Worker environment binding",
    ))?;
    if value.is_undefined() {
        return Ok(None);
    }
    value
        .as_string()
        .map(Some)
        .ok_or_else(|| AppError::internal("Worker environment binding must be a string"))
}

fn parse_jwt_duration_seconds(value: &str, now: i64) -> Result<u64, ConfigError> {
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
        .ok_or(ConfigError::Invalid(
            "JWT_DURATION_SECONDS must be positive and fit a Unix-second \
             expiration timestamp",
        ))
}

fn parse_domain_origin(domain: &str) -> AppResult<String> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Err(ConfigError::Missing("DOMAIN").into());
    }
    let value: std::borrow::Cow<'_, str> = if domain.contains("://") {
        std::borrow::Cow::Borrowed(domain)
    } else {
        std::borrow::Cow::Owned(format!("https://{domain}"))
    };
    let invalid = || {
        ConfigError::Invalid(
            "DOMAIN must be an HTTPS origin without credentials, path, query \
             or fragment; HTTP is allowed only for loopback development",
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
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        return Err(invalid().into());
    }
    Ok(url.origin().ascii_serialization())
}

/// Parse exact, normalized addresses from `ALLOWED_EMAILS`.
fn parse_allowed_emails(raw: &str) -> AppResult<Vec<String>> {
    let invalid = || AppError::bad_request("Expected a complete email address without wildcards");
    let options = Options::default()
        .without_display_text()
        .without_domain_literal()
        .with_required_tld();
    let mut emails = Vec::new();
    for value in raw.split([',', '\n']) {
        let email = value.trim();
        if !value.is_ascii() || value.chars().any(char::is_control) || email.len() > 254 {
            return Err(invalid());
        }
        let Ok(address) = EmailAddress::parse_with_options(email, options) else {
            return Err(invalid());
        };
        // Keep the account character policy in sync with scripts/deploy.mjs.
        let valid_local = address
            .local_part()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'));
        let valid_domain = address
            .domain()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
        if !valid_local || !valid_domain {
            return Err(invalid());
        }
        let mut email = String::from(address);
        email.make_ascii_lowercase();
        emails.push(email);
    }
    emails.sort_unstable();
    emails.dedup();
    Ok(emails)
}

// Attachment and Send settings are read when used.
const DEFAULT_ATTACHMENT_TOKEN_TTL_SECONDS: i64 = 60;
const DEFAULT_SEND_FILE_TOKEN_TTL_SECONDS: i64 = 300;
pub(crate) const DEFAULT_SEND_MAX_BYTES: i64 = 95 * 1024 * 1024;

fn attachment_setting<T: FromStr>(
    env: &Env,
    name: &str,
    parse_error: &'static str,
) -> AppResult<Option<T>>
where
    T::Err: Display,
{
    env_var(env, name)
        .map(|value| {
            value
                .parse()
                .map_err(|error| AppError::internal_with_context(parse_error, error))
        })
        .transpose()
}

pub(crate) fn attachment_token_ttl_seconds(env: &Env) -> AppResult<i64> {
    let ttl = attachment_setting(env, "ATTACHMENT_TTL_SECS", "Invalid ATTACHMENT_TTL_SECS")?
        .unwrap_or(DEFAULT_ATTACHMENT_TOKEN_TTL_SECONDS);
    if ttl <= 0 {
        return Err(AppError::internal("ATTACHMENT_TTL_SECS must be positive"));
    }
    Ok(ttl)
}

pub(crate) fn attachment_max_bytes(env: &Env) -> AppResult<Option<u64>> {
    attachment_setting(env, "ATTACHMENT_MAX_BYTES", "Invalid ATTACHMENT_MAX_BYTES")
}

pub(crate) fn attachment_quota_bytes(env: &Env) -> AppResult<Option<u64>> {
    attachment_setting::<u64>(
        env,
        "ATTACHMENT_TOTAL_LIMIT_KB",
        "Invalid ATTACHMENT_TOTAL_LIMIT_KB",
    )?
    .map(|kb| {
        kb.checked_mul(1024).ok_or_else(|| {
            AppError::internal("ATTACHMENT_TOTAL_LIMIT_KB overflowed when converting to bytes")
        })
    })
    .transpose()
}

pub(crate) fn send_max_bytes(env: &Env) -> i64 {
    env_parse::<i64>(env, "SEND_MAX_BYTES")
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_SEND_MAX_BYTES)
}

pub(crate) fn send_quota_bytes(env: &Env) -> AppResult<Option<i64>> {
    let Some(value) =
        string_binding(env, "USER_SEND_LIMIT_KB").map_err(|_error| invalid_send_quota())?
    else {
        return Ok(None);
    };
    value
        .parse::<i64>()
        .ok()
        .filter(|kb| *kb >= 0)
        .and_then(|kb| kb.checked_mul(1024))
        .map(Some)
        .ok_or_else(invalid_send_quota)
}

fn invalid_send_quota() -> AppError {
    ConfigError::Invalid("USER_SEND_LIMIT_KB must be a nonnegative integer in KiB").into()
}

pub(crate) fn send_file_token_expires_at_seconds(env: &Env, now_seconds: i64) -> AppResult<i64> {
    let value = env_var(env, "SEND_TTL_SECS");
    parse_send_file_token_expires_at_seconds(value.as_deref(), now_seconds)
}

fn parse_send_file_token_expires_at_seconds(
    value: Option<&str>,
    now_seconds: i64,
) -> AppResult<i64> {
    let ttl_seconds = value
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(DEFAULT_SEND_FILE_TOKEN_TTL_SECONDS);
    let expires_at_seconds = (ttl_seconds > 0)
        .then(|| now_seconds.checked_add(ttl_seconds))
        .flatten()
        .filter(|expires_at_seconds| jiff::Timestamp::from_second(*expires_at_seconds).is_ok());
    expires_at_seconds.ok_or_else(|| {
        ConfigError::Invalid(
            "SEND_TTL_SECS must be positive and fit a supported expiration \
             timestamp",
        )
        .into()
    })
}

const DEFAULT_ON_FLAGS: &[&str] = &[
    "pm-32413-multi-client-password-management",
    "enable-basic-auth-response",
    "pm-32009-new-item-types",
];
const OPTIONAL_FLAGS: &[&str] = &[
    "pm-5594-safari-account-switching",
    "undetermined-cipher-scenario-logic",
    "fill-assist-targeting-rules",
    "ssh-agent-v2",
    "windows-desktop-autotype",
    "windows-desktop-autotype-ga",
    "biometrics-sdk-ipc",
    "windows-native-credential-sync",
    "macos-native-credential-sync",
    "pm-27278-v2-password-registration",
    "pm-34171-card-scanner",
    "pm-30529-webauthn-related-origins",
];

fn parse_feature_flags(value: &str) -> impl Iterator<Item = (String, bool)> + '_ {
    value.split(',').filter_map(|entry| {
        let (name, enabled) = entry.split_once('=').unwrap_or((entry, "true"));
        let name = name.trim();
        if !DEFAULT_ON_FLAGS.contains(&name) && !OPTIONAL_FLAGS.contains(&name) {
            return None;
        }
        Some((name.to_owned(), parse_bool(enabled)?))
    })
}

pub(crate) fn client_feature_flags(env: &Env) -> BTreeMap<String, bool> {
    let mut features = ["pm-19148-innovation-archive"]
        .into_iter()
        .chain(DEFAULT_ON_FLAGS.iter().copied())
        .map(|flag| (flag.to_owned(), true))
        .collect::<BTreeMap<_, _>>();
    if let Some(value) = env_text(env, "CLIENT_FEATURE_FLAGS") {
        features.extend(parse_feature_flags(&value));
    }
    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_and_feature_flags_normalize_and_reject_wildcards() {
        let flags = parse_feature_flags("macos-native-credential-sync,windows-native-credential-sync=false,force-upgrade-v2-encryption,bogus")
            .collect::<BTreeMap<_, _>>();
        assert_eq!(flags.len(), 2);
        assert_eq!(
            parse_allowed_emails(" B@Example.test, Owner+v@Example.test\nb@example.test ")
                .expect("valid"),
            vec!["b@example.test", "owner+v@example.test"]
        );
        for bad in [
            "",
            "a@b.test,",
            "*@b.test",
            "a@@b.test",
            "a@localhost",
            "Name <a@b.test>",
        ] {
            assert!(parse_allowed_emails(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn origins_durations_and_limits_enforce_bounds() {
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
        for bad in [
            "",
            "http://vault.example",
            "https://u:p@vault.example",
            "https://vault.example/path",
            "http://localhost.evil.test",
        ] {
            assert!(parse_domain_origin(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_jwt_duration_seconds("3600", 1_800_000_000).ok(),
            Some(3600)
        );
        assert!(parse_jwt_duration_seconds("0", 1_800_000_000).is_err());
        assert!(parse_jwt_duration_seconds("1", i64::MAX).is_err());
        assert_eq!(
            parse_send_file_token_expires_at_seconds(None, 1_000).expect("default"),
            1_300
        );
        assert!(parse_send_file_token_expires_at_seconds(Some("0"), 1_000).is_err());
        assert_eq!(
            parse_send_text_size_bytes(Some("18446744073709551615")),
            1_900_000
        );
        assert!(is_valid_fill_assist_url(
            "https://rules.example.test/rules.json"
        ));
        assert!(!is_valid_fill_assist_url("http://rules.example.test"));
    }
}
