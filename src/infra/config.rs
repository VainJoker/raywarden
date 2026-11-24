//! Application settings read from the current Worker environment.

use std::{collections::BTreeMap, str::FromStr};

use email_address::{EmailAddress, Options};
use worker::Env;

use crate::errors::{AppError, AppResult, ConfigError};

pub(crate) struct EnvReader<'a>(pub &'a Env);

impl EnvReader<'_> {
    fn value(&self, name: &str) -> Option<String> {
        self.0.var(name).ok().map(|value| value.to_string())
    }

    pub(crate) fn value_or(&self, name: &str, default: &str) -> String {
        self.value(name).unwrap_or_else(|| default.to_owned())
    }

    pub(crate) fn parse_or_default<T: FromStr>(&self, name: &str, default: T) -> T {
        self.value(name)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    pub(crate) fn required_secret(&self, name: &str) -> AppResult<String> {
        self.0
            .secret(name)
            .map(|value| value.to_string())
            .map_err(|_error| ConfigError::Missing(name.to_owned()).into())
    }
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
        let reader = EnvReader(env);
        let domain = reader
            .value("DOMAIN")
            .ok_or_else(|| ConfigError::Missing("DOMAIN".into()))?;
        let domain = parse_domain_origin(&domain)?;

        let allowed_emails = env_text(env, "ALLOWED_EMAILS")
            .map(|raw| parse_allowed_emails(&raw))
            .transpose()?;

        let jwt_duration_seconds = parse_jwt_duration_seconds(
            &reader.value_or("JWT_DURATION_SECONDS", "3600"),
            crate::utils::time::now_seconds(),
        )?;
        Ok(Self {
            domain,
            jwt_duration_seconds,
            import_batch_size: reader.parse_or_default("IMPORT_BATCH_SIZE", 30),
            authenticator_time_drift_disabled: env_bool(
                env,
                "AUTHENTICATOR_DISABLE_TIME_DRIFT",
                false,
            ),
            two_factor_remember_days: reader
                .value_or("TWO_FACTOR_REMEMBER_DAYS", "30")
                .trim()
                .parse::<i64>()
                .unwrap_or(30)
                .clamp(1, 90),

            allowed_emails,
        })
    }
}

pub(crate) fn cors_allowed_origins(env: &Env) -> AppResult<Option<String>> {
    string_binding(env, "CORS_ALLOWED_ORIGINS")
}

pub(crate) fn heavy_shard_count(env: &Env) -> usize {
    let value = EnvReader(env).value("HEAVY_DO_SHARDS");
    parse_heavy_shard_count(value.as_deref())
}

fn parse_heavy_shard_count(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.trim().parse().ok())
        .filter(|n| (1..=64).contains(n))
        .unwrap_or(16)
}

pub(crate) fn owner_setup_secret(env: &Env) -> AppResult<String> {
    EnvReader(env)
        .required_secret("OWNER_SETUP_TOKEN")
        .map_err(|_error| AppError::bad_request("Owner setup is not configured"))
}

pub(crate) fn webauthn_allowed_origins(env: &Env) -> String {
    EnvReader(env).value_or("WEBAUTHN_ALLOWED_ORIGINS", "")
}

pub(crate) fn registration_disabled(env: &Env) -> bool {
    env_bool(env, "DISABLE_USER_REGISTRATION", true)
}

pub(crate) fn fill_assist_rules_url(env: &Env) -> String {
    EnvReader(env)
        .value("FILL_ASSIST_RULES_URL")
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
    EnvReader(env).value("RAYWARDEN_RELEASE_ID").filter(|id| {
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) const DEFAULT_SEND_TEXT_SIZE_BYTES: usize = 1_887_436;

pub(crate) fn send_text_size_bytes(env: &Env) -> usize {
    let value = EnvReader(env).value("SEND_TEXT_MAX_BYTES");
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
    EnvReader(env).value(key).filter(|v| !v.trim().is_empty())
}

pub(crate) fn trash_retention_days(env: &Env) -> i64 {
    EnvReader(env).parse_or_default("TRASH_AUTO_DELETE_DAYS", 30)
}

pub fn env_bool(env: &Env, key: &str, default: bool) -> bool {
    let Some(value) = env_text(env, key) else {
        return default;
    };
    let value = value.trim();
    if ["1", "true", "yes", "on"]
        .iter()
        .any(|option| value.eq_ignore_ascii_case(option))
    {
        true
    } else if ["0", "false", "no", "off"]
        .iter()
        .any(|option| value.eq_ignore_ascii_case(option))
    {
        false
    } else {
        default
    }
}

pub(crate) fn string_binding(env: &Env, name: &str) -> AppResult<Option<String>> {
    // Distinguish an absent property from a value of the wrong type.
    let value = js_sys::Reflect::get(env, &name.into()).map_err(AppError::internal_error)?;
    if value.is_undefined() {
        return Ok(None);
    }
    value.as_string().map(Some).ok_or(AppError::Internal)
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

pub(crate) fn attachment_token_ttl_seconds(env: &Env) -> AppResult<i64> {
    match env.var("ATTACHMENT_TTL_SECS") {
        Ok(value) => {
            let raw = value.to_string();
            let ttl = raw.parse::<i64>().map_err(|error| {
                AppError::internal_with_context("Invalid ATTACHMENT_TTL_SECS", error)
            })?;

            if ttl <= 0 {
                return Err(AppError::InternalFailure(
                    "ATTACHMENT_TTL_SECS must be positive".into(),
                ));
            }

            Ok(ttl)
        }
        Err(_) => Ok(DEFAULT_ATTACHMENT_TOKEN_TTL_SECONDS),
    }
}

pub(crate) fn attachment_max_bytes(env: &Env) -> AppResult<Option<u64>> {
    match env.var("ATTACHMENT_MAX_BYTES") {
        Ok(value) => {
            let raw = value.to_string();
            raw.parse::<u64>().map(Some).map_err(|error| {
                AppError::internal_with_context("Invalid ATTACHMENT_MAX_BYTES", error)
            })
        }
        Err(_) => Ok(None),
    }
}

pub(crate) fn attachment_quota_bytes(env: &Env) -> AppResult<Option<u64>> {
    match env.var("ATTACHMENT_TOTAL_LIMIT_KB") {
        Ok(value) => {
            let raw = value.to_string();
            let kb = raw.parse::<u64>().map_err(|error| {
                AppError::internal_with_context("Invalid ATTACHMENT_TOTAL_LIMIT_KB", error)
            })?;

            let bytes = kb.checked_mul(1024).ok_or_else(|| {
                AppError::InternalFailure(
                    "ATTACHMENT_TOTAL_LIMIT_KB overflowed when converting to \
                     bytes"
                        .into(),
                )
            })?;

            Ok(Some(bytes))
        }
        Err(_) => Ok(None),
    }
}

pub(crate) fn send_max_bytes(env: &Env) -> i64 {
    env.var("SEND_MAX_BYTES")
        .ok()
        .and_then(|value| value.to_string().parse::<i64>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_SEND_MAX_BYTES)
}

pub(crate) fn send_quota_bytes(env: &Env) -> AppResult<Option<i64>> {
    let value = js_sys::Reflect::get(env, &"USER_SEND_LIMIT_KB".into())
        .map_err(|_error| invalid_send_quota())?;
    if value.is_undefined() {
        return Ok(None);
    }
    value
        .as_string()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|kb| *kb >= 0)
        .and_then(|kb| kb.checked_mul(1024))
        .map(Some)
        .ok_or_else(invalid_send_quota)
}

fn invalid_send_quota() -> AppError {
    ConfigError::Invalid("USER_SEND_LIMIT_KB must be a nonnegative integer in KiB".into()).into()
}

pub(crate) fn send_file_token_expires_at_seconds(env: &Env, now_seconds: i64) -> AppResult<i64> {
    let value = env.var("SEND_TTL_SECS").ok().map(|value| value.to_string());
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
             timestamp"
                .into(),
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
        let enabled = match enabled.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => return None,
        };
        Some((name.to_owned(), enabled))
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
mod account_email_tests {
    use super::*;

    #[test]
    fn client_flags_only_override_supported_configurable_flags() {
        let flags = parse_feature_flags(
            "macos-native-credential-sync,\
                 pm-27278-v2-password-registration,\
                 windows-native-credential-sync=false,\
                 force-upgrade-v2-encryption,pm-30144-sdk-key-rotation,\
                 pm-31050-no-logout-key-upgrade-rotation,\
                 enable-account-encryption-v2-jit-password-registration,bogus,\
                 +             \
                 pm-19148-innovation-archive=false,\
                 pm-32009-new-item-types=FALSE",
        )
        .collect::<BTreeMap<_, _>>();
        assert_eq!(flags.len(), 4);
        assert!(flags["macos-native-credential-sync"]);
        assert!(!flags["windows-native-credential-sync"]);
        assert!(!flags["pm-32009-new-item-types"]);
    }

    #[test]
    fn allowlist_accepts_lists_and_normalizes_scope() {
        assert_eq!(
            parse_allowed_emails(" B@Example.test, a@example.test\nb@example.test ")
                .expect("test fixture should be valid"),
            vec!["a@example.test", "b@example.test"]
        );
        for raw in ["", "a@example.test,", "a@example.test,,b@example.test"] {
            assert!(parse_allowed_emails(raw).is_err());
        }
    }

    #[test]
    fn allowlist_requires_plain_account_addresses() {
        assert_eq!(
            parse_allowed_emails(" Owner+vault@Example.TEST ")
                .expect("test fixture should be valid"),
            vec!["owner+vault@example.test"]
        );
        for invalid in [
            "*",
            "*@example.test",
            "a*@example.test",
            "a?@example.test",
            "a@b.test;",
            "a@@b.test",
            "a@localhost",
            ".a@b.test",
            "a..b@b.test",
            "a@-b.test",
            "a@b..test",
            "a@b_c.test",
            "\"a\"@b.test",
            "a@[127.0.0.1]",
            "Name <a@b.test>",
            "á@b.test",
            "a @b.test",
            "\ta@b.test",
        ] {
            assert!(parse_allowed_emails(invalid).is_err(), "{invalid:?}");
        }

        let local = "a".repeat(64);
        let label = "b".repeat(63);
        let domain = format!("{label}.{label}.{}", "c".repeat(61));
        assert!(parse_allowed_emails(&format!("{local}@{domain}")).is_ok());
        assert!(parse_allowed_emails(&format!("{local}@{domain}c")).is_err());
        assert!(parse_allowed_emails(&format!("{local}a@b.test")).is_err());
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
        for (input, origin) in [
            (" vault.example/ ", "https://vault.example"),
            ("HTTPS://VAULT.EXAMPLE:443/", "https://vault.example"),
            ("http://localhost:8787/", "http://localhost:8787"),
            ("http://127.0.0.1:8787", "http://127.0.0.1:8787"),
            ("http://[::1]:8787", "http://[::1]:8787"),
        ] {
            assert_eq!(
                parse_domain_origin(input).ok().as_deref(),
                Some(origin),
                "{input}"
            );
        }
        for domain in [
            "",
            "ftp://vault.example",
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

    #[test]
    fn file_lifetimes_keep_reference_defaults_and_reject_invalid_dates() {
        for value in [None, Some("invalid"), Some("18446744073709551616")] {
            assert_eq!(
                parse_send_file_token_expires_at_seconds(value, 1_000).expect("valid test fixture"),
                1_300
            );
        }
        assert_eq!(
            parse_send_file_token_expires_at_seconds(Some("17"), 1_000)
                .expect("valid test fixture"),
            1_017
        );
        for value in ["0", "-1", "9223372036854775807", "253402300799"] {
            assert!(parse_send_file_token_expires_at_seconds(Some(value), 1_000).is_err());
        }
        assert!(parse_send_file_token_expires_at_seconds(Some("1"), i64::MAX).is_err());
    }

    #[test]
    fn heavy_shard_counts_stay_within_bounded_range() {
        assert_eq!(parse_heavy_shard_count(Some("2")), 2);
        assert_eq!(parse_heavy_shard_count(Some("64")), 64);
        for value in [None, Some("0"), Some("65"), Some("invalid")] {
            assert_eq!(parse_heavy_shard_count(value), 16);
        }
    }

    #[test]
    fn text_limits_parse_unsigned_and_clamp_before_native_or_wasm_conversion() {
        for value in [
            None,
            Some("invalid"),
            Some("-1"),
            Some("18446744073709551616"),
        ] {
            assert_eq!(
                parse_send_text_size_bytes(value),
                DEFAULT_SEND_TEXT_SIZE_BYTES
            );
        }
        assert_eq!(parse_send_text_size_bytes(Some("0")), 0);
        assert_eq!(parse_send_text_size_bytes(Some("23")), 23);
        assert_eq!(
            parse_send_text_size_bytes(Some("18446744073709551615")),
            1_900_000
        );
    }

    #[test]
    fn rules_urls_cannot_carry_credentials_queries_or_non_https_schemes() {
        assert!(is_valid_fill_assist_url(
            "https://rules.example.test/rules.json"
        ));
        for value in [
            "http://rules.example.test",
            "https://user@rules.example.test",
            "https://rules.example.test/?token=x",
            "https://rules.example.test/#x",
            " https://rules.example.test",
        ] {
            assert!(!is_valid_fill_assist_url(value));
        }
    }
}
