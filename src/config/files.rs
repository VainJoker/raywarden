//! Settings read when issuing file capabilities or enforcing upload limits.
use worker::Env;

use crate::errors::{
    AppError,
    AppResult,
    ConfigError,
};

const DEFAULT_ATTACHMENT_TOKEN_TTL_SECONDS: i64 = 60;
const DEFAULT_SEND_FILE_TOKEN_TTL_SECONDS: i64 = 300;
pub(crate) const DEFAULT_SEND_MAX_BYTES: i64 = 95 * 1024 * 1024;

pub(crate) fn attachment_token_ttl_seconds(env: &Env) -> AppResult<i64> {
    match env.var("ATTACHMENT_TTL_SECS") {
        Ok(value) => {
            let raw = value.to_string();
            let ttl = raw.parse::<i64>().map_err(|error| {
                AppError::internal_with_context(
                    "api",
                    &format!("Invalid ATTACHMENT_TTL_SECS '{raw}'"),
                    error,
                )
            })?;

            if ttl <= 0 {
                log::error!("ATTACHMENT_TTL_SECS '{raw}' must be positive");
                return Err(AppError::Internal);
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
                AppError::internal_with_context(
                    "api",
                    &format!("Invalid ATTACHMENT_MAX_BYTES '{raw}'"),
                    error,
                )
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
                AppError::internal_with_context(
                    "api",
                    &format!("Invalid ATTACHMENT_TOTAL_LIMIT_KB '{raw}'"),
                    error,
                )
            })?;

            let bytes = kb.checked_mul(1024).ok_or_else(|| {
                log::error!(
                    "ATTACHMENT_TOTAL_LIMIT_KB '{raw}' overflowed when \
                     converting to bytes"
                );
                AppError::Internal
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

pub(crate) fn send_quota_bytes(env: &Env) -> Option<i64> {
    env.var("USER_SEND_LIMIT_KB")
        .ok()
        .and_then(|value| value.to_string().parse::<i64>().ok())
        .filter(|kb| *kb >= 0)
        .and_then(|kb| kb.checked_mul(1024))
}

pub(crate) fn send_file_token_expires_at_seconds(
    env: &Env,
    now_seconds: i64,
) -> AppResult<i64> {
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
        .filter(|expires_at_seconds| {
            jiff::Timestamp::from_second(*expires_at_seconds).is_ok()
        });
    expires_at_seconds.ok_or_else(|| {
        ConfigError::Invalid(
            "SEND_TTL_SECS must be positive and fit a supported expiration \
             timestamp"
                .into(),
        )
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_lifetimes_keep_reference_defaults_and_reject_invalid_dates() {
        for value in [None, Some("invalid"), Some("18446744073709551616")] {
            assert_eq!(
                parse_send_file_token_expires_at_seconds(value, 1_000)
                    .expect("valid test fixture"),
                1_300
            );
        }
        assert_eq!(
            parse_send_file_token_expires_at_seconds(Some("17"), 1_000)
                .expect("valid test fixture"),
            1_017
        );
        for value in ["0", "-1", "9223372036854775807", "253402300799"] {
            assert!(
                parse_send_file_token_expires_at_seconds(Some(value), 1_000)
                    .is_err()
            );
        }
        assert!(
            parse_send_file_token_expires_at_seconds(Some("1"), i64::MAX)
                .is_err()
        );
    }
}
