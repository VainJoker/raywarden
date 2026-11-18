//! Purge handler for cleaning up soft-deleted ciphers
//!
//! This module handles the automatic cleanup of ciphers that have been
//! soft-deleted (marked with `deleted_at`) for longer than the configured
//! retention period.

use jiff::{
    SignedDuration,
    Timestamp,
};
use worker::{
    D1Database,
    Env,
};

use crate::models::{
    attachment::AttachmentDB,
    cipher::CipherDB,
    purge::PurgeDB,
};

/// Default number of days to keep soft-deleted items before purging
const DEFAULT_PURGE_DAYS: i64 = 30;
/// Retain pending attachments for at most this many days before cleanup
const PENDING_RETENTION_DAYS: i64 = 1;

/// Get the purge threshold days from environment variable or use default
fn get_purge_days(env: &Env) -> i64 {
    env.var("TRASH_AUTO_DELETE_DAYS")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_PURGE_DAYS)
}

fn purge_cutoff(now: Timestamp, days: i64) -> Option<String> {
    days.checked_mul(86_400)
        .and_then(|seconds| {
            now.checked_sub(SignedDuration::from_secs(seconds)).ok()
        })
        .map(crate::infra::time::format_millis)
}

/// Run independent cleanup jobs even if one of them fails.
pub async fn run_scheduled(env: &Env) {
    log_purge_result(
        "stale pending attachments",
        purge_stale_pending_attachments(env).await,
    );
    log_purge_result("soft-deleted ciphers", purge_deleted_ciphers(env).await);
    log_purge_result(
        "expired sends",
        crate::send::purge_expired_sends(env).await,
    );
    log_purge_result(
        "expired auth requests",
        purge_expired_auth_requests(env).await,
    );
    match env.d1("warden-db") {
        Ok(db) => {
            if let Err(error) =
                crate::infra::storage::cleanup::drain(env, &db).await
            {
                log::error!("Deferred file cleanup failed: {error}");
            }
            if let Err(error) =
                crate::models::domains::DomainsDB::refresh_global_domains(&db)
                    .await
            {
                log::warn!(
                    "Global domains refresh failed; keeping cache: {error}"
                );
            }
            if let Err(error) = crate::models::email::EmailDB::purge(
                &db,
                crate::infra::time::now_seconds(),
            )
            .await
            {
                log::error!("Verification cleanup failed: {error}");
            }
            if let Err(error) =
                crate::models::webauthn::ChallengeDB::purge(&db).await
            {
                log::error!("WebAuthn cleanup failed: {error}");
            }
        }
        Err(error) => {
            log::error!("Security cleanup database unavailable: {error}")
        }
    }
}

async fn purge_expired_auth_requests(env: &Env) -> Result<u32, worker::Error> {
    let db = env.d1("warden-db")?;
    crate::models::auth_request::AuthRequestDB::purge_expired(&db)
        .await
        .map_err(Into::into)
}

fn log_purge_result(name: &str, result: Result<u32, worker::Error>) {
    match result {
        Ok(count) => log::info!("Purge {name} removed {count} record(s)"),
        Err(err) => log::error!("Purge {name} failed: {err}"),
    }
}

/// Purge pending attachments older than the configured retention window.
pub async fn purge_stale_pending_attachments(
    env: &Env,
) -> Result<u32, worker::Error> {
    let db: D1Database = env.d1("warden-db")?;
    let now = crate::infra::time::now();
    let pending_cutoff_str = purge_cutoff(now, PENDING_RETENTION_DAYS)
        .ok_or_else(|| {
            worker::Error::RustError("Invalid pending retention".to_string())
        })?;

    let pending_count =
        AttachmentDB::purge_pending_before(&db, &pending_cutoff_str)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

    if let Err(error) = crate::infra::storage::cleanup::drain(env, &db).await {
        log::warn!("Pending attachment object cleanup deferred: {error}");
    }

    if pending_count > 0 {
        log::info!(
            "Purged {pending_count} pending attachment(s) older than \
             {PENDING_RETENTION_DAYS} day(s)"
        );
    } else {
        log::info!("No pending attachments to purge");
    }

    Ok(pending_count)
}

/// Purge soft-deleted ciphers that are older than the configured threshold.
///
/// This function:
/// 1. Calculates the cutoff timestamp based on `TRASH_AUTO_DELETE_DAYS` env var
///    (default: 30 days)
/// 2. Deletes all ciphers where `deleted_at` is not null and older than the
///    cutoff
/// 3. Updates the affected users' `updated_at` to trigger client sync
/// 4. If `TRASH_AUTO_DELETE_DAYS` is set to 0 or negative, skips purging
///    (disabled)
///
/// Returns the number of purged records on success.
pub async fn purge_deleted_ciphers(env: &Env) -> Result<u32, worker::Error> {
    let purge_days = get_purge_days(env);

    // If purge_days is 0 or negative, auto-purge is disabled
    if purge_days <= 0 {
        log::info!("Auto-purge is disabled (TRASH_AUTO_DELETE_DAYS <= 0)");
        return Ok(0);
    }

    let db: D1Database = env.d1("warden-db")?;

    // Calculate the cutoff timestamp
    let now = crate::infra::time::now();
    let cutoff_str = purge_cutoff(now, purge_days).ok_or_else(|| {
        worker::Error::RustError(
            "TRASH_AUTO_DELETE_DAYS exceeds the supported date range"
                .to_string(),
        )
    })?;
    let now_str = crate::infra::time::format_millis(now);

    log::info!(
        "Purging soft-deleted ciphers older than {purge_days} days (before \
         {cutoff_str})"
    );

    // Count the records to be deleted (for logging purposes)
    let count = CipherDB::count_soft_deleted_before(&db, &cutoff_str)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    if count > 0 {
        PurgeDB::delete_ciphers_before(&db, &cutoff_str, &now_str)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        if let Err(error) =
            crate::infra::storage::cleanup::drain(env, &db).await
        {
            log::warn!("Purged cipher object cleanup deferred: {error}");
        }

        log::info!("Successfully purged {count} soft-deleted cipher(s)");
    } else {
        log::info!("No soft-deleted ciphers to purge");
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::purge_cutoff;

    #[test]
    fn retention_cutoff_preserves_utc_and_milliseconds() {
        let now = crate::infra::time::parse("2026-11-13T03:00:00.123Z")
            .expect("valid timestamp");
        assert_eq!(
            purge_cutoff(now, 30).as_deref(),
            Some("2026-10-14T03:00:00.123Z")
        );
    }

    #[test]
    fn excessive_retention_returns_none_without_panicking() {
        let now = crate::infra::time::parse("2026-11-13T03:00:00Z")
            .expect("valid timestamp");
        assert_eq!(purge_cutoff(now, i64::MAX), None);
        assert_eq!(purge_cutoff(now, i64::MIN), None);
    }
}

#[cfg(test)]
mod timestamp_boundaries {
    use jiff::Timestamp;

    use super::purge_cutoff;

    #[test]
    fn cutoff_normalizes_offsets_without_changing_the_instant() {
        for raw in [
            "2026-11-13T11:00:00.123+08:00",
            "2026-11-12T22:00:00.123-05:00",
        ] {
            let now = crate::infra::time::parse(raw).unwrap();
            assert_eq!(
                purge_cutoff(now, 30).as_deref(),
                Some("2026-10-14T03:00:00.123Z")
            );
        }
    }

    #[test]
    fn timestamp_range_overflow_returns_none() {
        assert_eq!(purge_cutoff(Timestamp::MIN, 1), None);
        assert_eq!(purge_cutoff(Timestamp::MAX, -1), None);
    }
}
