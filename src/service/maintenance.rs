//! Coordinate scheduled maintenance across application features.

use jiff::{SignedDuration, Timestamp};
use worker::{D1Database, Env};

use super::{send, storage_cleanup, vault::domains};
use crate::{
    errors::{AppResult, ConfigError},
    infra::{config::trash_retention_days, db},
    models::{
        identity::{auth_request::AuthRequestRow, email, webauthn::WebauthnChallengeRow},
        vault::{attachment::AttachmentRow, cipher::CipherRow},
    },
};

/// Run routine maintenance and continue after individual task failures.
pub(crate) async fn run_maintenance(env: &Env) {
    let db = match db::binding(env) {
        Ok(db) => db,
        Err(error) => {
            log::error!("Scheduled maintenance database unavailable: {error}");
            return;
        }
    };
    log_purge_result(
        "stale pending attachments",
        purge_stale_pending_attachments(env, &db).await,
    );
    log_purge_result(
        "soft-deleted ciphers",
        purge_deleted_ciphers(env, &db).await,
    );
    log_purge_result("expired sends", send::purge_expired_sends(env, &db).await);
    log_purge_result(
        "expired auth requests",
        AuthRequestRow::purge_expired(&db).await,
    );
    if let Err(error) = storage_cleanup::expire_stages(&db).await {
        log::error!("Staged file expiry failed: {error}");
    }
    if let Err(error) = storage_cleanup::process_batch(env, &db).await {
        log::error!("Deferred file cleanup failed: {error}");
    }
    if let Err(error) = domains::refresh_global_domains(&db).await {
        log::warn!("Global domains refresh failed; keeping cache: {error}");
    }
    if let Err(error) = email::purge(&db, crate::utils::time::now_seconds()).await {
        log::error!("Verification cleanup failed: {error}");
    }
    if let Err(error) = WebauthnChallengeRow::purge(&db).await {
        log::error!("WebAuthn cleanup failed: {error}");
    }
}

fn log_purge_result(name: &str, result: AppResult<u32>) {
    match result {
        Ok(count) => log::info!("Purge {name} removed {count} record(s)"),
        Err(err) => log::error!("Purge {name} failed: {err}"),
    }
}

/// Default number of days to keep soft-deleted items before purging
/// Retain pending attachments for at most this many days before cleanup
const PENDING_RETENTION_DAYS: i64 = 1;

/// Get the purge threshold days from environment variable or use default
fn retention_cutoff(now: Timestamp, days: i64) -> Option<String> {
    days.checked_mul(86_400)
        .and_then(|seconds| now.checked_sub(SignedDuration::from_secs(seconds)).ok())
        .map(crate::utils::time::format_millis)
}

/// Purge pending attachments older than the retention window.
async fn purge_stale_pending_attachments(env: &Env, db: &D1Database) -> AppResult<u32> {
    let now = crate::utils::time::now();
    let pending_cutoff_str = retention_cutoff(now, PENDING_RETENTION_DAYS)
        .ok_or_else(|| ConfigError::Invalid("Invalid pending retention".into()))?;

    let pending_count = AttachmentRow::purge_pending_before(db, &pending_cutoff_str).await?;

    if let Err(error) = storage_cleanup::process_batch(env, db).await {
        log::warn!("Pending attachment object cleanup deferred: {error}");
    }

    Ok(pending_count)
}

/// Purge expired trash and advance the affected users' sync revisions.
async fn purge_deleted_ciphers(env: &Env, db: &D1Database) -> AppResult<u32> {
    let retention_days = trash_retention_days(env);

    if retention_days <= 0 {
        return Ok(0);
    }

    let now = crate::utils::time::now();
    let cutoff_str = retention_cutoff(now, retention_days).ok_or_else(|| {
        ConfigError::Invalid("TRASH_AUTO_DELETE_DAYS exceeds the supported date range".into())
    })?;
    let now_str = crate::utils::time::format_millis(now);

    let count = CipherRow::delete_ciphers_before(db, &cutoff_str, &now_str).await?;

    if count > 0
        && let Err(error) = storage_cleanup::process_batch(env, db).await
    {
        log::warn!("Purged cipher object cleanup deferred: {error}");
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::retention_cutoff;

    #[test]
    fn excessive_retention_returns_none_without_panicking() {
        let now = crate::utils::time::parse("2026-11-13T03:00:00Z").expect("valid timestamp");
        assert_eq!(retention_cutoff(now, i64::MAX), None);
        assert_eq!(retention_cutoff(now, i64::MIN), None);
    }
    #[test]
    fn cutoff_normalizes_offsets_without_changing_the_instant() {
        for raw in [
            "2026-11-13T11:00:00.123+08:00",
            "2026-11-12T22:00:00.123-05:00",
        ] {
            let now = crate::utils::time::parse(raw).expect("valid maintenance fixture");
            assert_eq!(
                retention_cutoff(now, 30).as_deref(),
                Some("2026-10-14T03:00:00.123Z")
            );
        }
    }

    #[test]
    fn timestamp_range_overflow_returns_none() {
        assert_eq!(retention_cutoff(Timestamp::MIN, 1), None);
        assert_eq!(retention_cutoff(Timestamp::MAX, -1), None);
    }
}
