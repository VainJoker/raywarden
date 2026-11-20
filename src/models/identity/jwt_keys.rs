//! Persisted signing keys and guarded D1 reads and writes.
use serde::Deserialize;
use worker::D1Database;

use crate::{
    errors::{
        AppResult,
        worker_failure,
    },
    infra::db,
};

#[derive(Deserialize)]
pub struct JwtKeysRow {
    pub access_secret:  String,
    pub refresh_secret: String,
}

pub struct JwtKeysStore;

fn require_write_success(result: &worker::D1Result) -> worker::Result<()> {
    if result.success() {
        Ok(())
    } else {
        Err(worker_failure("JWT key persistence failed"))
    }
}

impl JwtKeysStore {
    pub async fn find(db: &D1Database) -> AppResult<Option<JwtKeysRow>> {
        db::run_query(
            async {
                db.prepare(
                    "SELECT access_secret, refresh_secret FROM jwt_keys WHERE \
                     id = 'global'",
                )
                .first::<JwtKeysRow>(None)
                .await
            },
            "Failed to read JWT keys",
        )
        .await
    }

    pub async fn wrap_if_current(
        db: &D1Database,
        previous: JwtKeysRow,
        wrapped: JwtKeysRow,
    ) -> AppResult<()> {
        db::run_query(
            async {
                // Both fields move together. A concurrent wrapper can win,
                // but never overwrite a changed key pair with this snapshot.
                db.prepare(
                    "UPDATE jwt_keys SET access_secret = ?1, refresh_secret = \
                     ?2 WHERE id = 'global' AND access_secret = ?3 AND \
                     refresh_secret = ?4",
                )
                .bind(&[
                    wrapped.access_secret.into(),
                    wrapped.refresh_secret.into(),
                    previous.access_secret.into(),
                    previous.refresh_secret.into(),
                ])?
                .run()
                .await
                .and_then(|result| require_write_success(&result))
            },
            "Failed to wrap legacy JWT keys",
        )
        .await
    }

    pub async fn initialize_if_allowed(
        db: &D1Database,
        keys: JwtKeysRow,
        importing_legacy: bool,
    ) -> AppResult<()> {
        db::run_query(
            async {
                db.prepare(
                    "INSERT OR IGNORE INTO jwt_keys (id, access_secret, \
                     refresh_secret) SELECT 'global', ?1, ?2 WHERE ?3 = 1 OR \
                     (NOT EXISTS (SELECT 1 FROM users) AND NOT EXISTS (SELECT \
                     1 FROM user_api_keys))",
                )
                .bind(&[
                    keys.access_secret.into(),
                    keys.refresh_secret.into(),
                    i32::from(importing_legacy).into(),
                ])?
                .run()
                .await
                .and_then(|result| require_write_success(&result))
            },
            "Failed to initialize JWT keys",
        )
        .await
    }
}
