//! Persisted signing keys and guarded D1 reads and writes.
use serde::Deserialize;
use worker::D1Database;

use crate::{
    errors::{AppResult, worker_failure},
    infra::db,
};

#[derive(Deserialize)]
pub struct JwtKeysRow {
    pub access_secret: String,
    pub refresh_secret: String,
}

fn require_write_success(result: &worker::D1Result) -> worker::Result<()> {
    if result.success() {
        Ok(())
    } else {
        Err(worker_failure("JWT key persistence failed"))
    }
}

pub async fn find(db: &D1Database) -> AppResult<Option<JwtKeysRow>> {
    db::query_first::<JwtKeysRow>(
        Ok(db.prepare(
            "SELECT access_secret, refresh_secret FROM jwt_keys WHERE \
                     id = 'global'",
        )),
        None,
        "Failed to read JWT keys",
    )
    .await
}

pub async fn initialize_if_empty(db: &D1Database, keys: JwtKeysRow) -> AppResult<()> {
    db::run_query(
        async {
            db.prepare(
                "INSERT OR IGNORE INTO jwt_keys (id, access_secret, \
                     refresh_secret) SELECT 'global', ?1, ?2 WHERE NOT EXISTS \
                     (SELECT 1 FROM users) AND NOT EXISTS (SELECT 1 FROM \
                     user_api_keys)",
            )
            .bind(&db::d1_params![keys.access_secret, keys.refresh_secret])?
            .run()
            .await
            .and_then(|result| require_write_success(&result))
        },
        "Failed to initialize JWT keys",
    )
    .await
}
