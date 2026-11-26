use serde::{Deserialize, Serialize};
use worker::D1Database;

use crate::{
    errors::{AppError, AppResult},
    infra::db,
};

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ConnectionCheck<'a> {
    User {
        user_id: &'a str,
        device_id: &'a str,
        stamp: &'a str,
        nonce: &'a str,
    },
    Anonymous {
        request_id: &'a str,
        ip: &'a str,
    },
}

#[derive(Deserialize)]
struct ValidConnection {
    position: usize,
}

pub(crate) async fn validate_connections(
    db: &D1Database,
    checks: &[Option<ConnectionCheck<'_>>],
    now: &str,
) -> AppResult<Vec<bool>> {
    const CHECKS_PER_QUERY: usize = 32;
    let mut statements = Vec::new();
    let mut offsets = Vec::new();
    for (group, checks) in checks.chunks(CHECKS_PER_QUERY).enumerate() {
        if checks.iter().all(Option::is_none) {
            continue;
        }
        let input = serde_json::to_string(checks).map_err(AppError::internal_json(
            "Failed to serialize notification session checks",
        ))?;
        statements.push(db.prepare(
            "SELECT entry.key AS position FROM json_each(?1) entry \
             WHERE CASE json_extract(entry.value, '$.kind') \
             WHEN 'user' THEN EXISTS (SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id \
                WHERE d.user_id=json_extract(entry.value, '$.user_id') \
                  AND d.device_id=json_extract(entry.value, '$.device_id') \
                  AND d.session_token=json_extract(entry.value, '$.nonce') \
                  AND u.security_stamp=json_extract(entry.value, '$.stamp')) \
             WHEN 'anonymous' THEN EXISTS (SELECT 1 FROM auth_requests a JOIN users u ON u.id=a.user_id \
                WHERE a.id=json_extract(entry.value, '$.request_id') \
                  AND a.request_ip=json_extract(entry.value, '$.ip') \
                  AND a.authenticated_at IS NULL AND julianday(a.expires_at)>julianday(?2) \
                  AND u.security_stamp=a.security_stamp) ELSE 0 END",
        ).bind(&db::d1_params![input, now])?);
        offsets.push(group * CHECKS_PER_QUERY);
    }

    let mut valid = vec![false; checks.len()];
    if !statements.is_empty() {
        let results = db::run_batch(
            db,
            statements,
            "Failed to validate notification connections",
        )
        .await?;
        if results.len() != offsets.len() {
            return Err(AppError::internal(
                "Notification validation batch returned an unexpected result count",
            ));
        }
        for (offset, result) in offsets.into_iter().zip(results) {
            for row in db::decode_results::<ValidConnection>(&result)? {
                let slot = valid
                    .get_mut(offset + row.position)
                    .ok_or_else(|| AppError::internal("Notification check index out of bounds"))?;
                *slot = true;
            }
        }
    }
    Ok(valid)
}
