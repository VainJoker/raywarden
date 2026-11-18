use std::collections::HashSet;

use log::warn;
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use worker::{
    AbortSignal,
    D1Database,
    Fetch,
    Method,
    Request,
    query,
};

use crate::{
    errors::{
        AppError,
        AuthError,
        DatabaseError,
    },
    infra::db,
};

const GLOBAL_DOMAINS_URL: &str = "https://raw.githubusercontent.com/dani-garcia/vaultwarden/main/src/static/global_domains.json";
const REFRESH_INTERVAL_SECONDS: i64 = 24 * 60 * 60;
const RETRY_INTERVAL_SECONDS: i64 = 60 * 60;

#[derive(Debug, Deserialize, Serialize)]
struct GlobalDomain {
    #[serde(rename = "type")]
    type_id: i32,
    domains: Vec<String>,
}

fn validated_global_domains(raw: &str) -> Result<String, String> {
    let groups: Vec<GlobalDomain> =
        serde_json::from_str(raw).map_err(|error| error.to_string())?;
    if groups.is_empty() {
        return Err("Global domains dataset is empty".to_string());
    }
    let mut types = HashSet::with_capacity(groups.len());
    for group in &groups {
        if group.type_id < 0 || !types.insert(group.type_id) {
            return Err("Invalid or duplicate global domain type".to_string());
        }
        if group.domains.is_empty() ||
            group.domains.iter().any(|domain| domain.trim().is_empty())
        {
            return Err(
                "Global domain group contains no usable domains".to_string()
            );
        }
    }
    serde_json::to_string(&groups).map_err(|error| error.to_string())
}

#[derive(Debug)]
pub struct DomainsDB {
    pub equivalent_domains: String,
    pub excluded_globals:   String,
}

impl DomainsDB {
    pub async fn fetch_by_user_id(
        db: &D1Database,
        user_id: &str,
    ) -> Result<Self, AppError> {
        let row: Option<Value> = db
            .prepare(
                "SELECT equivalent_domains, excluded_globals FROM users WHERE \
                 id = ?1",
            )
            .bind(&[user_id.into()])
            .map_err(|e| {
                warn!("query user domains failed: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to query user domains".to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| {
                warn!("query user domains failed: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to query user domains".to_string(),
                ))
            })?;

        let row = row.ok_or_else(|| AppError::Auth(AuthError::UserNotFound))?;

        let equivalent_domains = row
            .get("equivalent_domains")
            .and_then(|v| v.as_str())
            .unwrap_or("[]")
            .to_string();
        let excluded_globals = row
            .get("excluded_globals")
            .and_then(|v| v.as_str())
            .unwrap_or("[]")
            .to_string();

        Ok(Self {
            equivalent_domains,
            excluded_globals,
        })
    }

    pub async fn update_for_user(
        db: &D1Database,
        user_id: &str,
        equivalent_domains_json: &str,
        excluded_globals_json: &str,
        updated_at: &str,
    ) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "UPDATE users SET equivalent_domains = ?1, \
                     excluded_globals = ?2, updated_at = ?3 WHERE id = ?4",
                    equivalent_domains_json,
                    excluded_globals_json,
                    updated_at,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update domains",
        )
        .await
    }

    /// Refresh the shared cache at most daily. Claiming the attempt first also
    /// backs off failures and prevents concurrent sync requests from fetching.
    pub(crate) async fn refresh_global_domains(
        db: &D1Database,
    ) -> worker::Result<()> {
        let now = crate::infra::time::now_seconds();
        if !Self::claim_global_domains_refresh(db, now).await? {
            return Ok(());
        }

        let request = Request::new(GLOBAL_DOMAINS_URL, Method::Get)?;
        let signal =
            AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(5_000));
        let mut response =
            Fetch::Request(request).send_with_signal(&signal).await?;
        if !(200..300).contains(&response.status_code()) {
            return Err(worker::Error::RustError(format!(
                "Global domains upstream returned HTTP {}",
                response.status_code()
            )));
        }
        let groups = validated_global_domains(&response.text().await?)
            .map_err(worker::Error::RustError)?;
        Self::replace_global_domains(
            db,
            &groups,
            crate::infra::time::now_seconds(),
        )
        .await
    }

    async fn claim_global_domains_refresh(
        db: &D1Database,
        now: i64,
    ) -> worker::Result<bool> {
        let claimed: Option<Value> = query!(
            db,
            "INSERT INTO global_domains_cache (id, next_refresh_at) VALUES \
             (1, ?1) ON CONFLICT(id) DO UPDATE SET next_refresh_at = \
             excluded.next_refresh_at WHERE \
             global_domains_cache.next_refresh_at <= ?2 RETURNING id",
            now + RETRY_INTERVAL_SECONDS,
            now
        )?
        .first(None)
        .await?;
        Ok(claimed.is_some())
    }

    async fn replace_global_domains(
        db: &D1Database,
        groups_json: &str,
        now: i64,
    ) -> worker::Result<()> {
        // D1 batches are transactional: any failed statement keeps the old
        // dataset and the one-hour retry deadline established by the claim.
        db.batch(vec![
            db.prepare("DELETE FROM global_equivalent_domains"),
            query!(
                db,
                "INSERT INTO global_equivalent_domains (type, sort_order, \
                 domains_json) SELECT json_extract(value, '$.type'), CAST(key \
                 AS INTEGER), json_extract(value, '$.domains') FROM \
                 json_each(?1)",
                groups_json
            )?,
            query!(
                db,
                "UPDATE global_domains_cache SET next_refresh_at = ?1 WHERE \
                 id = 1",
                now + REFRESH_INTERVAL_SECONDS
            )?,
        ])
        .await?;
        Ok(())
    }
}

async fn run_once(
    db: &D1Database,
    sql: &str,
    excluded: &str,
) -> Result<String, ()> {
    let row: Option<Value> = db
        .prepare(sql)
        .bind(&[excluded.to_string().into()])
        .map_err(|err| {
            warn!("Failed to prepare globalEquivalentDomains query: {err}");
        })?
        .first(None)
        .await
        .map_err(|err| {
            warn!("Failed to execute globalEquivalentDomains query: {err}");
        })?;

    Ok(row
        .and_then(|r| {
            r.get("globals")
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string)
        })
        .unwrap_or_else(|| "[]".to_string()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivDomainData {
    pub excluded_global_equivalent_domains: Option<Vec<i32>>,
    pub equivalent_domains:                 Option<Vec<Vec<String>>>,
}

impl EquivDomainData {
    /// Build `globalEquivalentDomains` JSON (as a raw JSON string) in
    /// SQLite/D1.
    ///
    /// - `include_excluded=true`  => returns all groups, each with `excluded`
    ///   boolean (settings UI).
    /// - `include_excluded=false` => returns only non-excluded groups, with
    ///   `excluded=false` (sync payload).
    ///
    /// Cached rows are assembled in SQL; upstream JSON is parsed only when a
    /// refresh is due. Refresh failures leave cached and custom domains usable.
    pub(crate) async fn global_equivalent_domains_json(
        db: &worker::D1Database,
        excluded_globals_json: &str,
        include_excluded: bool,
    ) -> String {
        if let Err(error) = DomainsDB::refresh_global_domains(db).await {
            warn!("Global domains refresh failed; using cached data: {error}");
        }
        let sql = if include_excluded {
            "
SELECT COALESCE(
  (SELECT json_group_array(json(value))
   FROM (
     SELECT json_object(
              'type', g.type,
              'domains', json(g.domains_json),
              'excluded', CASE WHEN eg.value IS NULL THEN json('false') ELSE \
             json('true') END
            ) AS value
     FROM global_equivalent_domains g
     LEFT JOIN json_each(?1) eg ON eg.value = g.type
     ORDER BY g.sort_order
   )),
  '[]'
) AS globals
"
        } else {
            "
SELECT COALESCE(
  (SELECT json_group_array(json(value))
   FROM (
     SELECT json_object(
              'type', g.type,
              'domains', json(g.domains_json),
              'excluded', json('false')
            ) AS value
     FROM global_equivalent_domains g
     LEFT JOIN json_each(?1) eg ON eg.value = g.type
     WHERE eg.value IS NULL
     ORDER BY g.sort_order
   )),
  '[]'
) AS globals
"
        };

        // If excluded_globals is invalid JSON, json_each() can fail.
        // Fallback to treating it as empty list.
        match run_once(db, sql, excluded_globals_json).await {
            Ok(s) => s,
            Err(()) => {
                if excluded_globals_json == "[]" {
                    warn!(
                        "Failed to build globalEquivalentDomains JSON \
                         (falling back to [])"
                    );
                    "[]".to_string()
                } else if let Ok(s) = run_once(db, sql, "[]").await {
                    s
                } else {
                    warn!(
                        "Failed to build globalEquivalentDomains JSON \
                         (falling back to [])"
                    );
                    "[]".to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validated_global_domains;

    #[test]
    fn global_domains_validation_preserves_order_and_domains() {
        let validated = validated_global_domains(
            r#"[{"type":2,"domains":["example.test","example.org"],"excluded":false},{"type":1,"domains":["other.test"]}]"#,
        )
        .expect("valid upstream array");
        assert_eq!(
            validated,
            r#"[{"type":2,"domains":["example.test","example.org"]},{"type":1,"domains":["other.test"]}]"#
        );
    }

    #[test]
    fn global_domains_validation_rejects_entire_bad_dataset() {
        for raw in [
            "",
            "[]",
            "{}",
            r#"[{"type":1,"domains":["valid.test"]},null]"#,
            r#"[{"type":1,"domains":["valid.test"]},{"type":2}]"#,
            r#"[{"type":1,"domains":["valid.test"]},{"type":1,"domains":["duplicate.test"]}]"#,
            r#"[{"type":-1,"domains":["example.test"]}]"#,
            r#"[{"type":2147483648,"domains":["example.test"]}]"#,
            r#"[{"type":true,"domains":["example.test"]}]"#,
            r#"[{"type":1,"domains":[]}]"#,
            r#"[{"type":1,"domains":["  "]}]"#,
            r#"[{"type":1,"domains":["example.test",42]}]"#,
        ] {
            assert!(validated_global_domains(raw).is_err(), "accepted {raw}");
        }
    }
}
