use log::warn;
use serde::Deserialize;
use serde_json::Value;
use worker::{
    D1Database,
    query,
};

use crate::{
    errors::{
        AppError,
        AuthError,
        DatabaseError,
    },
    infra::DB,
};

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
        DB::run_query(
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
    /// This keeps the Worker from parsing the large upstream dataset.
    pub(crate) async fn global_equivalent_domains_json(
        db: &worker::D1Database,
        excluded_globals_json: &str,
        include_excluded: bool,
    ) -> String {
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
