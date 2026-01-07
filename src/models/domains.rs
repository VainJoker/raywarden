use log::warn;
use serde::Deserialize;
use serde_json::Value;

async fn run_once(
    db: &worker::D1Database,
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
