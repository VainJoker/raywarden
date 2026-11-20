use serde_json::Value;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
};

use crate::errors::{
    AppResult,
    AuthError,
    DatabaseError,
};

#[derive(Debug)]
pub struct DomainsRow {
    pub equivalent_domains: String,
    pub excluded_globals:   String,
}

impl DomainsRow {
    pub fn snapshot_guard(
        &self,
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<D1PreparedStatement> {
        crate::models::mutation::guard(
            db,
            "EXISTS(SELECT 1 FROM users WHERE id=?1 AND equivalent_domains=?2 \
             AND excluded_globals=?3)",
            &[
                user_id.into(),
                self.equivalent_domains.clone().into(),
                self.excluded_globals.clone().into(),
            ],
        )
    }

    pub async fn fetch_by_user_id(
        db: &D1Database,
        user_id: &str,
    ) -> AppResult<Self> {
        let row: Option<Value> = db
            .prepare(
                "SELECT equivalent_domains, excluded_globals FROM users WHERE \
                 id = ?1",
            )
            .bind(&[user_id.into()])
            .map_err(|e| DatabaseError::query("query user domains failed", e))?
            .first(None)
            .await
            .map_err(|e| {
                DatabaseError::query("query user domains failed", e)
            })?;

        let row = row.ok_or(AuthError::UserNotFound)?;

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

    pub fn update_for_user(
        db: &D1Database,
        user_id: &str,
        equivalent_domains_json: &str,
        excluded_globals_json: &str,
    ) -> AppResult<D1PreparedStatement> {
        Ok(query!(
            db,
            "UPDATE users SET equivalent_domains = ?1, excluded_globals = ?2 \
             WHERE id = ?3",
            equivalent_domains_json,
            excluded_globals_json,
            user_id
        )?)
    }

    pub(crate) async fn claim_global_domains_refresh(
        db: &D1Database,
        now: i64,
        retry_at: i64,
    ) -> worker::Result<bool> {
        let claimed: Option<Value> = query!(
            db,
            "INSERT INTO global_domains_cache (id, next_refresh_at) VALUES \
             (1, ?1) ON CONFLICT(id) DO UPDATE SET next_refresh_at = \
             excluded.next_refresh_at WHERE \
             global_domains_cache.next_refresh_at <= ?2 RETURNING id",
            retry_at,
            now
        )?
        .first(None)
        .await?;
        Ok(claimed.is_some())
    }

    pub(crate) async fn replace_global_domains(
        db: &D1Database,
        groups_json: &str,
        refresh_at: i64,
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
                refresh_at
            )?,
        ])
        .await?;
        Ok(())
    }

    /// Build `globalEquivalentDomains` JSON (as a raw JSON string) in
    /// SQLite/D1.
    ///
    /// - `include_excluded=true`  => returns all groups, each with `excluded`
    ///   boolean (settings UI).
    /// - `include_excluded=false` => returns only non-excluded groups, with
    ///   `excluded=false` (sync payload).
    ///
    /// Return the raw query row; retry and response defaults belong to service.
    pub(crate) async fn query_global_equivalent_domains(
        db: &worker::D1Database,
        excluded_globals_json: &str,
        include_excluded: bool,
    ) -> AppResult<Option<Value>> {
        let sql = "
SELECT COALESCE(json_group_array(json(value)), '[]') AS globals
FROM (
  SELECT json_object(
           'type', type,
           'domains', json(domains_json),
           'excluded', json(CASE WHEN excluded THEN 'true' ELSE 'false' END)
         ) AS value
  FROM (
    SELECT g.type, g.domains_json, g.sort_order,
           EXISTS(SELECT 1 FROM json_each(?1) eg WHERE eg.value = g.type) AS \
                   excluded
    FROM global_equivalent_domains g
  )
  WHERE ?2 OR NOT excluded
  ORDER BY sort_order
)";

        db.prepare(sql)
            .bind(&[
                excluded_globals_json.into(),
                i32::from(include_excluded).into(),
            ])
            .map_err(|err| {
                DatabaseError::query(
                    "Failed to prepare globalEquivalentDomains query",
                    err,
                )
            })?
            .first(None)
            .await
            .map_err(|err| {
                DatabaseError::query(
                    "Failed to execute globalEquivalentDomains query",
                    err,
                )
            })
    }
}
