//! Equivalent-domain request data and shared upstream cache refresh.
use std::collections::HashSet;

use futures_util::StreamExt;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use worker::{AbortSignal, D1Database, Env, Fetch, Method, Request};

use crate::{
    errors::{AppError, AppResult},
    models::vault::domains::DomainsRow,
    service::{
        identity::session::Claims,
        notifications::{UpdateType, admin::Event},
        vault_write::VaultWrite,
    },
};

const GLOBAL_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/dani-garcia/vaultwarden/main/src/static/global_domains.json";
const REFRESH_INTERVAL_SECONDS: i64 = 24 * 60 * 60;
const RETRY_INTERVAL_SECONDS: i64 = 60 * 60;
const MAX_GLOBAL_DOMAINS_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
struct GlobalDomain {
    #[serde(rename = "type")]
    type_id: i32,
    domains: Vec<String>,
}

fn validated_global_domains(raw: &str) -> AppResult<String> {
    let groups: Vec<GlobalDomain> = serde_json::from_str(raw).map_err(AppError::upstream_error)?;
    if groups.is_empty() {
        return Err(AppError::upstream_error("Global domains dataset is empty"));
    }
    let mut types = HashSet::with_capacity(groups.len());
    for group in &groups {
        if group.type_id < 0 || !types.insert(group.type_id) {
            return Err(AppError::upstream_error(
                "Invalid or duplicate global domain type",
            ));
        }
        if group.domains.is_empty() || group.domains.iter().any(|domain| domain.trim().is_empty()) {
            return Err(AppError::upstream_error(
                "Global domain group contains no usable domains",
            ));
        }
    }
    serde_json::to_string(&groups).map_err(AppError::upstream_error)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDomainsRequest {
    pub excluded_global_equivalent_domains: Option<Vec<i32>>,
    pub equivalent_domains: Option<Vec<Vec<String>>>,
}

/// Refresh the shared cache at most daily. Claiming the attempt first also
/// backs off failures and prevents concurrent sync requests from fetching.
pub(crate) async fn refresh_global_domains(db: &D1Database) -> AppResult<()> {
    let now = crate::utils::time::now_seconds();
    if !DomainsRow::claim_global_domains_refresh(db, now, now + RETRY_INTERVAL_SECONDS).await? {
        return Ok(());
    }

    let request = Request::new(GLOBAL_DOMAINS_URL, Method::Get)?;
    let signal = AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(5_000));
    let mut response = Fetch::Request(request).send_with_signal(&signal).await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::upstream_error(format_args!(
            "Global domains upstream returned HTTP {}",
            response.status_code()
        )));
    }
    let raw = read_bounded_upstream_text(&mut response, MAX_GLOBAL_DOMAINS_BYTES).await?;
    let groups = validated_global_domains(&raw)?;
    DomainsRow::replace_global_domains(
        db,
        &groups,
        crate::utils::time::now_seconds() + REFRESH_INTERVAL_SECONDS,
    )
    .await?;
    Ok(())
}

async fn read_bounded_upstream_text(
    response: &mut worker::Response,
    max_bytes: usize,
) -> AppResult<String> {
    if response
        .headers()
        .get("content-length")?
        .and_then(|value| value.trim().parse::<usize>().ok())
        .is_some_and(|length| length > max_bytes)
    {
        return Err(AppError::upstream_error(
            "Global domains upstream response exceeds size limit",
        ));
    }
    let mut stream = response.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > max_bytes - bytes.len() {
            return Err(AppError::upstream_error(
                "Global domains upstream response exceeds size limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(AppError::upstream_error)
}

async fn global_equivalent_domains_json(
    db: &D1Database,
    excluded_globals_json: &str,
    include_excluded: bool,
) -> String {
    if let Err(error) = refresh_global_domains(db).await {
        warn!("Global domains refresh failed; using cached data: {error}");
    }
    let result = match DomainsRow::query_global_equivalent_domains(
        db,
        excluded_globals_json,
        include_excluded,
    )
    .await
    {
        Err(error) if excluded_globals_json != "[]" => {
            warn!(
                "Global domain query failed; retrying without exclusions: \
                 {error}"
            );
            DomainsRow::query_global_equivalent_domains(db, "[]", include_excluded).await
        }
        result => result,
    };
    match result {
        Ok(row) => normalize_cached_domains(row),
        Err(error) => {
            warn!("Global domain query failed; using an empty list: {error}");
            "[]".to_string()
        }
    }
}

fn normalize_cached_domains(row: Option<serde_json::Value>) -> String {
    row.and_then(|row| {
        row.get("globals")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    })
    .unwrap_or_else(|| "[]".to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DomainsResponse {
    equivalent_domains: Vec<Vec<String>>,
    global_equivalent_domains: Box<RawValue>,
    object: &'static str,
}

pub(crate) async fn settings(db: &D1Database, user_id: &str) -> AppResult<DomainsResponse> {
    let domains = DomainsRow::fetch_by_user_id(db, user_id).await?;
    Ok(render_settings(
        db,
        &domains.equivalent_domains,
        &domains.excluded_globals,
        true,
    )
    .await)
}

pub(crate) async fn render_settings(
    db: &D1Database,
    equivalent_domains: &str,
    excluded_globals: &str,
    include_excluded: bool,
) -> DomainsResponse {
    let equivalent_domains = serde_json::from_str(equivalent_domains).unwrap_or_else(|_error| {
        warn!("Invalid stored equivalent domains; using an empty list");
        Vec::new()
    });
    let raw_globals = global_equivalent_domains_json(db, excluded_globals, include_excluded).await;
    let global_equivalent_domains = RawValue::from_string(raw_globals).unwrap_or_else(|_error| {
        warn!("Invalid cached global domains; using an empty list");
        empty_domains()
    });
    DomainsResponse {
        equivalent_domains,
        global_equivalent_domains,
        object: "domains",
    }
}

fn empty_domains() -> Box<RawValue> {
    serde_json::value::to_raw_value(&[(); 0]).expect("empty array serializes")
}

pub async fn update_settings(
    db: &D1Database,
    env: &Env,
    claims: &Claims,
    payload: UpdateDomainsRequest,
) -> AppResult<()> {
    let mut mutation = VaultWrite::new(db, env, claims);
    let previous = DomainsRow::fetch_by_user_id(db, mutation.user_id()).await?;
    mutation.guard_account_key().await?;
    mutation.add_guard(previous.snapshot_guard(db, mutation.user_id())?);

    let excluded_globals = payload
        .excluded_global_equivalent_domains
        .unwrap_or_default();
    let equivalent_domains = payload.equivalent_domains.unwrap_or_default();

    let excluded_globals_json = serde_json::to_string(&excluded_globals).map_err(|err| {
        log::warn!("Failed to serialize excluded globals: {err}");
        AppError::Params("Invalid excluded globals".into())
    })?;
    let equivalent_domains_json = serde_json::to_string(&equivalent_domains).map_err(|err| {
        log::warn!("Failed to serialize equivalent domains: {err}");
        AppError::Params("Invalid equivalent domains".into())
    })?;

    let write = DomainsRow::update_for_user(
        db,
        mutation.user_id(),
        &equivalent_domains_json,
        &excluded_globals_json,
    )?;
    let committed = mutation.commit(vec![write]).await?;
    committed.publish_user(UpdateType::SyncSettings).await;
    committed.emit_admin(Event::AccountSettingsChanged).await;
    Ok(())
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
