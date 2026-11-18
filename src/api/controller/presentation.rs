use axum::{
    Json,
    body::Body,
    extract::{
        Path,
        Query,
        State,
    },
    http::{
        HeaderMap,
        HeaderValue,
        StatusCode,
        header,
    },
    response::{
        IntoResponse,
        Response,
    },
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            ui,
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    infra::config::env_bool,
    models::usage::UsageDB,
};

#[worker::send]
pub async fn icon(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> AppResult<Response> {
    if !valid_icon_domain(&domain) {
        return Err(AppError::bad_request("Invalid icon domain"));
    }
    if env_bool(&state.env, "DISABLE_ICON_DOWNLOAD", false) {
        return Err(AppError::not_found("Icon"));
    }
    let url = format!("https://vault.bitwarden.com/icons/{domain}/icon.png");
    let request = worker::Request::new(&url, worker::Method::Get)?;
    let mut upstream = worker::Fetch::Request(request).send().await?;
    let status = StatusCode::from_u16(upstream.status_code())
        .map_err(|_| AppError::Internal)?;
    let kind = upstream
        .headers()
        .get("content-type")?
        .unwrap_or_else(|| "image/png".into());
    if !kind.starts_with("image/") && status.is_success() {
        return Err(AppError::not_found("Icon"));
    }
    let bytes = upstream.bytes().await?;
    if bytes.len() > 1024 * 1024 {
        return Err(AppError::bad_request("Icon is too large"));
    }
    Ok((
        status,
        [
            (header::CONTENT_TYPE, kind.as_str()),
            (header::CACHE_CONTROL, "public, max-age=604800"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    )
        .into_response())
}

fn valid_icon_domain(domain: &str) -> bool {
    !domain.is_empty() &&
        domain.len() <= 253 &&
        domain.split('.').all(|label| {
            !label.is_empty() &&
                label.len() <= 63 &&
                !label.starts_with('-') &&
                !label.ends_with('-') &&
                label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[worker::send]
pub async fn css(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let css =
        ui::stylesheet(&state.env, state.config.disable_user_registration);
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(css.as_bytes())));
    let matched = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',').any(|v| {
                v.trim().trim_start_matches("W/") == etag || v.trim() == "*"
            })
        });
    let mut response = if matched {
        (StatusCode::NOT_MODIFIED, Body::empty()).into_response()
    } else {
        ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], css)
            .into_response()
    };
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, no-cache"),
    );
    response
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageQuery {
    user_id: Option<String>,
}

#[worker::send]
pub async fn usage(
    claims: Claims,
    State(state): State<AppState>,
    Query(query): Query<UsageQuery>,
) -> AppResult<Json<Value>> {
    if query.user_id.as_deref().is_some_and(|id| id != claims.sub) {
        return Err(AppError::Unauthorized {
            message: "Cannot inspect another account".into(),
        });
    }
    let rows = UsageDB::for_user(&state.get_db(), &claims.sub).await?;
    let mut total = 0i64;
    let mut files = 0i64;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            if row.name.ends_with("Files") {
                files += row.bytes;
            } else {
                total += row.bytes;
            }
            json!({"key": row.name, "name": row.name, "bytes": row.bytes})
        })
        .collect();
    Ok(Json(
        json!({"object":"d1-usage", "userId": claims.sub, "totalBytes":total,
        "fileBytes":files, "isEstimate":true, "items":items}),
    ))
}

#[cfg(test)]
mod tests {
    use super::valid_icon_domain;
    #[test]
    fn icons_cannot_escape_the_fixed_upstream_path() {
        assert!(valid_icon_domain("vault.example.com"));
        for bad in [
            "",
            "../admin",
            "example.com?token=x",
            "a%2fb",
            "a@b",
            "-a.test",
        ] {
            assert!(!valid_icon_domain(bad));
        }
    }
}

#[worker::send]
pub async fn client_script() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, no-cache"),
        ],
        include_str!("../../../static/overrides/raywarden.js"),
    )
        .into_response()
}
