//! Route Worker HTTP requests to a Durable Object or the shared Axum app.
mod heavy;
mod notifications;

use axum::response::IntoResponse;
use wasm_bindgen::JsCast;
use worker::{
    Env,
    HttpRequest,
    Request,
    Response,
};

use super::{
    bootstrap::handle_request,
    middleware::{
        cors::CorsContext,
        security_headers,
    },
};
use crate::{
    errors::AppResult,
    infra::worker_response::into_worker_response,
};

pub(crate) async fn handle_fetch(
    request: Request,
    env: Env,
) -> worker::Result<Response> {
    let path = request.path();
    let cors = CorsContext::new(&request, &env);
    match dispatch_request(request, env, &path, &cors).await {
        Ok(response) => Ok(response),
        Err(error) => {
            let response: Response = error.into_response().try_into()?;
            security_headers::apply_worker(&path, cors.apply(response)?)
        }
    }
}

async fn dispatch_request(
    request: Request,
    env: Env,
    raw_path: &str,
    cors: &CorsContext,
) -> AppResult<Response> {
    let path = normalized_path(raw_path);
    let request = if path == raw_path {
        request
    } else {
        normalized_request(&request, path)?
    };

    let response = if path.starts_with("/notifications/") {
        notifications::handle(path, request, &env, cors).await?
    } else if let Some(stub) = heavy::select_stub(path, &request, &env).await? {
        stub.fetch_with_request(request).await?
    } else {
        let request: HttpRequest = request.try_into()?;
        let response = handle_request(request, env, cors.policy()).await?;
        return Ok(into_worker_response(response)?);
    };
    Ok(security_headers::apply_worker(path, response)?)
}

fn normalized_path(path: &str) -> &str {
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        "/"
    } else {
        normalized
    }
}

fn normalized_request(request: &Request, path: &str) -> AppResult<Request> {
    let mut url = request.url()?;
    url.set_path(path);
    // Equivalent to new Request(url, original): preserve the original body,
    // headers, method and request options without buffering a stream.
    let init: &web_sys::RequestInit = request.inner().unchecked_ref();
    let normalized =
        web_sys::Request::new_with_str_and_init(url.as_str(), init)
            .map_err(worker::Error::from)?;
    Ok(normalized.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_trailing_slashes_before_dispatch() {
        assert_eq!(
            normalized_path("/notifications/hub/negotiate///"),
            "/notifications/hub/negotiate"
        );
    }
}
