//! Route Worker HTTP requests to a Durable Object or the shared Axum app.
mod heavy;
mod notifications;

pub use heavy::heavydo;
pub use notifications::notifydo;
use wasm_bindgen::JsCast;
use worker::{Env, HttpRequest, Method, Request, Response};

use super::{
    bootstrap::{handle_request, worker_error_response},
    common::response::into_worker_response,
    middleware::{cors::CorsContext, headers},
};
use crate::errors::AppResult;

enum DispatchTarget {
    Notifications(notifications::Route),
    Heavy(heavy::Route),
    App,
}

impl DispatchTarget {
    fn classify(path: &str, method: &Method) -> Self {
        if let Some(route) = notifications::Route::classify(path, method) {
            Self::Notifications(route)
        } else if let Some(route) = heavy::Route::classify(path, method) {
            Self::Heavy(route)
        } else {
            Self::App
        }
    }
}

pub(crate) async fn handle_fetch(request: Request, env: Env) -> worker::Result<Response> {
    let path = request.path();
    let cors = CorsContext::new(&request, &env);
    match dispatch_request(request, env, &path, &cors).await {
        Ok(response) => Ok(response),
        Err(error) => headers::apply_worker(&path, worker_error_response(error, &cors)?),
    }
}

async fn dispatch_request(
    request: Request,
    env: Env,
    raw_path: &str,
    cors: &CorsContext,
) -> AppResult<Response> {
    let (request, path) = normalize(request, raw_path)?;
    let response = match DispatchTarget::classify(path, &request.method()) {
        DispatchTarget::Notifications(route) => route.handle(request, &env, cors).await?,
        DispatchTarget::Heavy(route) => {
            let Some(stub) = route.select_stub(&request, &env).await? else {
                return handle_locally(request, env, cors).await;
            };
            stub.fetch_with_request(request).await?
        }
        DispatchTarget::App => return handle_locally(request, env, cors).await,
    };
    Ok(headers::apply_worker(path, response)?)
}

async fn handle_locally(request: Request, env: Env, cors: &CorsContext) -> AppResult<Response> {
    let request: HttpRequest = request.try_into()?;
    let response = handle_request(request, env, cors.policy()).await?;
    Ok(into_worker_response(response)?)
}

fn normalized_path(raw_path: &str) -> &str {
    match raw_path.trim_end_matches('/') {
        "" => "/",
        path => path,
    }
}

fn normalize(request: Request, raw_path: &str) -> AppResult<(Request, &str)> {
    let path = normalized_path(raw_path);
    if path == raw_path {
        return Ok((request, path));
    }

    let mut url = request.url()?;
    url.set_path(path);
    // Equivalent to new Request(url, original): preserve the original body,
    // headers, method and request options without buffering a stream.
    let init: &web_sys::RequestInit = request.inner().unchecked_ref();
    let request =
        web_sys::Request::new_with_str_and_init(url.as_str(), init).map_err(worker::Error::from)?;
    Ok((request.into(), path))
}
