//! Shared API response wrappers and conversion to Worker responses.
use axum::{
    Json,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::errors::worker_failure;

/// Serialize the response body as JSON using its public wire format.
pub(in crate::api) struct ApiResponse<T>(pub T);

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        Json(self.0).into_response()
    }
}

pub(in crate::api) struct NoStore<R>(pub R);

impl<R: IntoResponse> NoStore<R> {
    pub(in crate::api) fn private(response: R) -> impl IntoResponse {
        ([(header::CACHE_CONTROL, "private, no-store")], response)
    }
}

impl<R: IntoResponse> IntoResponse for NoStore<R> {
    fn into_response(self) -> Response {
        let mut response = self.0.into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

pub(in crate::api) struct WithCookies<R> {
    pub response: R,
    pub cookies: Vec<HeaderValue>,
}

impl<R: IntoResponse> IntoResponse for WithCookies<R> {
    fn into_response(self) -> Response {
        let mut response = self.response.into_response();
        for cookie in self.cookies {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
        response
    }
}

#[derive(Serialize)]
pub(in crate::api) struct EmptyObject {}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::api) struct EmptyListResponse {
    data: [(); 0],
    object: &'static str,
    continuation_token: (),
}

impl EmptyListResponse {
    pub(in crate::api) const fn new() -> Self {
        Self {
            data: [],
            object: "list",
            continuation_token: (),
        }
    }
}

#[derive(Clone)]
struct NativeStream(worker::send::SendWrapper<web_sys::ReadableStream>);

/// Keep native download streams outside `http_body`'s per-chunk WASM adapter.
/// Axum still applies headers and CORS before this final response conversion.
pub fn into_worker_response(mut response: Response) -> worker::Result<worker::Response> {
    if let Some(NativeStream(stream)) = response.extensions_mut().remove::<NativeStream>() {
        let headers = worker::Headers::new();
        for (name, value) in response.headers() {
            headers.append(
                name.as_str(),
                value
                    .to_str()
                    .map_err(|error| worker_failure(error.to_string()))?,
            )?;
        }
        Ok(
            worker::Response::from_body(worker::ResponseBody::Stream(stream.0))?
                .with_status(response.status().as_u16())
                .with_headers(headers),
        )
    } else {
        response.try_into()
    }
}

pub(crate) fn set_native_stream(response: &mut Response, stream: web_sys::ReadableStream) {
    response
        .extensions_mut()
        .insert(NativeStream(worker::send::SendWrapper::new(stream)));
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future as _,
        task::{Context, Poll, Waker},
    };

    use axum::http::StatusCode;
    use serde_json::{Value, json};

    use super::*;

    fn body(response: Response) -> (StatusCode, Vec<u8>) {
        let status = response.status();
        let mut body = std::pin::pin!(axum::body::to_bytes(response.into_body(), usize::MAX));
        let Poll::Ready(bytes) = body.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
            panic!("fixed JSON/string responses must be ready without I/O");
        };
        (status, bytes.expect("valid response fixture").to_vec())
    }

    #[test]
    fn typed_success_preserves_json_shape_and_status() {
        let response = (StatusCode::CREATED, ApiResponse(EmptyListResponse::new())).into_response();
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/json"
        );
        let (status, bytes) = body(response);
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).expect("valid response fixture"),
            json!({"data":[],"object":"list","continuationToken":null})
        );
        assert_eq!(body(ApiResponse(()).into_response()).1, b"null");
    }

    #[test]
    fn response_modifiers_compose_without_replacing_cookie_headers() {
        let response = NoStore(WithCookies {
            response: (
                [(header::SET_COOKIE, "original=1")],
                ApiResponse(EmptyObject {}),
            ),
            cookies: vec![HeaderValue::from_static("added=2")],
        })
        .into_response();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert_eq!(body(response).1, b"{}");
    }
}
