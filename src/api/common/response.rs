//! Shared API response wrappers and conversion to Worker responses.
pub(in crate::api) use axum::Json as ApiResponse;
use axum::{
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::errors::worker_failure;

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
pub(in crate::api) struct ListResponse<T> {
    data: Vec<T>,
    object: &'static str,
    continuation_token: (),
}

impl<T> From<Vec<T>> for ListResponse<T> {
    fn from(data: Vec<T>) -> Self {
        Self {
            data,
            object: "list",
            continuation_token: (),
        }
    }
}

pub(in crate::api) type EmptyListResponse = ListResponse<()>;

impl ListResponse<()> {
    pub(in crate::api) fn new() -> Self {
        Vec::new().into()
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
    use axum::http::StatusCode;
    use futures_util::FutureExt as _;

    use super::*;

    #[test]
    fn response_wrappers_preserve_json_status_and_multiple_cookies() {
        let resp = NoStore(WithCookies {
            response: (
                StatusCode::CREATED,
                [(header::SET_COOKIE, "a=1")],
                ApiResponse(EmptyObject {}),
            ),
            cookies: vec![HeaderValue::from_static("b=2")],
        })
        .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(resp.headers().get_all(header::SET_COOKIE).iter().count(), 2);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .now_or_never()
            .expect("ready")
            .expect("body");
        assert_eq!(&*bytes, b"{}");
    }
}
