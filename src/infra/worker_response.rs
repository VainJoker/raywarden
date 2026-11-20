//! Preserve native Worker streams when converting HTTP responses.
use axum::response::Response;

use crate::errors::worker_failure;

#[derive(Clone)]
struct NativeStream(worker::send::SendWrapper<web_sys::ReadableStream>);

/// Keep native download streams outside `http_body`'s per-chunk WASM adapter.
/// Axum still applies headers and CORS before this final response conversion.
pub fn into_worker_response(
    mut response: Response,
) -> worker::Result<worker::Response> {
    if let Some(NativeStream(stream)) =
        response.extensions_mut().remove::<NativeStream>()
    {
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
            worker::Response::from_body(worker::ResponseBody::Stream(
                stream.0,
            ))?
            .with_status(response.status().as_u16())
            .with_headers(headers),
        )
    } else {
        response.try_into()
    }
}

pub(crate) fn set_native_stream(
    response: &mut Response,
    stream: web_sys::ReadableStream,
) {
    response
        .extensions_mut()
        .insert(NativeStream(worker::send::SendWrapper::new(stream)));
}
