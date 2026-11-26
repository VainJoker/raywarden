use axum::{
    Json as AxumJson,
    extract::{FromRequest, Request, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use serde::de::DeserializeOwned;

use crate::errors::AppError;

pub(in crate::api) struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match AxumJson::<T>::from_request(request, state).await {
            Ok(AxumJson(value)) => Ok(Self(value)),
            Err(JsonRejection::BytesRejection(error)) => {
                if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    Err(AppError::PayloadTooLarge {
                        message: "JSON request body exceeds size limit".into(),
                    }
                    .into_response())
                } else {
                    Err((
                        error.status(),
                        AppError::bad_request("Cannot read JSON request body"),
                    )
                        .into_response())
                }
            }
            Err(JsonRejection::MissingJsonContentType(_)) => Err(AppError::UnsupportedMediaType {
                message: "Expected application/json".into(),
            }
            .into_response()),
            Err(JsonRejection::JsonSyntaxError(_)) => {
                Err(AppError::bad_request("Malformed JSON request body").into_response())
            }
            Err(JsonRejection::JsonDataError(error)) => Err(AppError::UnprocessableEntity {
                message: sanitize_json_data_error(&error.body_text()).into(),
            }
            .into_response()),
            Err(error) => Err(error.into_response()),
        }
    }
}

/// Strip quoted input values from Serde/Axum schema diagnostics while keeping
/// the offending field path and expected type.
fn sanitize_json_data_error(raw: &str) -> String {
    let trimmed = raw
        .strip_prefix("Failed to deserialize the JSON body into the target type: ")
        .unwrap_or(raw)
        .trim();
    if trimmed.is_empty() {
        return "Request body does not match the expected JSON schema".to_owned();
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut chars = trimmed.chars();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            out.push_str("\"<redacted>\"");
            let mut escaped = false;
            for inner in chars.by_ref() {
                if escaped {
                    escaped = false;
                } else {
                    match inner {
                        '\\' => escaped = true,
                        '"' => break,
                        _ => {}
                    }
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sanitize_json_data_error;

    #[test]
    fn json_data_diagnostics_preserve_field_names_and_redact_quoted_values() {
        assert_eq!(
            sanitize_json_data_error(
                "Failed to deserialize the JSON body into the target type: missing field `email` at line 1 column 2"
            ),
            "missing field `email` at line 1 column 2"
        );
        let sanitized = sanitize_json_data_error(
            "Failed to deserialize the JSON body into the target type: kdf: invalid type: string \"secret-\\\"token\\\"\", expected i32 at line 1 column 28",
        );
        assert_eq!(
            sanitized,
            "kdf: invalid type: string \"<redacted>\", expected i32 at line 1 column 28"
        );
        assert!(!sanitized.contains("secret"));
    }
}
