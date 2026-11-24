use axum::{
    Json as AxumJson,
    extract::{FromRequest, Request, rejection::JsonRejection},
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
            Err(JsonRejection::BytesRejection(error)) => Err((
                error.status(),
                AppError::bad_request("Cannot read JSON request body"),
            )
                .into_response()),
            Err(error) => Err(error.into_response()),
        }
    }
}
