//! HTTP failures with response formats defined by their protocols.
use axum::{
    body::Body,
    http::{
        StatusCode,
        header,
        response::Builder,
    },
    response::{
        IntoResponse,
        Response,
    },
};

use super::{
    AppError,
    AppResult,
};

pub(crate) enum NotificationError {
    NotFound,
    NotConfigured,
    MethodNotAllowed,
    Unauthorized,
    UpgradeRequired,
    TooManyConnections,
    Unavailable,
    Forbidden,
    InvalidNotification,
}

impl NotificationError {
    pub(crate) fn into_worker_response(
        self,
    ) -> worker::Result<worker::Response> {
        let (message, status) = match self {
            Self::NotFound => ("Not found", 404),
            Self::NotConfigured => ("Notifications are not configured", 503),
            Self::MethodNotAllowed => ("Method not allowed", 405),
            Self::Unauthorized => ("Unauthorized", 401),
            Self::UpgradeRequired => ("WebSocket upgrade required", 426),
            Self::TooManyConnections => ("Too many connections", 429),
            Self::Unavailable => ("Service temporarily unavailable", 503),
            Self::Forbidden => ("Forbidden", 403),
            Self::InvalidNotification => ("Invalid notification", 400),
        };
        worker::Response::error(message, status)
    }
}

pub(crate) enum AssetError {
    IconNotFound,
    DemoDisabled,
}

impl IntoResponse for AssetError {
    fn into_response(self) -> Response {
        match self {
            Self::IconNotFound => (
                StatusCode::NOT_FOUND,
                [(header::CACHE_CONTROL, "public, max-age=300")],
                Body::empty(),
            )
                .into_response(),
            Self::DemoDisabled => StatusCode::NOT_FOUND.into_response(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvalidRange(pub(crate) u64);

impl InvalidRange {
    pub(crate) fn into_response(self, builder: Builder) -> AppResult<Response> {
        let Self(size) = self;
        builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{size}"))
            .body(Body::empty())
            .map_err(AppError::internal_error)
    }
}
