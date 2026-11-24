use std::{convert::Infallible, future::ready};

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::{HeaderMap, request::Parts},
};

use crate::{
    errors::AppError,
    service::rate_limit::client_ip,
    utils::version::{ParsedVersion, parse},
};

pub(in crate::api) struct ClientIp(pub String);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        ready(Ok(Self(client_ip(&parts.headers).to_owned())))
    }
}

pub(in crate::api) struct DeviceTypeHeader(pub i32);

impl<S: Send + Sync> FromRequestParts<S> for DeviceTypeHeader {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        let value = device_type(&parts.headers)
            .ok_or_else(|| AppError::bad_request("Missing device-type header"));
        ready(value.and_then(|value| {
            value
                .trim()
                .parse::<i32>()
                .ok()
                .filter(|value| (0..=40).contains(value))
                .map(Self)
                .ok_or_else(|| AppError::bad_request("Invalid device-type header"))
        }))
    }
}

impl DeviceTypeHeader {
    pub(in crate::api) fn for_send_upload(headers: &HeaderMap) -> Option<Self> {
        device_type(headers)?.parse::<i32>().ok().map(Self)
    }
}

/// Legacy Send callers may omit or send an unrecognized device type.
impl<S: Send + Sync> OptionalFromRequestParts<S> for DeviceTypeHeader {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> {
        ready(Ok(Self::for_send_upload(&parts.headers)))
    }
}

fn device_type(headers: &HeaderMap) -> Option<&str> {
    headers.get("device-type")?.to_str().ok()
}

pub(in crate::api) struct ClientVersionHeader(pub Option<ParsedVersion>);

impl ClientVersionHeader {
    pub(in crate::api) fn from_headers(headers: &HeaderMap) -> Self {
        Self(
            headers
                .get("Bitwarden-Client-Version")
                .and_then(|value| value.to_str().ok())
                .and_then(parse),
        )
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientVersionHeader {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        ready(Ok(Self::from_headers(&parts.headers)))
    }
}
