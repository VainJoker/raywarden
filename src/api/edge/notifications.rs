//! Public notification edge adapter, `SignalR` HTTP errors, and `notifydo`
//! host.
mod notify_do;

pub use notify_do::notifydo;
use worker::{Env, Method, Request, Response, ResponseBuilder, Result as WorkerResult};

use crate::{
    api::middleware::cors::CorsContext, errors::AppResult, service::notifications::hub::HubError,
};

const NOTIFICATION_METHODS: &str = "GET,POST,OPTIONS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicNotificationEndpoint {
    Upgrade { anonymous: bool },
    Negotiate { anonymous: bool },
}

impl PublicNotificationEndpoint {
    fn parse(path: &str) -> Option<Self> {
        match path {
            "/notifications/hub" => Some(Self::Upgrade { anonymous: false }),
            "/notifications/anonymous-hub" => Some(Self::Upgrade { anonymous: true }),
            "/notifications/hub/negotiate" => Some(Self::Negotiate { anonymous: false }),
            "/notifications/anonymous-hub/negotiate" => Some(Self::Negotiate { anonymous: true }),
            _ => None,
        }
    }

    const fn expected_method(self) -> (Method, &'static str) {
        match self {
            Self::Upgrade { .. } => (Method::Get, "GET, OPTIONS"),
            Self::Negotiate { .. } => (Method::Post, "POST, OPTIONS"),
        }
    }
}

/// `SignalR` HTTP rejections emitted by the Worker edge and `notifydo`.
enum NotificationError {
    NotFound,
    NotConfigured,
    MethodNotAllowed { allow: &'static str },
    UpgradeRequired,
    Hub(HubError),
}

impl From<HubError> for NotificationError {
    fn from(error: HubError) -> Self {
        Self::Hub(error)
    }
}

impl NotificationError {
    pub(self) fn into_worker_response(self) -> WorkerResult<Response> {
        let (status, message, headers): (_, _, &[(_, _)]) = match self {
            Self::NotFound => (404, "Not found", &[]),
            Self::NotConfigured => (503, "Notifications are not configured", &[]),
            Self::MethodNotAllowed { allow } => {
                return ResponseBuilder::new()
                    .with_header("Allow", allow)?
                    .error("Method not allowed", 405);
            }
            Self::UpgradeRequired => (426, "WebSocket upgrade required", &[
                ("Upgrade", "websocket"),
                ("Connection", "upgrade"),
            ]),
            Self::Hub(HubError::Unauthorized) => (401, "Unauthorized", &[]),
            Self::Hub(HubError::BearerRequired) => {
                (401, "Unauthorized", &[("WWW-Authenticate", "Bearer")])
            }
            Self::Hub(HubError::InvalidBearerToken) => (401, "Unauthorized", &[(
                "WWW-Authenticate",
                "Bearer error=\"invalid_token\"",
            )]),
            Self::Hub(HubError::TooManyConnections) => (429, "Too many connections", &[]),
            Self::Hub(HubError::Unavailable) => (503, "Service temporarily unavailable", &[]),
            Self::Hub(HubError::Forbidden) => (403, "Forbidden", &[]),
            Self::Hub(HubError::InvalidNotification) => (400, "Invalid notification", &[]),
        };
        let mut response = ResponseBuilder::new();
        for &(name, value) in headers {
            response = response.with_header(name, value)?;
        }
        response.error(message, status)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Route {
    NotFound,
    Options,
    MethodNotAllowed { allow: &'static str },
    Forward,
}

impl Route {
    pub(super) fn classify(path: &str, method: &Method) -> Option<Self> {
        let Some(endpoint) = PublicNotificationEndpoint::parse(path) else {
            return path
                .starts_with("/notifications/")
                .then_some(Self::NotFound);
        };
        let (expected, allow) = endpoint.expected_method();

        Some(match method {
            Method::Options => Self::Options,
            method if *method == expected => Self::Forward,
            _ => Self::MethodNotAllowed { allow },
        })
    }

    pub(super) async fn handle(
        self,
        request: Request,
        env: &Env,
        cors: &CorsContext,
    ) -> AppResult<Response> {
        let response = match self {
            Self::NotFound => NotificationError::NotFound.into_worker_response()?,
            Self::Options => Response::empty()?.with_status(204),
            route => match (env.durable_object("notifydo"), route) {
                (Err(_), _) => NotificationError::NotConfigured.into_worker_response()?,
                (Ok(_), Self::MethodNotAllowed { allow }) => {
                    NotificationError::MethodNotAllowed { allow }.into_worker_response()?
                }
                (Ok(namespace), _) => {
                    let result = async {
                        let stub = namespace.id_from_name("global")?.get_stub()?;
                        stub.fetch_with_request(request).await
                    }
                    .await;
                    if let Ok(response) = result {
                        response
                    } else {
                        log::warn!("notifydo forwarding failed");
                        NotificationError::from(HubError::Unavailable).into_worker_response()?
                    }
                }
            },
        };
        cors.apply_methods(response, NOTIFICATION_METHODS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_only_expose_public_hubs_and_negotiate() {
        for path in ["/notifications/hub", "/notifications/anonymous-hub"] {
            assert_eq!(Route::classify(path, &Method::Get), Some(Route::Forward));
            assert_eq!(
                Route::classify(path, &Method::Post),
                Some(Route::MethodNotAllowed {
                    allow: "GET, OPTIONS",
                })
            );
            assert_eq!(
                Route::classify(path, &Method::Options),
                Some(Route::Options)
            );
        }
        for path in [
            "/notifications/hub/negotiate",
            "/notifications/anonymous-hub/negotiate",
        ] {
            assert_eq!(Route::classify(path, &Method::Post), Some(Route::Forward));
            assert_eq!(
                Route::classify(path, &Method::Get),
                Some(Route::MethodNotAllowed {
                    allow: "POST, OPTIONS",
                })
            );
        }
        for path in ["/notifications/internal/fanout", "/notifications/unknown"] {
            assert_eq!(Route::classify(path, &Method::Post), Some(Route::NotFound));
            assert_eq!(
                Route::classify(path, &Method::Options),
                Some(Route::NotFound)
            );
        }
        for path in ["/api/alive", "/notifications", "/notifications-other/hub"] {
            assert_eq!(Route::classify(path, &Method::Get), None, "{path}");
        }
    }
}
