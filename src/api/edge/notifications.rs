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

impl HubError {
    fn response(self) -> WorkerResult<Response> {
        let (status, message, headers): (_, _, &[(_, _)]) = match self {
            Self::Unauthorized => (401, "Unauthorized", &[]),
            Self::BearerRequired => (401, "Unauthorized", &[("WWW-Authenticate", "Bearer")]),
            Self::InvalidBearerToken => (401, "Unauthorized", &[(
                "WWW-Authenticate",
                "Bearer error=\"invalid_token\"",
            )]),
            Self::TooManyConnections => (429, "Too many connections", &[]),
            Self::Unavailable => (503, "Service temporarily unavailable", &[]),
            Self::Forbidden => (403, "Forbidden", &[]),
            Self::InvalidNotification => (400, "Invalid notification", &[]),
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
            Self::NotFound => Response::error("Not found", 404)?,
            Self::Options => Response::empty()?.with_status(204),
            Self::MethodNotAllowed { allow } => match env.durable_object("notifydo") {
                Err(_) => Response::error("Notifications are not configured", 503)?,
                Ok(_) => ResponseBuilder::new()
                    .with_header("Allow", allow)?
                    .error("Method not allowed", 405)?,
            },
            Self::Forward => match env.durable_object("notifydo") {
                Err(_) => Response::error("Notifications are not configured", 503)?,
                Ok(namespace) => {
                    let result = async {
                        let stub = namespace.id_from_name("global")?.get_stub()?;
                        stub.fetch_with_request(request).await
                    }
                    .await;
                    if let Ok(response) = result {
                        response
                    } else {
                        log::warn!("notifydo forwarding failed");
                        HubError::Unavailable.response()?
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
