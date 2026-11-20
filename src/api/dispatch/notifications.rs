//! Handle public notification requests before forwarding to the Durable Object.

use worker::{
    Env,
    Method,
    Request,
    Response,
};

use crate::{
    api::middleware::cors::CorsContext,
    errors::{
        AppResult,
        protocol::NotificationError,
    },
};

const NOTIFICATION_METHODS: &str = "GET,POST,OPTIONS";

pub(super) async fn handle(
    path: &str,
    request: Request,
    env: &Env,
    cors: &CorsContext,
) -> AppResult<Response> {
    let route = NotificationRoute::classify(path, &request.method());
    let response = match route {
        NotificationRoute::NotFound => {
            NotificationError::NotFound.into_worker_response()?
        }
        NotificationRoute::Options => Response::empty()?.with_status(204),
        route => match env.durable_object("NOTIFY_DO") {
            Err(_) => {
                NotificationError::NotConfigured.into_worker_response()?
            }
            Ok(_) if route == NotificationRoute::MethodNotAllowed => {
                NotificationError::MethodNotAllowed.into_worker_response()?
            }
            Ok(namespace) => {
                let stub = namespace.id_from_name("global")?.get_stub()?;
                stub.fetch_with_request(request).await?
            }
        },
    };
    cors.apply_methods(response, NOTIFICATION_METHODS)
}

#[derive(Debug, PartialEq, Eq)]
enum NotificationRoute {
    NotFound,
    Options,
    MethodNotAllowed,
    Forward,
}

impl NotificationRoute {
    fn classify(path: &str, method: &Method) -> Self {
        let expected = match path {
            "/notifications/hub" | "/notifications/anonymous-hub" => {
                Method::Get
            }
            "/notifications/hub/negotiate" |
            "/notifications/anonymous-hub/negotiate" => Method::Post,
            _ => return Self::NotFound,
        };
        if *method == Method::Options {
            Self::Options
        } else if *method == expected {
            Self::Forward
        } else {
            Self::MethodNotAllowed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_only_expose_public_hubs_and_negotiate() {
        for path in ["/notifications/hub", "/notifications/anonymous-hub"] {
            assert_eq!(
                NotificationRoute::classify(path, &Method::Get),
                NotificationRoute::Forward
            );
            assert_eq!(
                NotificationRoute::classify(path, &Method::Post),
                NotificationRoute::MethodNotAllowed
            );
            assert_eq!(
                NotificationRoute::classify(path, &Method::Options),
                NotificationRoute::Options
            );
        }
        for path in [
            "/notifications/hub/negotiate",
            "/notifications/anonymous-hub/negotiate",
        ] {
            assert_eq!(
                NotificationRoute::classify(path, &Method::Post),
                NotificationRoute::Forward
            );
            assert_eq!(
                NotificationRoute::classify(path, &Method::Get),
                NotificationRoute::MethodNotAllowed
            );
        }
        for path in ["/notifications/internal/fanout", "/notifications/unknown"]
        {
            assert_eq!(
                NotificationRoute::classify(path, &Method::Post),
                NotificationRoute::NotFound
            );
            assert_eq!(
                NotificationRoute::classify(path, &Method::Options),
                NotificationRoute::NotFound
            );
        }
    }
}
