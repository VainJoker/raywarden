use axum::http::{
    Method,
    header::{
        AUTHORIZATION,
        CONTENT_TYPE,
    },
};
use tower_http::cors::{
    AllowHeaders,
    AllowMethods,
    AllowOrigin,
    CorsLayer,
};

use crate::infra::cfg::Config;

/// Build CORS layer from configuration.
pub fn cors_layer(config: &Config) -> CorsLayer {
    let origins = if config.allowed_origins.is_empty() {
        AllowOrigin::list(vec![])
    } else {
        AllowOrigin::list(config.allowed_origins.clone())
    };

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
        ]))
        .allow_headers(AllowHeaders::list([CONTENT_TYPE, AUTHORIZATION]))
        .allow_credentials(true)
}
