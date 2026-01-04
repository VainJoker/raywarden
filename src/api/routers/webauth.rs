use axum::{
    Router,
    routing::get,
};

use crate::api::{
    AppState,
    controller::webauth,
};

pub fn webauthn_router() -> Router<AppState> {
    Router::new().route("/api/webauthn", get(webauth::get_webauthn_credentials))
}
