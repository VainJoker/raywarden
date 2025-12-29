use axum::{
    Router,
    routing::get,
};

use crate::warden::{
    AppState,
    api::emergency,
};

pub fn emergency_router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/emergency-access/trusted",
            get(emergency::get_trusted_contacts),
        )
        .route(
            "/api/emergency-access/granted",
            get(emergency::get_granted_access),
        )
}
