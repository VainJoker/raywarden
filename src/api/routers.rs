//! Router composition for the single application state shared by handlers.
mod identity;
mod send;
mod server;
mod vault;

use std::sync::{Arc, OnceLock};

use axum::Router;
pub(super) use server::public_router;

use crate::api::AppState;

pub(super) fn router() -> Router<Arc<AppState>> {
    static ROUTER: OnceLock<Router<Arc<AppState>>> = OnceLock::new();
    ROUTER
        .get_or_init(|| {
            Router::new()
                .merge(identity::router())
                .merge(vault::router())
                .merge(send::router())
                .merge(server::router())
        })
        .clone()
}
