mod identity;
mod send;
mod server;
mod vault;

use std::sync::OnceLock;

use axum::Router;

use crate::api::AppState;

pub(super) fn router() -> Router<AppState> {
    static ROUTER: OnceLock<Router<AppState>> = OnceLock::new();
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
