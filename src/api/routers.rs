pub mod accounts;
pub mod attachments;
pub mod ciphers;
pub mod config;
pub mod devices;
pub mod emergency;
pub mod folders;
pub mod identity;
pub mod sync;
pub mod twofactor;
pub mod webauth;

use accounts::accounts_router;
use attachments::attachment_router;
use axum::Router;
use ciphers::cipher_router;
use config::config_router;
use devices::devices_router;
use emergency::emergency_router;
use folders::folders_router;
use identity::identity_router;
use sync::sync_router;
use twofactor::twofactor_router;
use webauth::webauthn_router;

use crate::api::AppState;

/// Build the main application router with all grouped routes.
pub fn api_router(state: AppState) -> Router {
    Router::new()
        .merge(attachment_router())
        .merge(cipher_router())
        .merge(identity_router())
        .merge(config_router())
        .merge(sync_router())
        .merge(accounts_router())
        .merge(folders_router())
        .merge(devices_router())
        .merge(twofactor_router())
        .merge(emergency_router())
        .merge(webauthn_router())
        .with_state(state)
}
