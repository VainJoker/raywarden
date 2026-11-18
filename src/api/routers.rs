pub mod accounts;
pub mod api_keys;
pub mod archive;
pub mod attachments;
pub mod auth_requests;
pub mod ciphers;
pub mod devices;
pub mod email;
pub mod extras;
pub mod folders;
pub mod identity;
pub mod others;
pub mod sessions;
pub mod turnstile;
pub mod twofactor;
pub mod webauthn;

use accounts::accounts_router;
use attachments::attachment_router;
use axum::Router;
use ciphers::cipher_router;
use devices::devices_router;
use folders::folders_router;
use identity::identity_router;
use others::others_router;
use twofactor::twofactor_router;

use crate::api::AppState;

/// Build the main application router with all grouped routes.
pub fn api_router(state: AppState) -> Router {
    Router::new()
        .merge(webauthn::webauthn_router())
        .merge(api_keys::api_keys_router())
        .merge(email::email_router())
        .merge(turnstile::turnstile_router())
        .merge(extras::extras_router())
        .merge(archive::archive_router())
        .merge(crate::send::router())
        .merge(auth_requests::auth_requests_router())
        .merge(sessions::sessions_router())
        .merge(attachment_router())
        .merge(cipher_router())
        .merge(identity_router())
        .merge(accounts_router())
        .merge(folders_router())
        .merge(devices_router())
        .merge(twofactor_router())
        .merge(others_router())
        .with_state(state)
}
