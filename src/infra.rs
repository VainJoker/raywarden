pub mod crypto;
pub mod db;
pub mod delivery;
pub(crate) mod env;
pub mod jwt;
pub mod logging;
pub mod storage;
pub(crate) mod worker_response;

use std::sync::Once;

use ::worker::Env;

/// Initialize panic hook and logging once per Worker instance.
pub(crate) fn init(env: &Env) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        console_error_panic_hook::set_once();
        logging::init(env);
    });
}
