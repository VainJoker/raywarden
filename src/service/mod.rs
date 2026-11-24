//! Business workflows grouped by identity, vault, Send and notifications.
//! Persisted records and platform primitives live in `models` and `infra`.

pub mod identity;
mod maintenance;
pub mod notifications;
mod password;
pub mod rate_limit;
pub mod send;
pub mod storage_cleanup;
pub mod vault;
pub mod vault_write;
pub mod web_vault_ui;

pub(crate) use maintenance::run_maintenance;
