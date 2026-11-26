//! Persisted records and atomic writes, grouped by identity, vault and Send.
pub(crate) mod health;
pub mod identity;
pub mod mutation;
pub(crate) mod page;
pub mod send;
pub mod storage;
pub mod vault;
