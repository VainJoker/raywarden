//! Persisted records and atomic writes, grouped by identity, vault and Send.
//! Cross-feature transactions, usage queries and row helpers remain shared.
pub(crate) mod health;
pub mod identity;
pub mod mutation;
pub(crate) mod page;
pub mod send;
pub mod storage;
pub mod usage;
pub mod vault;
