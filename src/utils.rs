//! Shared utilities independent of application workflows and platform bindings.
pub mod serde;
pub mod time;
pub mod version;

pub use constant_time_eq::constant_time_eq;
