//! Shared serde helpers for model (de)serialization.

/// Serialize/deserialize booleans stored as integer `0`/`1`.
///
/// Cloudflare D1 returns `SQLite` integers for boolean columns, and some tables
/// store booleans as `0` (false) / `1` (true).
pub mod bool_from_int {
    use serde::{
        Deserialize,
        Deserializer,
        Serializer,
    };

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(serde::de::Error::custom("expected integer 0 or 1")),
        }
    }

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(i64::from(*value))
    }
}
