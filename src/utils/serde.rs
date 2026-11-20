//! Serde adapters for shared data representations.

/// Serialize/deserialize booleans stored as integer `0`/`1`.
///
/// Accept only integer `0` and `1`, preserving the numeric representation on
/// serialization. Boolean and string inputs are rejected.
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

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "Serde field serializers require a shared reference to the \
                  field value"
    )]
    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(i64::from(*value))
    }
}

#[cfg(test)]
mod tests {
    use serde::{
        Deserialize,
        Serialize,
    };
    use serde_json::json;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Record {
        #[serde(with = "super::bool_from_int")]
        enabled: bool,
    }

    #[test]
    fn numeric_booleans_round_trip_as_integers() {
        for (value, enabled) in [(0, false), (1, true)] {
            let wire = json!({"enabled": value});
            let record: Record = serde_json::from_value(wire.clone())
                .expect("integer boolean should decode");
            assert_eq!(record, Record { enabled });
            assert_eq!(
                serde_json::to_value(record).expect("record should encode"),
                wire
            );
        }
    }

    #[test]
    fn numeric_booleans_reject_other_representations() {
        for value in [
            json!(true),
            json!(false),
            json!(2),
            json!(-1),
            json!("1"),
            json!(null),
        ] {
            assert!(
                serde_json::from_value::<Record>(json!({"enabled": value}))
                    .is_err()
            );
        }
    }
}
