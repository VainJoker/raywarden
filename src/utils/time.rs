//! UTC instants and the stable timestamp precision used by the API and D1.
use jiff::Timestamp;

pub fn now() -> Timestamp {
    Timestamp::now()
}

pub fn now_seconds() -> i64 {
    now().as_second()
}

pub fn now_rfc3339() -> String {
    format_millis(now())
}

pub fn format_millis(timestamp: Timestamp) -> String {
    format!("{timestamp:.3}")
}

pub fn format_micros(timestamp: Timestamp) -> String {
    format!("{timestamp:.6}")
}

pub fn parse(value: &str) -> Result<Timestamp, jiff::Error> {
    value.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_use_fixed_utc_precision_without_losing_offset_semantics() {
        let utc = parse("2026-11-17T01:02:03.123456789Z").expect("test fixture should be valid");
        let offset =
            parse("2026-11-17T09:02:03.123456789+08:00").expect("test fixture should be valid");
        assert_eq!(utc, offset);
        assert_eq!(format_millis(utc), "2026-11-17T01:02:03.123Z");
        assert_eq!(format_micros(offset), "2026-11-17T01:02:03.123456Z");
        assert_eq!(
            format_millis(Timestamp::UNIX_EPOCH),
            "1970-01-01T00:00:00.000Z"
        );
        assert!(parse("not a date").is_err());
        assert!(parse("2026-11-17T01:02:03").is_err());
    }
}
