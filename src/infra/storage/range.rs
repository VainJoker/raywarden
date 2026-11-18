/// A single inclusive byte interval. Numeric values must remain exact when
/// passed to the Workers runtime's JavaScript APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end:   u64,
}

impl ByteRange {
    pub const fn length(self) -> u64 {
        self.end - self.start + 1
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidRange;

pub fn parse_byte_range(
    value: Option<&str>,
    size: u64,
) -> Result<Option<ByteRange>, InvalidRange> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let spec = value.trim().strip_prefix("bytes=").ok_or(InvalidRange)?;
    let (start, end) = spec.split_once('-').ok_or(InvalidRange)?;
    if size == 0 || size > 9_007_199_254_740_991 {
        return Err(InvalidRange);
    }
    let number = |text: &str| -> Result<u64, InvalidRange> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(InvalidRange);
        }
        text.parse::<u64>()
            .ok()
            .filter(|value| *value <= 9_007_199_254_740_991)
            .ok_or(InvalidRange)
    };
    let range = if start.is_empty() {
        let suffix = number(end)?;
        if suffix == 0 {
            return Err(InvalidRange);
        }
        ByteRange {
            start: size.saturating_sub(suffix),
            end:   size - 1,
        }
    } else {
        let start = number(start)?;
        let end = if end.is_empty() {
            size - 1
        } else {
            number(end)?
        };
        if start >= size || start > end {
            return Err(InvalidRange);
        }
        ByteRange {
            start,
            end: end.min(size - 1),
        }
    };
    Ok(Some(range))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_ranges_preserve_closed_open_suffix_and_clamping() {
        for (header, start, end) in [
            ("bytes=1-3", 1, 3),
            ("bytes=5-", 5, 9),
            ("bytes=-3", 7, 9),
            ("bytes=0-999", 0, 9),
            ("bytes=-99", 0, 9),
        ] {
            let range = parse_byte_range(Some(header), 10).unwrap().unwrap();
            assert_eq!(range, ByteRange { start, end });
            assert_eq!(range.length(), end - start + 1);
        }
        assert_eq!(parse_byte_range(None, 0), Ok(None));
    }

    #[test]
    fn malformed_multiple_unsafe_and_unsatisfiable_ranges_fail() {
        for header in [
            "bytes=",
            "bytes=-0",
            "bytes=10-",
            "bytes=5-3",
            "bytes=0-1,3-4",
            "bytes=0-9007199254740992",
            "bytes=1-x",
            "bytes=+1-3",
            "items=0-1",
            "bytes=0--1",
        ] {
            assert!(parse_byte_range(Some(header), 10).is_err(), "{header}");
        }
        assert!(parse_byte_range(Some("bytes=0-"), 0).is_err());
    }
}
