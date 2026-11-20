//! Numeric version cores with a flag for prerelease suffixes.

/// Parse three `u64` components and optional prerelease/build suffixes.
/// Returns the numeric core and whether a prerelease is present. Build metadata
/// is validated but discarded; this function does not compare full versions.
pub(crate) fn parse(value: &str) -> Option<((u64, u64, u64), bool)> {
    let identifiers = |part: &str| {
        !part.is_empty() &&
            part.split('.').all(|id| {
                !id.is_empty() &&
                    id.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
    };
    let (value, build) = value
        .split_once('+')
        .map_or((value, None), |(core, build)| (core, Some(build)));
    if build.is_some_and(|value| !identifiers(value)) {
        return None;
    }
    let (core, pre) = value
        .split_once('-')
        .map_or((value, None), |(core, pre)| (core, Some(pre)));
    if pre.is_some_and(|value| {
        !identifiers(value) ||
            value.split('.').any(|id| {
                id.len() > 1 &&
                    id.starts_with('0') &&
                    id.bytes().all(|c| c.is_ascii_digit())
            })
    }) {
        return None;
    }
    let number = |part: &str| {
        if part.is_empty() ||
            !part.bytes().all(|b| b.is_ascii_digit()) ||
            (part.len() > 1 && part.starts_with('0'))
        {
            None
        } else {
            part.parse().ok()
        }
    };
    let mut parts = core.split('.');
    let version = (
        number(parts.next()?)?,
        number(parts.next()?)?,
        number(parts.next()?)?,
    );
    parts.next().is_none().then_some((version, pre.is_some()))
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_numeric_cores_and_prerelease_flags_without_build_metadata() {
        for (value, core, prerelease) in [
            ("0.0.0", (0, 0, 0), false),
            ("2026.10.2", (2026, 10, 2), false),
            ("2026.11.0-beta.1+build", (2026, 11, 0), true),
            ("1.2.3+001.build-7", (1, 2, 3), false),
            ("1.2.3-0", (1, 2, 3), true),
            ("18446744073709551615.0.0", (u64::MAX, 0, 0), false),
        ] {
            assert_eq!(parse(value), Some((core, prerelease)), "{value}");
        }
    }

    #[test]
    fn rejects_invalid_cores_suffixes_and_overflow() {
        for value in [
            "",
            "2026.10",
            "2026.10.01",
            "2026.10.2-",
            "2026.10.2+",
            "2026.10.2-beta.01",
            "1.2.3.4",
            "v1.2.3",
            " 1.2.3",
            "1.2.3 ",
            "01.2.3",
            "1.02.3",
            "1.2.3-beta..1",
            "1.2.3+build..1",
            "1.2.3-beta_1",
            "1.2.3+build+one",
            "18446744073709551616.0.0",
        ] {
            assert!(parse(value).is_none(), "{value}");
        }
    }
}
