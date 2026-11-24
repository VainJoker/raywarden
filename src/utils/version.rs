//! Numeric version cores with a flag for prerelease suffixes.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParsedVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub is_prerelease: bool,
}

impl ParsedVersion {
    pub(crate) fn satisfies_minimum(self, major: u64, minor: u64, patch: u64) -> bool {
        let current = (self.major, self.minor, self.patch);
        let minimum = (major, minor, patch);
        current > minimum || (current == minimum && !self.is_prerelease)
    }
}

/// Build metadata is validated and discarded.
pub(crate) fn parse(value: &str) -> Option<ParsedVersion> {
    let identifiers = |part: &str| {
        !part.is_empty()
            && part.split('.').all(|id| {
                !id.is_empty() && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
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
        !identifiers(value)
            || value.split('.').any(|id| {
                id.len() > 1 && id.starts_with('0') && id.bytes().all(|c| c.is_ascii_digit())
            })
    }) {
        return None;
    }
    let number = |part: &str| {
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            None
        } else {
            part.parse().ok()
        }
    };
    let mut parts = core.split('.');
    let version = ParsedVersion {
        major: number(parts.next()?)?,
        minor: number(parts.next()?)?,
        patch: number(parts.next()?)?,
        is_prerelease: pre.is_some(),
    };
    parts.next().is_none().then_some(version)
}

#[cfg(test)]
mod tests {
    use super::{ParsedVersion, parse};

    #[test]
    fn parses_numeric_cores_and_prerelease_flags_without_build_metadata() {
        for (value, (major, minor, patch), is_prerelease) in [
            ("0.0.0", (0, 0, 0), false),
            ("2026.10.2", (2026, 10, 2), false),
            ("2026.11.0-beta.1+build", (2026, 11, 0), true),
            ("1.2.3+001.build-7", (1, 2, 3), false),
            ("1.2.3-0", (1, 2, 3), true),
            ("18446744073709551615.0.0", (u64::MAX, 0, 0), false),
        ] {
            let version = ParsedVersion {
                major,
                minor,
                patch,
                is_prerelease,
            };
            assert_eq!(parse(value), Some(version), "{value}");
            assert_eq!(
                version.satisfies_minimum(major, minor, patch),
                !is_prerelease
            );
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
