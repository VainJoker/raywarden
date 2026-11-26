//! Numeric version cores with a flag for prerelease suffixes.
use std::str::FromStr;

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

impl FromStr for ParsedVersion {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
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
            return Err(());
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
            return Err(());
        }
        let number = |part: &str| {
            if part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                Err(())
            } else {
                part.parse().map_err(|_error| ())
            }
        };
        let mut parts = core.split('.');
        let version = Self {
            major: number(parts.next().ok_or(())?)?,
            minor: number(parts.next().ok_or(())?)?,
            patch: number(parts.next().ok_or(())?)?,
            is_prerelease: pre.is_some(),
        };
        parts.next().is_none().then_some(version).ok_or(())
    }
}

/// Build metadata is validated and discarded.
pub(crate) fn parse(value: &str) -> Option<ParsedVersion> {
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{ParsedVersion, parse};

    #[test]
    fn semver_parses_prerelease_flags_and_rejects_malformed_inputs() {
        assert_eq!(
            parse("2026.10.2"),
            Some(ParsedVersion {
                major: 2026,
                minor: 10,
                patch: 2,
                is_prerelease: false
            })
        );
        let pre = parse("2026.11.0-beta.1+build").expect("pre");
        assert!(pre.is_prerelease && !pre.satisfies_minimum(2026, 11, 0));
        for bad in [
            "",
            "2026.10",
            "2026.10.01",
            "v1.2.3",
            "1.2.3-beta.01",
            "18446744073709551616.0.0",
        ] {
            assert!(parse(bad).is_none(), "{bad}");
        }
    }
}
