//! Shared utilities independent of application workflows and platform bindings.
pub mod serde;
pub mod time;
pub mod version;

pub use constant_time_eq::constant_time_eq;

/// Read a Bearer credential without modifying the token itself.
pub(crate) fn parse_bearer(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim_start_matches(' ');
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::parse_bearer;

    #[test]
    fn bearer_parsing_matches_the_scheme_and_preserves_token_bytes() {
        assert_eq!(parse_bearer("Bearer single"), Some("single"));
        assert_eq!(parse_bearer("bEaReR   two. parts "), Some("two. parts "));
        for value in [
            "Bearer",
            "Bearer  ",
            "Bearer\ttoken",
            "BearerX token",
            " Bearer token",
        ] {
            assert_eq!(parse_bearer(value), None, "{value:?}");
        }
    }
}
