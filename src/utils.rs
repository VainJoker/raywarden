//! Shared utilities independent of application workflows and platform bindings.
pub mod serde;
pub mod time;
pub mod version;

pub use constant_time_eq::constant_time_eq;
use futures_util::{Stream, StreamExt as _};

/// Read at most `limit` bytes, returning `None` as soon as a chunk exceeds it.
pub(crate) async fn collect_bounded<C, E>(
    stream: impl Stream<Item = Result<C, E>>,
    limit: usize,
) -> Result<Option<Vec<u8>>, E>
where
    C: AsRef<[u8]>,
{
    futures_util::pin_mut!(stream);
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let slice = chunk.as_ref();
        if slice.len() > limit.saturating_sub(bytes.len()) {
            return Ok(None);
        }
        bytes.extend_from_slice(slice);
    }
    Ok(Some(bytes))
}

/// Empty content-length values are treated like an absent header.
pub(crate) fn bounded_content_length(value: Option<&str>, limit: usize) -> bool {
    value.filter(|value| !value.is_empty()).is_none_or(|value| {
        value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<usize>().is_ok_and(|size| size <= limit)
    })
}

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
