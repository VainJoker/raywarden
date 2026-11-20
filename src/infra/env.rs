//! Worker environment access without application state or persistence.
use worker::Env;

use crate::errors::{
    AppError,
    AppResult,
};

/// Read an optional secret or variable without introducing mandatory bindings.
pub fn env_text(env: &Env, key: &str) -> Option<String> {
    env.var(key)
        .ok()
        .map(|v| v.to_string())
        .filter(|v| !v.trim().is_empty())
}

pub fn env_bool(env: &Env, key: &str, default: bool) -> bool {
    let value = env_text(env, key)
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase());
    match value.as_deref() {
        Some("1" | "true" | "yes" | "on") => true,
        Some("0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

pub(crate) fn string_binding(
    env: &Env,
    name: &str,
) -> AppResult<Option<String>> {
    // Distinguish an absent property from a value of the wrong type.
    let value = js_sys::Reflect::get(env, &name.into())
        .map_err(AppError::internal_error)?;
    if value.is_undefined() {
        return Ok(None);
    }
    value.as_string().map(Some).ok_or(AppError::Internal)
}
