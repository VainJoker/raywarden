use std::{any::type_name, fmt::Display};

use serde::de::DeserializeOwned;
use serde_json::{Value, error::Category};
use wasm_bindgen::JsValue;
use worker::{D1Database, D1PreparedStatement, D1Result, Env, Result as WorkerResult};

use crate::errors::{AppError, AppResult, DatabaseError};

const D1_BINDING: &str = "DB";
const MAX_SAFE_D1_INT: i64 = (1_i64 << f64::MANTISSA_DIGITS) - 1;

pub(crate) trait IntoD1Param {
    fn to_d1_param(&self) -> JsValue;
}

impl IntoD1Param for str {
    fn to_d1_param(&self) -> JsValue {
        JsValue::from_str(self)
    }
}

impl IntoD1Param for String {
    fn to_d1_param(&self) -> JsValue {
        self.as_str().to_d1_param()
    }
}

impl<T: IntoD1Param + ?Sized> IntoD1Param for &T {
    fn to_d1_param(&self) -> JsValue {
        (*self).to_d1_param()
    }
}

impl<T: IntoD1Param> IntoD1Param for Option<T> {
    fn to_d1_param(&self) -> JsValue {
        self.as_ref()
            .map_or(JsValue::NULL, IntoD1Param::to_d1_param)
    }
}

macro_rules! copy_params {
    ($($ty:ty),+ $(,)?) => {$(
        impl IntoD1Param for $ty {
            fn to_d1_param(&self) -> JsValue {
                (*self).into()
            }
        }
    )+};
}

// 64-bit integers are deliberately excluded: `JsValue::from(i64/u64)` produces
// a JS BigInt that D1 rejects, while unchecked `as f64` loses precision above
// 2^53 - 1. Call `safe_int` to convert wide integers explicitly.
copy_params!(bool, i32, u32, f64);

/// Convert a signed 64-bit integer to an exact IEEE-754 number for D1 binding.
pub(crate) fn safe_int(value: i64) -> AppResult<f64> {
    if !(-MAX_SAFE_D1_INT..=MAX_SAFE_D1_INT).contains(&value) {
        return Err(AppError::internal_error(
            "Integer cannot be bound to D1 without precision loss",
        ));
    }
    Ok(value as f64)
}

macro_rules! d1_params {
    ($($value:expr),* $(,)?) => {
        [$($crate::infra::db::IntoD1Param::to_d1_param(&$value)),*]
    };
}

pub(crate) use d1_params;

pub(crate) fn changes_count(result: &D1Result) -> WorkerResult<usize> {
    Ok(result.meta()?.and_then(|meta| meta.changes).unwrap_or(0))
}

/// Resolve the application's D1 binding for the current Worker environment.
pub(crate) fn binding(env: &Env) -> WorkerResult<D1Database> {
    env.d1(D1_BINDING)
}

pub(crate) async fn query_first<T: DeserializeOwned>(
    query: D1PreparedStatement,
    column: Option<&str>,
    context: &str,
) -> AppResult<Option<T>> {
    run_query(query.first(column), context).await
}

pub(crate) async fn query_all<T: DeserializeOwned>(
    query: D1PreparedStatement,
) -> AppResult<Vec<T>> {
    decode_results(&query.all().await?)
}

/// Decode rows explicitly: a malformed stored row fails the entire read.
pub fn decode_results<T: serde::de::DeserializeOwned>(
    result: &worker::D1Result,
) -> AppResult<Vec<T>> {
    decode_rows(result.results::<Value>()?)
}

fn decode_rows<T: serde::de::DeserializeOwned>(rows: Vec<Value>) -> AppResult<Vec<T>> {
    rows.into_iter()
        .enumerate()
        .map(|(index, row)| decode_row(row, format_args!("D1 row {}", index + 1)))
        .collect()
}

pub(crate) fn decode_row<T: serde::de::DeserializeOwned>(
    row: Value,
    context: impl Display,
) -> AppResult<T> {
    serde_json::from_value(row).map_err(|error| {
        // Serde's Display can include the unexpected field value.
        let reason = match error.classify() {
            Category::Io => "failed to read JSON data",
            Category::Syntax => "invalid JSON syntax",
            Category::Data => "row does not match the expected schema",
            Category::Eof => "incomplete JSON data",
        };
        DatabaseError::invalid_result(
            format_args!("{context}: could not deserialize {}", type_name::<T>()),
            reason,
        )
    })
}

pub async fn run_query<F, T>(query: F, context: &str) -> AppResult<T>
where
    F: Future<Output = WorkerResult<T>>,
{
    query
        .await
        .map_err(|error| DatabaseError::query(context, &error))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn invalid_rows_report_context_without_stored_values() {
        let error = decode_rows::<u32>(vec![json!(7), json!("private row value")])
            .expect_err("invalid row must fail the read");
        let message = error.to_string();
        assert!(message.contains("D1 row 2: could not deserialize u32"));
        assert!(message.contains("row does not match the expected schema"));
        assert!(!message.contains("private row value"));
    }

    #[test]
    fn safe_int_accepts_only_exact_ieee754_integers() {
        assert_eq!(safe_int(0).ok(), Some(0.0));
        assert_eq!(safe_int(MAX_SAFE_D1_INT).ok(), Some(MAX_SAFE_D1_INT as f64));
        assert_eq!(
            safe_int(-MAX_SAFE_D1_INT).ok(),
            Some(-MAX_SAFE_D1_INT as f64)
        );
        assert!(safe_int(MAX_SAFE_D1_INT + 1).is_err());
        assert!(safe_int(-MAX_SAFE_D1_INT - 1).is_err());
    }
}
