use std::sync::Mutex;

use axum::http::HeaderMap;
use worker::Env;

use crate::errors::{AppError, AppResult};

const FAILURE_WARNING_INTERVAL_SECONDS: i64 = 60;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
enum Limiter {
    Login,
    SendAccess,
}

impl Limiter {
    const fn binding(self) -> &'static str {
        match self {
            Self::Login => "LOGIN_RATE_LIMITER",
            Self::SendAccess => "SEND_ACCESS_RATE_LIMITER",
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
enum LimiterFailure {
    BindingUnavailable,
    RequestFailed,
}

impl LimiterFailure {
    const fn description(self) -> &'static str {
        match self {
            Self::BindingUnavailable => "binding unavailable",
            Self::RequestFailed => "request failed",
        }
    }
}

#[derive(Default)]
struct FailureWarningThrottle {
    last_reported_at_seconds: [[Option<i64>; 2]; 2],
}

impl FailureWarningThrottle {
    const fn should_report(&mut self, limiter: Limiter, failure: LimiterFailure, now: i64) -> bool {
        let last_reported_at_seconds =
            &mut self.last_reported_at_seconds[limiter as usize][failure as usize];
        if let Some(previous) = *last_reported_at_seconds
            && now >= previous
            && now.saturating_sub(previous) < FAILURE_WARNING_INTERVAL_SECONDS
        {
            return false;
        }
        *last_reported_at_seconds = Some(now);
        true
    }
}

// A fixed-size per-isolate gate prevents an unavailable binding from logging
// once per request. Neither keys nor provider errors enter this state or logs.
static FAILURE_WARNING_THROTTLE: Mutex<FailureWarningThrottle> =
    Mutex::new(FailureWarningThrottle {
        last_reported_at_seconds: [[None; 2]; 2],
    });

fn report_failure(limiter: Limiter, failure: LimiterFailure) {
    let label = limiter.binding();
    let should_report = FAILURE_WARNING_THROTTLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .should_report(limiter, failure, crate::utils::time::now_seconds());
    if should_report {
        log::warn!(target: "auth", "Rate limiter {label} {}; rejecting protected request", failure.description());
    }
}

fn rate_limit_result(outcome: Result<bool, LimiterFailure>) -> AppResult<()> {
    match outcome {
        Ok(true) => Ok(()),
        Ok(false) => Err(AppError::TooManyRequests {
            message: "Too many attempts. Please try again later.".into(),
        }),
        // Missing protection is not permission to make unlimited password or
        // OTP guesses. Unrelated reads and health checks do not use this gate.
        Err(_) => Err(AppError::service_unavailable(
            "Rate limiting service is unavailable",
        )),
    }
}

pub fn client_ip(headers: &HeaderMap) -> &str {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
}

pub async fn check_auth_attempt(env: &Env, rate_limit_key: String) -> AppResult<()> {
    check_rate_limit_binding(env, rate_limit_key, Limiter::Login).await
}

pub async fn check_send_access(env: &Env, rate_limit_key: String) -> AppResult<()> {
    check_rate_limit_binding(env, rate_limit_key, Limiter::SendAccess).await
}

async fn check_rate_limit_binding(
    env: &Env,
    rate_limit_key: String,
    limiter: Limiter,
) -> AppResult<()> {
    let outcome = match env.rate_limiter(limiter.binding()) {
        Ok(rate_limiter) => rate_limiter
            .limit(rate_limit_key)
            .await
            .map(|outcome| outcome.success)
            .map_err(|_error| LimiterFailure::RequestFailed),
        Err(_) => Err(LimiterFailure::BindingUnavailable),
    };
    if let Err(failure) = outcome {
        report_failure(limiter, failure);
    }
    rate_limit_result(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_denials_and_failures_never_allow_unlimited_attempts() {
        assert!(rate_limit_result(Ok(true)).is_ok());
        assert!(matches!(
            rate_limit_result(Ok(false)),
            Err(AppError::TooManyRequests { .. })
        ));
        for failure in [
            LimiterFailure::BindingUnavailable,
            LimiterFailure::RequestFailed,
        ] {
            assert!(matches!(
                rate_limit_result(Err(failure)),
                Err(AppError::ServiceUnavailable { .. })
            ));
        }
    }

    #[test]
    fn failure_warnings_are_bounded_per_binding_and_failure_kind() {
        let mut warnings = FailureWarningThrottle::default();
        for limiter in [Limiter::Login, Limiter::SendAccess] {
            for failure in [
                LimiterFailure::BindingUnavailable,
                LimiterFailure::RequestFailed,
            ] {
                assert!(warnings.should_report(limiter, failure, 100));
                assert!(!warnings.should_report(limiter, failure, 100));
                assert!(!warnings.should_report(limiter, failure, 159));
                assert!(warnings.should_report(limiter, failure, 160));
                assert!(!warnings.should_report(limiter, failure, 161));
            }
        }
        // A clock correction must not silence warnings until the old time.
        let limiter = Limiter::Login;
        let failure = LimiterFailure::BindingUnavailable;
        assert!(warnings.should_report(limiter, failure, 90));
        assert!(!warnings.should_report(limiter, failure, 100));
        assert!(warnings.should_report(limiter, failure, 150));
    }
}
