use std::sync::OnceLock;

use axum::http::HeaderValue;
use worker::Env;

use crate::errors::{
    AppError,
    AppResult,
    ConfigError,
};

/// Load configuration from environment (cached in static).
pub static CONFIG: OnceLock<Config> = OnceLock::new();

/// Load configuration from environment (cached in static).
pub fn load_config(env: &Env) -> AppResult<&'static Config> {
    CONFIG.get_or_try_init(|| {
        Config::from_env(env).map_err(|e| {
            AppError::Worker(worker::Error::RustError(format!(
                "config load error: {e}"
            )))
        })
    })
}

/// Application configuration loaded from Worker environment variables and
/// secrets.
#[derive(Clone, Debug)]
pub struct Config {
    pub domain: String,

    /// Allowed CORS origins (comma-separated in env var `ALLOWED_ORIGINS`).
    pub allowed_origins: Vec<HeaderValue>,

    /// JWT signing secret (from secret `JWT_SECRET`).
    pub jwt_secret: String,

    pub jwt_duration_seconds: u64,

    pub jwt_refresh_secret: String,

    /// KDF iterations for client-side key derivation (default: 600000 for
    /// Argon2id).
    pub kdf_iterations: u32,

    /// KDF memory in MB for Argon2id (default: 64).
    pub kdf_memory: u32,

    /// KDF parallelism for Argon2id (default: 4).
    pub kdf_parallelism: u32,

    /// Whether user registration is disabled (from
    /// `DISABLE_USER_REGISTRATION`).
    pub disable_user_registration: bool,

    /// Import batch size (from `IMPORT_BATCH_SIZE`).
    pub import_batch_size: u32,

    /// Whether TOTP validation should allow ±1 time step drift.
    pub authenticator_disable_time_drift: bool,

    pub allowed_emails: Option<Vec<String>>,
}

impl Config {
    pub fn from_env(env: &Env) -> Result<Self, AppError> {
        // Helper for getting with default
        let get_var_or = |key: &str, default: &str| -> String {
            env.var(key)
                .map_or_else(|_| default.to_string(), |v| v.to_string())
        };

        let jwt_secret = env
            .secret("JWT_SECRET")
            .map_err(|e| {
                log::error!("JWT_SECRET load failed: {e}");
                AppError::Config(ConfigError::Missing(e.to_string()))
            })?
            .to_string();

        if jwt_secret.is_empty() {
            return Err(AppError::Config(ConfigError::Missing(
                "JWT_SECRET".to_string(),
            )));
        }

        let jwt_refresh_secret = env
            .secret("JWT_REFRESH_SECRET")
            .map_err(|e| {
                log::error!("JWT_REFRESH_SECRET load failed: {e}");
                AppError::Config(ConfigError::Missing(e.to_string()))
            })?
            .to_string();

        if jwt_refresh_secret.is_empty() {
            return Err(AppError::Config(ConfigError::Missing(
                "JWT_REFRESH_SECRET".to_string(),
            )));
        }

        let domain = env
            .var("DOMAIN")
            .map_err(|e| {
                log::error!("DOMAIN load failed: {e}");
                AppError::Config(ConfigError::Missing("DOMAIN".to_string()))
            })?
            .to_string();

        let allowed_origins = get_var_or("ALLOWED_ORIGINS", "")
            .split(',')
            .filter_map(|s| HeaderValue::from_str(s.trim()).ok())
            .collect();

        let disable_user_registration = env
            .var("DISABLE_USER_REGISTRATION")
            .ok()
            .map(|value| value.to_string().to_lowercase());

        let import_batch_size = get_var_or("IMPORT_BATCH_SIZE", "30");

        let authenticator_disable_time_drift = env
            .var("AUTHENTICATOR_DISABLE_TIME_DRIFT")
            .ok()
            .map(|value| value.to_string().to_lowercase());

        let allowed_emails = match env.secret("ALLOWED_EMAILS") {
            Ok(secret) => {
                let emails_str = secret.to_string();
                let emails: Vec<String> = emails_str
                    .lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();
                Some(emails)
            }
            Err(_) => None,
        };

        Ok(Self {
            domain,
            allowed_origins,
            jwt_secret,
            jwt_refresh_secret,
            jwt_duration_seconds: get_var_or("JWT_DURATION_SECONDS", "3600")
                .parse()
                .unwrap_or(3600),
            kdf_iterations: get_var_or("KDF_ITERATIONS", "600000")
                .parse()
                .unwrap_or(600_000),
            kdf_memory: get_var_or("KDF_MEMORY", "64").parse().unwrap_or(64),
            kdf_parallelism: get_var_or("KDF_PARALLELISM", "4")
                .parse()
                .unwrap_or(4),
            disable_user_registration: disable_user_registration.is_none_or(
                |value| !matches!(value.as_str(), "1" | "true" | "yes" | "on"),
            ),
            import_batch_size: import_batch_size.parse().unwrap_or(30),
            authenticator_disable_time_drift: authenticator_disable_time_drift
                .is_none_or(|value| {
                    !matches!(value.as_str(), "1" | "true" | "yes" | "on")
                }),

            allowed_emails,
        })
    }
}
