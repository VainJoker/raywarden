//! Global and fixed-module filters for the existing application log records.
use std::sync::OnceLock;

use log::{
    Level,
    LevelFilter,
    Log,
    Metadata,
    Record,
};
use worker::Env;

#[derive(Clone, Copy, Debug)]
enum Module {
    Auth,
    Api,
    Db,
    External,
    Notify,
}

impl Module {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "auth" => Some(Self::Auth),
            "api" => Some(Self::Api),
            "db" => Some(Self::Db),
            "external" => Some(Self::External),
            "notify" => Some(Self::Notify),
            _ => None,
        }
    }

    /// Explicit targets take precedence; ordinary macros use their Rust module.
    fn for_record(target: &str, module_path: Option<&str>) -> Option<Self> {
        Self::parse(target.split("::").next().unwrap_or(target))
            .or_else(|| Self::for_path(target))
            .or_else(|| module_path.and_then(Self::for_path))
    }

    fn for_path(path: &str) -> Option<Self> {
        let path =
            path.strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))?;
        let mut parts = path.split("::");
        match parts.next()? {
            "models" => Some(Self::Db),
            "infra" => match parts.next()? {
                "db" => Some(Self::Db),
                "crypto" | "jwt" | "jwt_keys" | "webauthn" => Some(Self::Auth),
                "storage" => Some(Self::External),
                "delivery" | "admin_notify" => Some(Self::Notify),
                _ => None,
            },
            "durable" => match parts.next()? {
                "notify_do" => Some(Self::Notify),
                "heavy_do" => Some(Self::Api),
                _ => None,
            },
            "send" => match parts.next() {
                Some("store" | "rotation") => Some(Self::Db),
                _ => Some(Self::Api),
            },
            "api" => {
                if matches!(parts.next(), Some("controller" | "service")) {
                    match parts.next() {
                        Some(
                            "accounts" | "account_keys" | "api_keys" |
                            "api_key" | "auth" | "auth_requests" | "claims" |
                            "devices" | "email" | "identity" | "kdf" | "rate" |
                            "sessions" | "turnstile" | "twofactor" |
                            "webauth" | "webauthn",
                        ) => return Some(Self::Auth),
                        Some("notifications" | "push") => {
                            return Some(Self::Notify);
                        }
                        Some("meta") => return Some(Self::External),
                        _ => {}
                    }
                }
                Some(Self::Api)
            }
            "dispatch" => Some(Self::Api),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Filter {
    global:  LevelFilter,
    modules: [Option<LevelFilter>; 5],
}

impl Filter {
    /// Invalid/missing global levels use info. Ignore invalid overrides and
    /// unknown modules; the last valid override for a known module wins.
    fn parse(value: Option<&str>) -> Self {
        let mut parts = value.unwrap_or_default().split(',');
        let global = parts
            .next()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(LevelFilter::Info);
        let mut filter = Self {
            global,
            modules: [None; 5],
        };
        for part in parts {
            let Some((module, level)) = part.split_once('=') else {
                continue;
            };
            let Some(module) =
                Module::parse(&module.trim().to_ascii_lowercase())
            else {
                continue;
            };
            if let Ok(level) = level.trim().parse() {
                filter.modules[module as usize] = Some(level);
            }
        }
        filter
    }

    fn max_level(&self) -> LevelFilter {
        self.modules
            .iter()
            .flatten()
            .copied()
            .fold(self.global, std::cmp::max)
    }

    fn allows(
        &self,
        level: Level,
        target: &str,
        module_path: Option<&str>,
    ) -> bool {
        let threshold = Module::for_record(target, module_path)
            .and_then(|module| self.modules[module as usize])
            .unwrap_or(self.global);
        level <= threshold
    }
}

struct ModuleLogger {
    filter: Filter,
}

impl Log for ModuleLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.filter
            .allows(metadata.level(), metadata.target(), None)
    }

    fn log(&self, record: &Record<'_>) {
        if self.filter.allows(
            record.level(),
            record.target(),
            record.module_path(),
        ) {
            // Keep the existing console formatter; do not include environment
            // values, request data or any additional context in the output.
            console_log::log(record);
        }
    }

    fn flush(&self) {}
}

static LOGGER: OnceLock<ModuleLogger> = OnceLock::new();

/// Called by the shared once-per-instance initializer used by fetch, cron and
/// DOs.
pub(crate) fn init(env: &Env) {
    let logger = LOGGER.get_or_init(|| {
        let value = env.var("LOG_LEVEL").ok().map(|value| value.to_string());
        ModuleLogger {
            filter: Filter::parse(value.as_deref()),
        }
    });
    if log::set_logger(logger).is_ok() {
        // The facade must retain records enabled by a more verbose override,
        // including when the global level is off.
        log::set_max_level(logger.filter.max_level());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logger(value: &str) -> ModuleLogger {
        ModuleLogger {
            filter: Filter::parse(Some(value)),
        }
    }

    fn enabled(logger: &ModuleLogger, level: Level, target: &str) -> bool {
        logger.enabled(&Metadata::builder().level(level).target(target).build())
    }

    #[test]
    fn single_levels_and_invalid_global_defaults_are_preserved() {
        for (value, expected) in [
            ("off", LevelFilter::Off),
            ("error", LevelFilter::Error),
            ("warn", LevelFilter::Warn),
            ("info", LevelFilter::Info),
            ("debug", LevelFilter::Debug),
            ("trace", LevelFilter::Trace),
            ("  DeBuG  ", LevelFilter::Debug),
        ] {
            let filter = Filter::parse(Some(value));
            assert_eq!(filter.global, expected);
            assert_eq!(filter.max_level(), expected);
        }
        for value in [None, Some(""), Some("invalid")] {
            assert_eq!(Filter::parse(value).global, LevelFilter::Info);
        }
    }

    #[test]
    fn overrides_filter_existing_application_module_paths() {
        let logger = logger("info,auth=debug,external=warn");
        assert!(enabled(
            &logger,
            Level::Debug,
            "raywarden::api::controller::identity"
        ));
        assert!(!enabled(
            &logger,
            Level::Debug,
            "raywarden::api::controller::ciphers"
        ));
        assert!(!enabled(
            &logger,
            Level::Info,
            "raywarden::infra::storage::cleanup"
        ));
        assert!(enabled(
            &logger,
            Level::Warn,
            "raywarden::infra::storage::cleanup"
        ));
        assert_eq!(logger.filter.max_level(), LevelFilter::Debug);
    }

    #[test]
    fn all_five_modules_classify_current_call_sites() {
        for (module, paths) in [
            (
                "auth",
                &[
                    "raywarden::api::controller::accounts",
                    "raywarden::api::controller::twofactor",
                    "raywarden::api::service::auth",
                    "raywarden::infra::jwt_keys",
                ][..],
            ),
            (
                "api",
                &[
                    "raywarden::api::controller::sync",
                    "raywarden::api::service::maintenance",
                    "raywarden::send::http",
                    "raywarden::durable::heavy_do",
                ][..],
            ),
            (
                "db",
                &[
                    "raywarden::infra::db",
                    "raywarden::models::cipher::store",
                    "raywarden::models::twofactor",
                    "raywarden::send::store",
                ][..],
            ),
            (
                "external",
                &[
                    "raywarden::infra::storage",
                    "raywarden::infra::storage::cleanup",
                    "raywarden::api::controller::meta",
                ][..],
            ),
            (
                "notify",
                &[
                    "raywarden::infra::delivery",
                    "raywarden::infra::admin_notify",
                    "raywarden::api::service::notifications",
                    "raywarden::api::service::push",
                    "raywarden::durable::notify_do",
                ][..],
            ),
        ] {
            let logger = logger(&format!("off,{module}=debug"));
            for path in paths {
                assert!(enabled(&logger, Level::Debug, path), "{path}");
                assert!(!enabled(&logger, Level::Trace, path), "{path}");
            }
        }
    }

    #[test]
    fn global_off_keeps_enabled_overrides_and_their_maximum_level() {
        let logger = logger("off,auth=debug,notify=trace");
        assert_eq!(logger.filter.max_level(), LevelFilter::Trace);
        assert!(enabled(&logger, Level::Debug, "auth"));
        assert!(enabled(&logger, Level::Trace, "notify::webhook"));
        assert!(!enabled(&logger, Level::Error, "api"));
        assert!(!enabled(&logger, Level::Error, "unknown_dependency"));
        assert_eq!(
            Filter::parse(Some("off,auth=off")).max_level(),
            LevelFilter::Off
        );
        assert_eq!(
            Filter::parse(Some("trace,auth=off")).max_level(),
            LevelFilter::Trace
        );
    }

    #[test]
    fn module_off_does_not_disable_other_modules() {
        let logger = logger("info,auth=off");
        assert!(!enabled(&logger, Level::Error, "auth"));
        assert!(enabled(&logger, Level::Info, "api"));
        assert!(enabled(&logger, Level::Info, "db"));
        assert!(!enabled(&logger, Level::Debug, "notify"));
    }

    #[test]
    fn unknown_and_invalid_tokens_are_ignored_and_last_valid_override_wins() {
        let logger = logger(
            "invalid,AUTH=DeBuG,auth=nope,unknown=trace,=trace,db=warn,db=off,\
             noise,notify=warn=trace",
        );
        assert_eq!(logger.filter.global, LevelFilter::Info);
        assert_eq!(logger.filter.max_level(), LevelFilter::Debug);
        assert!(enabled(&logger, Level::Debug, "auth"));
        assert!(!enabled(&logger, Level::Error, "db"));
        assert!(!enabled(&logger, Level::Debug, "notify"));
        assert!(!enabled(&logger, Level::Trace, "unknown"));
    }

    #[test]
    fn record_module_path_is_used_when_the_target_is_not_a_named_module() {
        let logger = logger("off,auth=debug");
        let record = Record::builder()
            .level(Level::Debug)
            .target("custom_operation")
            .module_path(Some("raywarden::api::service::claims"))
            .build();
        assert!(logger.filter.allows(
            record.level(),
            record.target(),
            record.module_path()
        ));
        // An explicit fixed-module target overrides the source classification.
        assert!(!logger.filter.allows(
            Level::Debug,
            "api",
            Some("raywarden::api::service::claims")
        ));
    }

    #[test]
    fn names_match_module_boundaries_and_unrelated_crates_use_the_global_level()
    {
        let logger = logger("off,auth=trace,api=trace,db=trace");
        for target in [
            "authentication",
            "database",
            "raywarden::models_extra",
            "raywarden_extra::api::controller::identity",
            "dependency::api",
        ] {
            assert!(!enabled(&logger, Level::Error, target), "{target}");
        }
        // A filtered record never reaches the browser-only console sink.
        logger.log(
            &Record::builder()
                .level(Level::Error)
                .target("database")
                .build(),
        );
    }
}
