//! Initialize application logging with a single global level.
use log::LevelFilter;
use worker::Env;

use super::env::env_text;

pub(crate) fn init(env: &Env) {
    let value = env_text(env, "LOG_LEVEL");
    if let Some(level) =
        global_level(value.as_deref().unwrap_or_default()).to_level()
    {
        let _ = console_log::init_with_level(level);
    }
}

fn global_level(value: &str) -> LevelFilter {
    // Keep the global level from legacy values with a comma-separated suffix.
    let global = value.split_once(',').map_or(value, |(global, _)| global);
    global.trim().parse().unwrap_or(LevelFilter::Info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_global_level_with_an_info_default() {
        for (value, expected) in [
            ("off", LevelFilter::Off),
            ("error", LevelFilter::Error),
            ("warn", LevelFilter::Warn),
            ("info", LevelFilter::Info),
            ("  DeBuG  ", LevelFilter::Debug),
            ("trace", LevelFilter::Trace),
            ("", LevelFilter::Info),
            ("invalid", LevelFilter::Info),
            ("off,auth=debug", LevelFilter::Off),
            ("warn,api=off", LevelFilter::Warn),
        ] {
            assert_eq!(global_level(value), expected);
        }
    }
}
