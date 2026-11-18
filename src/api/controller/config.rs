use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::IntoResponse as _,
};
use serde_json::{
    Value,
    json,
};

use crate::{
    api::{
        AppState,
        service::{
            setup,
            ui,
        },
    },
    errors::AppResult,
};

#[worker::send]
pub async fn config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<axum::response::Response> {
    let disable_user_registration =
        !setup::registration_enabled(&state, &headers).await?;
    let domain = state.get_domain().to_string();
    let mut features = serde_json::Map::new();
    for flag in [
        "pm-19148-innovation-archive",
        "pm-32413-multi-client-password-management",
        "enable-basic-auth-response",
        "pm-32009-new-item-types",
    ] {
        features.insert(flag.to_owned(), json!(true));
    }
    if let Ok(value) = state.env.var("CLIENT_FEATURE_FLAGS") {
        features.extend(parse_feature_flags(&value.to_string()));
    }
    features.insert(
        "email-verification".into(),
        json!(
            crate::api::service::email::registration_verification_required(
                &state
            )
        ),
    );
    let fill_assist = state
        .env
        .var("FILL_ASSIST_RULES_URL")
        .ok()
        .map(|v| v.to_string())
        .filter(|v| valid_rules_url(v))
        .unwrap_or_else(|| "https://fillassist.bitwarden.com".into());

    let mut response = Json(json!({
        // Note: The clients use this version to handle backwards compatibility concerns
        // This means they expect a version that closely matches the Bitwarden server version
        // We should make sure that we keep this updated when we support the new server features
        // Version history:
        // - Individual cipher key encryption: 2024.2.0
        "version": super::meta::SERVER_VERSION,
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": disable_user_registration,
            "suppressOnboardingInterstitials": ui::suppress_onboarding(&state.env),
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!("{domain}/notifications"),
          "sso": "",
          "fillAssistRules": fill_assist,
          "cloudRegion": null,
        },
        // Bitwarden uses this for the self-hosted servers to indicate the default push technology
        "push": {
          "pushTechnology": 0,
          "vapidPublicKey": null
        },
        "featureStates": features,
        "communication": null,
        "object": "config",
    })).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

const SUPPORTED_FLAGS: &[&str] = &[
    "pm-5594-safari-account-switching",
    "pm-32413-multi-client-password-management",
    "undetermined-cipher-scenario-logic",
    "enable-basic-auth-response",
    "fill-assist-targeting-rules",
    "ssh-agent-v2",
    "windows-desktop-autotype",
    "windows-desktop-autotype-ga",
    "biometrics-sdk-ipc",
    "windows-native-credential-sync",
    "macos-native-credential-sync",
    "pm-27278-v2-password-registration",
    "pm-34171-card-scanner",
    "pm-30529-webauthn-related-origins",
    "pm-32009-new-item-types",
];

fn parse_feature_flags(
    value: &str,
) -> impl Iterator<Item = (String, Value)> + '_ {
    value.split(',').filter_map(|entry| {
        let (name, enabled) = entry
            .trim()
            .split_once('=')
            .unwrap_or((entry.trim(), "true"));
        let name = name.trim();
        if !SUPPORTED_FLAGS.contains(&name) {
            return None;
        }
        let enabled = match enabled.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => return None,
        };
        Some((name.to_owned(), json!(enabled)))
    })
}

fn valid_rules_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        value.trim() == value &&
            url.scheme() == "https" &&
            url.has_host() &&
            url.username().is_empty() &&
            url.password().is_none() &&
            url.query().is_none() &&
            url.fragment().is_none()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_explicit_and_forced_upgrades_cannot_be_advertised() {
        let flags = parse_feature_flags(
            "macos-native-credential-sync,pm-27278-v2-password-registration,\
             windows-native-credential-sync=false,force-upgrade-v2-encryption,\
             pm-30144-sdk-key-rotation,\
             pm-31050-no-logout-key-upgrade-rotation,\
             enable-account-encryption-v2-jit-password-registration,bogus",
        )
        .collect::<serde_json::Map<_, _>>();
        assert_eq!(flags.len(), 3);
        assert_eq!(flags["macos-native-credential-sync"], true);
        assert_eq!(flags["windows-native-credential-sync"], false);
    }

    #[test]
    fn rules_urls_cannot_carry_credentials_queries_or_non_https_schemes() {
        assert!(valid_rules_url("https://rules.example.test/rules.json"));
        for value in [
            "http://rules.example.test",
            "https://user@rules.example.test",
            "https://rules.example.test/?token=x",
            "https://rules.example.test/#x",
            " https://rules.example.test",
        ] {
            assert!(!valid_rules_url(value));
        }
    }
}
