//! Server discovery, health, usage and compatibility endpoints.
use std::collections::BTreeMap;

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::IntoResponse as _,
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    api::{
        AppState,
        common::response::{
            ApiResponse,
            EmptyListResponse,
        },
    },
    errors::AppResult,
    models::health,
    service::{
        identity::{
            session::Claims,
            setup,
        },
        web_vault_ui,
    },
};

const SERVER_VERSION: &str = "2026.6.0";

/// Compatibility discovery for capabilities outside the personal-vault scope.
#[worker::send]
pub(in crate::api) async fn empty_personal_list(
    _claims: Claims,
) -> ApiResponse<EmptyListResponse> {
    ApiResponse(EmptyListResponse::new())
}

/// GET /api/now
///
/// Mirrors vaultwarden's `/api/now`: returns current UTC timestamp as an
/// RFC3339 string.
#[worker::send]
pub(in crate::api) async fn current_time() -> ApiResponse<String> {
    ApiResponse(crate::utils::time::now_rfc3339())
}

/// GET /api/alive
///
/// Simple healthcheck. Vaultwarden uses this to also verify DB connectivity.
#[worker::send]
pub(in crate::api) async fn health_check(
    State(state): State<AppState>,
) -> AppResult<ApiResponse<String>> {
    // Verify D1 binding is present + basic query works.
    let db = state.database();
    health::ping(db).await?;
    Ok(current_time().await)
}

/// GET /api/version
///
/// Returns a Bitwarden-server-like version string. Clients sometimes call this
/// endpoint.
#[worker::send]
pub(in crate::api) async fn server_version() -> ApiResponse<&'static str> {
    ApiResponse(SERVER_VERSION)
}

/// GET /emergency-access/trusted
///
/// Returns the list of trusted emergency access contacts (grantees) for the
/// current user. This is a stub implementation that always returns an empty
/// list since emergency access is not supported in this minimal
/// Bitwarden-compatible implementation.
///
/// In vaultwarden, when `emergency_access_allowed` is disabled, it returns an
/// empty list. We follow the same pattern here.
#[worker::send]
pub(in crate::api) async fn empty_emergency_contacts()
-> ApiResponse<EmptyListResponse> {
    ApiResponse(EmptyListResponse::new())
}

#[worker::send]
pub(in crate::api) async fn accept_events(
    _claims: Claims,
    Json(_events): Json<Vec<Value>>,
) {
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientConfigResponse<'a> {
    version:        &'static str,
    git_hash:       Option<&'static str>,
    server:         ClientServer,
    settings:       ClientSettings,
    environment:    ClientEnvironment<'a>,
    push:           ClientPush,
    feature_states: BTreeMap<String, bool>,
    communication:  (),
    object:         &'static str,
}

#[derive(Serialize)]
struct ClientServer {
    name: &'static str,
    url:  &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientSettings {
    disable_user_registration:         bool,
    suppress_onboarding_interstitials: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientEnvironment<'a> {
    vault:             &'a str,
    api:               String,
    identity:          String,
    notifications:     String,
    sso:               &'static str,
    fill_assist_rules: String,
    cloud_region:      (),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientPush {
    push_technology:  u8,
    vapid_public_key: (),
}

#[worker::send]
pub(in crate::api) async fn client_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<axum::response::Response> {
    let registration_disabled =
        !setup::registration_enabled(&state, &headers).await?;
    let domain = state.domain();
    let mut features = ["pm-19148-innovation-archive"]
        .into_iter()
        .chain(DEFAULT_ON_FLAGS.iter().copied())
        .map(|flag| (flag.to_owned(), true))
        .collect::<BTreeMap<_, _>>();
    if let Ok(value) = state.env.var("CLIENT_FEATURE_FLAGS") {
        features.extend(parse_feature_flags(&value.to_string()));
    }
    features.insert(
        "email-verification".into(),
        crate::service::identity::email::registration_verification_required(
            &state,
        ),
    );
    let fill_assist = state
        .env
        .var("FILL_ASSIST_RULES_URL")
        .ok()
        .map(|v| v.to_string())
        .filter(|v| is_valid_fill_assist_url(v))
        .unwrap_or_else(|| "https://fillassist.bitwarden.com".into());

    let mut response = ApiResponse(ClientConfigResponse {
        // Clients use this version to select compatible server features.
        version:        SERVER_VERSION,
        git_hash:       option_env!("GIT_REV"),
        server:         ClientServer {
            name: "Vaultwarden",
            url:  "https://github.com/dani-garcia/vaultwarden",
        },
        settings:       ClientSettings {
            disable_user_registration:         registration_disabled,
            suppress_onboarding_interstitials:
                web_vault_ui::suppress_onboarding(&state.env),
        },
        environment:    ClientEnvironment {
            vault:             domain,
            api:               format!("{domain}/api"),
            identity:          format!("{domain}/identity"),
            notifications:     format!("{domain}/notifications"),
            sso:               "",
            fill_assist_rules: fill_assist,
            cloud_region:      (),
        },
        // Bitwarden's default push technology for self-hosted servers.
        push:           ClientPush {
            push_technology:  0,
            vapid_public_key: (),
        },
        feature_states: features,
        communication:  (),
        object:         "config",
    })
    .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

const DEFAULT_ON_FLAGS: &[&str] = &[
    "pm-32413-multi-client-password-management",
    "enable-basic-auth-response",
    "pm-32009-new-item-types",
];
const OPTIONAL_FLAGS: &[&str] = &[
    "pm-5594-safari-account-switching",
    "undetermined-cipher-scenario-logic",
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
];

fn parse_feature_flags(
    value: &str,
) -> impl Iterator<Item = (String, bool)> + '_ {
    value.split(',').filter_map(|entry| {
        let (name, enabled) = entry.split_once('=').unwrap_or((entry, "true"));
        let name = name.trim();
        if !DEFAULT_ON_FLAGS.contains(&name) && !OPTIONAL_FLAGS.contains(&name)
        {
            return None;
        }
        let enabled = match enabled.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => return None,
        };
        Some((name.to_owned(), enabled))
    })
}

fn is_valid_fill_assist_url(value: &str) -> bool {
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
    fn client_flags_only_override_supported_configurable_flags() {
        let flags =
            parse_feature_flags(
                "macos-native-credential-sync,\
                 pm-27278-v2-password-registration,\
                 windows-native-credential-sync=false,\
                 force-upgrade-v2-encryption,pm-30144-sdk-key-rotation,\
                 pm-31050-no-logout-key-upgrade-rotation,\
                 enable-account-encryption-v2-jit-password-registration,bogus,\
                 +             \
                 pm-19148-innovation-archive=false,\
                 pm-32009-new-item-types=FALSE",
            )
            .collect::<BTreeMap<_, _>>();
        assert_eq!(flags.len(), 4);
        assert!(flags["macos-native-credential-sync"]);
        assert!(!flags["windows-native-credential-sync"]);
        assert!(!flags["pm-32009-new-item-types"]);
    }

    #[test]
    fn rules_urls_cannot_carry_credentials_queries_or_non_https_schemes() {
        assert!(is_valid_fill_assist_url(
            "https://rules.example.test/rules.json"
        ));
        for value in [
            "http://rules.example.test",
            "https://user@rules.example.test",
            "https://rules.example.test/?token=x",
            "https://rules.example.test/#x",
            " https://rules.example.test",
        ] {
            assert!(!is_valid_fill_assist_url(value));
        }
    }
}
