pub mod admin;
pub(crate) mod hub;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rmpv::Value as MsgValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use worker::{
    AbortSignal, Env, Fetch, Method, Request, RequestInit, RequestRedirect, wasm_bindgen::JsValue,
};

use self::hub::{HubError, HubResult};
use crate::{
    errors::{AppError, AppResult, JwtError},
    infra::{db, jwt},
};

pub const FANOUT_TOKEN_HEADER: &str = "x-raywarden-notify-token";
pub const FANOUT_PATH: &str = "/internal/fanout";
pub const PING: [u8; 3] = [2, 0x91, 6];
pub const HANDSHAKE_RESPONSE: [u8; 3] = [b'{', b'}', 0x1e];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,
    SyncVault = 5,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncSettings = 10,
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
    AuthRequest = 15,
    AuthRequestResponse = 16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FanoutSelector {
    User {
        user_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        logout_scope: Option<LogoutScope>,
    },
    Anonymous {
        request_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LogoutScope {
    Stamp { value: String },
    BeforeRevision { value: String, stamp: String },
}

pub(crate) fn user_tag(user_id: &str) -> String {
    format!("u:{user_id}")
}

pub(crate) fn anonymous_tag(request_id: &str) -> String {
    format!("a:{request_id}")
}

impl FanoutSelector {
    pub fn tag(&self) -> String {
        match self {
            Self::User { user_id, .. } => user_tag(user_id),
            Self::Anonymous { request_id } => anonymous_tag(request_id),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FanoutRequest {
    pub selector: FanoutSelector,
    pub message: String,
    pub logout: bool,
}

#[derive(Serialize, Deserialize)]
struct FanoutClaims {
    exp: i64,
    nbf: i64,
    iat: i64,
    scope: String,
    body_hash: String,
}

pub async fn issue_fanout_token(env: &Env, body: &str) -> AppResult<String> {
    let now = crate::utils::time::now_seconds();
    let claims = FanoutClaims {
        exp: now + 30,
        nbf: now,
        iat: now,
        scope: "notifications.internal".to_string(),
        body_hash: hex::encode(Sha256::digest(body.as_bytes())),
    };
    let secret = crate::service::identity::jwt_keys::load(env, &db::binding(env)?)
        .await?
        .access_secret;
    jwt::encode(&claims, secret.as_bytes())
}

async fn verify_fanout_token(env: &Env, body: &str, token: &str) -> HubResult<()> {
    let unavailable = |operation| {
        log::warn!("Notification fanout verification failed to {operation}");
        HubError::Unavailable
    };
    let db = db::binding(env).map_err(|_error| unavailable("resolve D1 binding DB"))?;
    let secret = crate::service::identity::jwt_keys::load(env, &db)
        .await
        .map_err(|_error| unavailable("load JWT signing keys"))?
        .access_secret;
    let options = jwt::ValidationOptions {
        leeway_seconds: 0,
        ..Default::default()
    };
    let claims = jwt::decode::<FanoutClaims>(token, secret.as_bytes(), &options).map_err(
        |error| match error {
            JwtError::CryptoError(_) => unavailable("verify JWT signature"),
            _ => HubError::Forbidden,
        },
    )?;
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    if claims.scope == "notifications.internal"
        && crate::utils::constant_time_eq(claims.body_hash.as_bytes(), digest.as_bytes())
    {
        Ok(())
    } else {
        Err(HubError::Forbidden)
    }
}

pub fn is_signalr_handshake(message: &str) -> bool {
    #[derive(Deserialize)]
    struct Handshake {
        protocol: String,
        version: i32,
    }
    if message.len() > 1024 {
        return false;
    }
    let message = message.strip_suffix('\u{1e}').unwrap_or(message);
    serde_json::from_str::<Handshake>(message)
        .is_ok_and(|h| h.protocol == "messagepack" && h.version == 1)
}

fn encode_signalr_frame(value: &MsgValue) -> AppResult<Vec<u8>> {
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, value)
        .map_err(|error| AppError::internal_debug("Failed to encode SignalR frame", error))?;
    let mut size = payload.len();
    let mut result = Vec::with_capacity(size + 5);
    loop {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if size == 0 {
            break;
        }
    }
    result.extend(payload);
    Ok(result)
}

fn encode_messagepack_timestamp(date: &str) -> MsgValue {
    let date = crate::utils::time::parse(date).unwrap_or_else(|_| crate::utils::time::now());
    // MessagePack uses a floor-second and an unsigned nanosecond remainder.
    // Jiff's subseconds are signed for dates before the Unix epoch.
    let total = date.as_nanosecond();
    let seconds = total.div_euclid(1_000_000_000) as i64;
    let nanos = total.rem_euclid(1_000_000_000) as u32;
    if (0..(1_i64 << 34)).contains(&seconds) {
        let bits = (u64::from(nanos) << 34) | seconds as u64;
        MsgValue::Ext(-1, bits.to_be_bytes().to_vec())
    } else {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend(nanos.to_be_bytes());
        bytes.extend(seconds.to_be_bytes());
        MsgValue::Ext(-1, bytes)
    }
}

fn encode_invocation(target: &str, message: Vec<(MsgValue, MsgValue)>) -> AppResult<Vec<u8>> {
    encode_signalr_frame(&MsgValue::Array(vec![
        1.into(),
        MsgValue::Map(vec![]),
        MsgValue::Nil,
        target.into(),
        MsgValue::Array(vec![MsgValue::Map(message)]),
    ]))
}

fn encode_update_message(
    update_type: UpdateType,
    payload: Vec<(MsgValue, MsgValue)>,
    context_id: Option<&str>,
) -> AppResult<Vec<u8>> {
    encode_invocation("ReceiveMessage", vec![
        (
            "ContextId".into(),
            context_id.map_or(MsgValue::Nil, Into::into),
        ),
        ("Type".into(), (update_type as i32).into()),
        ("Payload".into(), MsgValue::Map(payload)),
    ])
}

fn account_payload(user_id: &str, date: &str) -> Vec<(MsgValue, MsgValue)> {
    vec![
        ("UserId".into(), user_id.into()),
        ("Date".into(), encode_messagepack_timestamp(date)),
    ]
}

fn item_payload(user_id: &str, id: &str) -> Vec<(MsgValue, MsgValue)> {
    vec![("Id".into(), id.into()), ("UserId".into(), user_id.into())]
}

async fn publish_user(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    payload: Vec<(MsgValue, MsgValue)>,
    context_id: Option<&str>,
    logout_scope: Option<LogoutScope>,
) {
    let message = encode_update_message(kind, payload, context_id);
    let selector = FanoutSelector::User {
        user_id: user_id.to_owned(),
        logout_scope,
    };
    publish(env, selector, message, kind == UpdateType::LogOut).await;
}

async fn publish(env: &Env, selector: FanoutSelector, message: AppResult<Vec<u8>>, logout: bool) {
    let channel = match selector {
        FanoutSelector::User { .. } => "WebSocket",
        FanoutSelector::Anonymous { .. } => "Anonymous",
    };
    match message {
        Ok(bytes) => {
            if let Err(error) = fanout(env, selector, &bytes, logout).await {
                log::warn!("{channel} notification failed: {error:?}");
            }
        }
        Err(error) => log::warn!("{channel} notification encoding failed: {error:?}"),
    }
}

async fn fanout(env: &Env, selector: FanoutSelector, bytes: &[u8], logout: bool) -> AppResult<()> {
    let Ok(namespace) = env.durable_object("notifydo") else {
        return Ok(());
    };
    let stub = namespace.id_from_name("global")?.get_stub()?;
    let body = serde_json::to_string(&FanoutRequest {
        selector,
        message: STANDARD.encode(bytes),
        logout,
    })
    .map_err(AppError::internal_json(
        "Failed to serialize notification fanout request",
    ))?;
    let token = issue_fanout_token(env, &body).await?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(JsValue::from_str(&body)));
    let mut request =
        Request::new_with_init(&format!("https://notify.internal{FANOUT_PATH}"), &init)?;
    request
        .headers_mut()?
        .set("content-type", "application/json")?;
    request.headers_mut()?.set(FANOUT_TOKEN_HEADER, &token)?;
    let response = stub.fetch_with_request(request).await?;
    let status = response.status_code();
    if !(200..300).contains(&status) {
        return Err(AppError::internal_with_context(
            "Realtime notification fanout failed",
            format_args!("HTTP {status}"),
        ));
    }
    Ok(())
}

/// Deliver JSON over HTTPS with no redirects.
pub(super) async fn post_json(url: &str, body: Value, bearer: Option<&str>) -> AppResult<()> {
    if !url.starts_with("https://") {
        return Err(AppError::bad_request(
            "Notification delivery requires an HTTPS URL",
        ));
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_redirect(RequestRedirect::Manual)
        .with_body(Some(JsValue::from_str(&body.to_string())));
    let mut request = Request::new_with_init(url, &init)?;
    request
        .headers_mut()?
        .set("Content-Type", "application/json")?;
    if let Some(token) = bearer {
        request
            .headers_mut()?
            .set("Authorization", &format!("Bearer {token}"))?;
    }
    let signal = AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(5_000));
    let response = Fetch::Request(request).send_with_signal(&signal).await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::bad_request("Notification delivery failed"));
    }
    Ok(())
}

pub async fn publish_user_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    date: &str,
    context_id: Option<&str>,
) {
    publish_user(
        env,
        user_id,
        kind,
        account_payload(user_id, date),
        context_id,
        None,
    )
    .await;
}

pub(crate) async fn publish_deleted_account(env: &Env, user_id: &str, context_id: Option<&str>) {
    let date = crate::utils::time::now_rfc3339();
    publish_user_update(env, user_id, UpdateType::LogOut, &date, context_id).await;
}

pub(crate) async fn publish_account_logout(
    env: &Env,
    claims: &crate::service::identity::session::Claims,
    date: &str,
) {
    publish_user(
        env,
        &claims.sub,
        UpdateType::LogOut,
        account_payload(&claims.sub, date),
        claims.device(),
        Some(LogoutScope::Stamp {
            value: claims.sstamp.clone(),
        }),
    )
    .await;
}

pub async fn publish_key_rotation(
    env: &Env,
    user_id: &str,
    date: &str,
    scope: LogoutScope,
    context_id: Option<&str>,
) {
    let mut payload = account_payload(user_id, date);
    payload.push(("Reason".into(), 1.into()));
    publish_user(
        env,
        user_id,
        UpdateType::LogOut,
        payload,
        context_id,
        Some(scope),
    )
    .await;
}

pub async fn publish_cipher_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    id: &str,
    date: &str,
    context_id: Option<&str>,
) {
    let mut payload = item_payload(user_id, id);
    payload.extend([
        ("OrganizationId".into(), MsgValue::Nil),
        ("CollectionIds".into(), MsgValue::Nil),
        ("RevisionDate".into(), encode_messagepack_timestamp(date)),
    ]);
    publish_user(env, user_id, kind, payload, context_id, None).await;
}

pub async fn publish_revision_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    id: &str,
    date: &str,
    context_id: Option<&str>,
) {
    let mut payload = item_payload(user_id, id);
    payload.push(("RevisionDate".into(), encode_messagepack_timestamp(date)));
    publish_user(env, user_id, kind, payload, context_id, None).await;
}

pub async fn publish_auth_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    request_id: &str,
    context_id: Option<&str>,
) {
    publish_user(
        env,
        user_id,
        kind,
        item_payload(user_id, request_id),
        context_id,
        None,
    )
    .await;
}

pub async fn publish_anonymous_update(env: &Env, request_id: &str, user_id: &str) {
    let message = encode_invocation("AuthRequestResponseRecieved", vec![
        (
            "Type".into(),
            (UpdateType::AuthRequestResponse as i32).into(),
        ),
        (
            "Payload".into(),
            MsgValue::Map(item_payload(user_id, request_id)),
        ),
        ("UserId".into(), user_id.into()),
    ]);
    let selector = FanoutSelector::Anonymous {
        request_id: request_id.to_owned(),
    };
    publish(env, selector, message, true).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signalr_frames_handshakes_and_messagepack_timestamps_encode_cleanly() {
        let mut negative = 999_999_999_u32.to_be_bytes().to_vec();
        negative.extend((-1_i64).to_be_bytes());
        assert_eq!(
            encode_messagepack_timestamp("1969-12-31T23:59:59.999999999Z"),
            MsgValue::Ext(-1, negative)
        );
        assert_eq!(
            encode_messagepack_timestamp("1970-01-01T00:00:00.000000001Z"),
            MsgValue::Ext(-1, (1_u64 << 34).to_be_bytes().to_vec())
        );
        assert!(is_signalr_handshake(
            "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}"
        ));
        assert!(!is_signalr_handshake(
            "{\"protocol\":\"json\",\"version\":1}\u{1e}"
        ));
        assert_eq!(
            encode_signalr_frame(&MsgValue::Array(vec![6.into()])).expect("ping"),
            PING
        );
        let bytes = encode_update_message(
            UpdateType::SyncVault,
            account_payload("user", "2026-11-13T03:00:00.123Z"),
            Some("browser"),
        )
        .expect("frame");
        let value = rmpv::decode::read_value(&mut &bytes[1..]).expect("msgpack");
        assert_eq!(
            (value[3].as_str(), value[4][0]["Type"].as_i64()),
            (Some("ReceiveMessage"), Some(5))
        );
    }
}
