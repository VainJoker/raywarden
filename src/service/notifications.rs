pub mod admin;
pub(crate) mod hub;
pub mod push;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rmpv::Value as MsgValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use worker::{
    AbortSignal, Env, Fetch, Method, Request, RequestInit, RequestRedirect, Response,
    wasm_bindgen::JsValue,
};

use crate::{
    errors::{AppError, AppResult, JwtError},
    infra::{db, jwt},
    models::identity::push::PushDeviceRow,
};

pub const FANOUT_TOKEN_HEADER: &str = "x-raywarden-notify-token";
pub const FANOUT_PATH: &str = "/internal/fanout";
pub const PING: [u8; 3] = [2, 0x91, 6];
pub const HANDSHAKE_RESPONSE: [u8; 3] = [b'{', b'}', 0x1e];
const DELIVERY_TIMEOUT_MS: u32 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

pub(crate) enum FanoutVerificationError {
    InvalidProof,
    Unavailable(&'static str),
}

pub(crate) async fn verify_fanout_token(
    env: &Env,
    body: &str,
    token: &str,
) -> Result<(), FanoutVerificationError> {
    use FanoutVerificationError::{InvalidProof, Unavailable};

    let db = db::binding(env).map_err(|_error| Unavailable("resolve D1 binding DB"))?;
    let secret = crate::service::identity::jwt_keys::load(env, &db)
        .await
        .map_err(|_error| Unavailable("load JWT signing keys"))?
        .access_secret;
    let options = jwt::ValidationOptions {
        leeway_seconds: 0,
        ..Default::default()
    };
    let claims = jwt::decode::<FanoutClaims>(token, secret.as_bytes(), &options).map_err(
        |error| match error {
            JwtError::CryptoError(_) => Unavailable("verify JWT signature"),
            _ => InvalidProof,
        },
    )?;
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    if claims.scope != "notifications.internal"
        || !crate::utils::constant_time_eq(claims.body_hash.as_bytes(), digest.as_bytes())
    {
        return Err(InvalidProof);
    }
    Ok(())
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
    rmpv::encode::write_value(&mut payload, value).map_err(AppError::internal_error)?;
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

fn encode_update_message(
    update_type: UpdateType,
    payload: Vec<(MsgValue, MsgValue)>,
    context_id: Option<&str>,
) -> AppResult<Vec<u8>> {
    encode_signalr_frame(&MsgValue::Array(vec![
        1.into(),
        MsgValue::Map(vec![]),
        MsgValue::Nil,
        "ReceiveMessage".into(),
        MsgValue::Array(vec![MsgValue::Map(vec![
            (
                "ContextId".into(),
                context_id.map_or(MsgValue::Nil, Into::into),
            ),
            ("Type".into(), (update_type as i32).into()),
            ("Payload".into(), MsgValue::Map(payload)),
        ])]),
    ]))
}

enum NotificationEvent<'a> {
    Account { date: &'a str, reason: Option<i32> },
    Cipher { id: &'a str, date: &'a str },
    Revision { id: &'a str, date: &'a str },
    AuthRequest { id: &'a str },
}

/// A user event shared by `SignalR` and the mobile push relay.
struct UserUpdate<'a> {
    user_id: &'a str,
    kind: UpdateType,
    context_id: Option<&'a str>,
    payload: NotificationEvent<'a>,
    logout_scope: Option<LogoutScope>,
}

impl<'a> NotificationEvent<'a> {
    const fn for_user(
        self,
        user_id: &'a str,
        kind: UpdateType,
        context_id: Option<&'a str>,
    ) -> UserUpdate<'a> {
        UserUpdate {
            user_id,
            kind,
            context_id,
            payload: self,
            logout_scope: None,
        }
    }
}

impl UserUpdate<'_> {
    fn with_logout_scope(mut self, scope: LogoutScope) -> Self {
        self.logout_scope = Some(scope);
        self
    }

    fn websocket_message(&self) -> AppResult<Vec<u8>> {
        let user_id = self.user_id.into();
        let payload = match self.payload {
            NotificationEvent::Account { date, reason } => {
                let mut fields = vec![
                    ("UserId".into(), user_id),
                    ("Date".into(), encode_messagepack_timestamp(date)),
                ];
                if let Some(reason) = reason {
                    fields.push(("Reason".into(), reason.into()));
                }
                fields
            }
            NotificationEvent::Cipher { id, date } => vec![
                ("Id".into(), id.into()),
                ("UserId".into(), user_id),
                ("OrganizationId".into(), MsgValue::Nil),
                ("CollectionIds".into(), MsgValue::Nil),
                ("RevisionDate".into(), encode_messagepack_timestamp(date)),
            ],
            NotificationEvent::Revision { id, date } => vec![
                ("Id".into(), id.into()),
                ("UserId".into(), user_id),
                ("RevisionDate".into(), encode_messagepack_timestamp(date)),
            ],
            NotificationEvent::AuthRequest { id } => {
                vec![("Id".into(), id.into()), ("UserId".into(), user_id)]
            }
        };
        encode_update_message(self.kind, payload, self.context_id)
    }

    fn push_payload(&self) -> serde_json::Value {
        use serde_json::json;

        let user_id = self.user_id;
        match self.payload {
            NotificationEvent::Account { date, reason } => {
                let mut payload = json!({"userId": user_id, "date": date});
                if let Some(reason) = reason {
                    payload["reason"] = json!(reason);
                }
                payload
            }
            NotificationEvent::Cipher { id, date } => json!({
                "id": id, "userId": user_id, "organizationId": null,
                "collectionIds": null, "revisionDate": date,
            }),
            NotificationEvent::Revision { id, date } => {
                json!({"id": id, "userId": user_id, "revisionDate": date})
            }
            NotificationEvent::AuthRequest { id } => {
                json!({"id": id, "userId": user_id})
            }
        }
    }

    async fn push(&self, env: &Env) -> AppResult<()> {
        push::send_update(
            env,
            self.user_id,
            self.kind,
            &self.push_payload(),
            self.context_id,
        )
        .await
    }

    async fn publish_websocket(&self, env: &Env) {
        match self.websocket_message() {
            Ok(message) => {
                if let Err(error) = fanout(
                    env,
                    FanoutSelector::User {
                        user_id: self.user_id.to_string(),
                        logout_scope: self.logout_scope.clone(),
                    },
                    &message,
                    self.kind == UpdateType::LogOut,
                )
                .await
                {
                    log::warn!("WebSocket notification failed: {error}");
                }
            }
            Err(error) => log::warn!("Notification encoding failed: {error}"),
        }
    }

    async fn publish(&self, env: &Env) {
        self.publish_websocket(env).await;
        if let Err(error) = self.push(env).await {
            log::warn!("Mobile push failed: {error}");
        }
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
    .map_err(AppError::internal_error)?;
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
        return Err(AppError::InternalFailure(format!(
            "Notification fanout returned HTTP {status}"
        )));
    }
    Ok(())
}

/// Deliver JSON over HTTPS via the Worker runtime.
pub(super) async fn post_json(url: &str, body: Value, bearer: Option<&str>) -> AppResult<()> {
    // Require HTTPS before sending the body or credentials.
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
    let response = send_delivery_request(request).await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::bad_request("Notification delivery failed"));
    }
    Ok(())
}

async fn send_delivery_request(request: Request) -> worker::Result<Response> {
    let signal = AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(DELIVERY_TIMEOUT_MS));
    Fetch::Request(request).send_with_signal(&signal).await
}

pub async fn publish_user_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    date: &str,
    context_id: Option<&str>,
) {
    NotificationEvent::Account { date, reason: None }
        .for_user(user_id, kind, context_id)
        .publish(env)
        .await;
}

pub(crate) async fn publish_deleted_account(
    env: &Env,
    user_id: &str,
    devices: &[PushDeviceRow],
    context_id: Option<&str>,
) {
    let date = crate::utils::time::now_rfc3339();
    let update = NotificationEvent::Account {
        date: &date,
        reason: None,
    }
    .for_user(user_id, UpdateType::LogOut, context_id);
    update.publish_websocket(env).await;
    push::logout_deleted_user(env, user_id, devices, &update.push_payload(), context_id).await;
}

pub(crate) async fn publish_account_logout(
    env: &Env,
    claims: &crate::service::identity::session::Claims,
    date: &str,
) {
    NotificationEvent::Account { date, reason: None }
        .for_user(&claims.sub, UpdateType::LogOut, claims.device())
        .with_logout_scope(LogoutScope::Stamp {
            value: claims.sstamp.clone(),
        })
        .publish(env)
        .await;
}

pub async fn publish_key_rotation(
    env: &Env,
    user_id: &str,
    date: &str,
    scope: LogoutScope,
    context_id: Option<&str>,
) {
    NotificationEvent::Account {
        date,
        reason: Some(1),
    }
    .for_user(user_id, UpdateType::LogOut, context_id)
    .with_logout_scope(scope)
    .publish(env)
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
    NotificationEvent::Cipher { id, date }
        .for_user(user_id, kind, context_id)
        .publish(env)
        .await;
}

pub async fn publish_revision_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    id: &str,
    date: &str,
    context_id: Option<&str>,
) {
    NotificationEvent::Revision { id, date }
        .for_user(user_id, kind, context_id)
        .publish(env)
        .await;
}

pub async fn publish_auth_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    request_id: &str,
    context_id: Option<&str>,
) {
    NotificationEvent::AuthRequest { id: request_id }
        .for_user(user_id, kind, context_id)
        .publish(env)
        .await;
}

pub async fn publish_anonymous_update(env: &Env, request_id: &str, user_id: &str) {
    let message = encode_signalr_frame(&MsgValue::Array(vec![
        1.into(),
        MsgValue::Map(vec![]),
        MsgValue::Nil,
        "AuthRequestResponseRecieved".into(),
        MsgValue::Array(vec![MsgValue::Map(vec![
            (
                "Type".into(),
                (UpdateType::AuthRequestResponse as i32).into(),
            ),
            (
                "Payload".into(),
                MsgValue::Map(vec![
                    ("Id".into(), request_id.into()),
                    ("UserId".into(), user_id.into()),
                ]),
            ),
            ("UserId".into(), user_id.into()),
        ])]),
    ]));
    match message {
        Ok(bytes) => {
            if let Err(error) = fanout(
                env,
                FanoutSelector::Anonymous {
                    request_id: request_id.to_string(),
                },
                &bytes,
                true,
            )
            .await
            {
                log::warn!("Anonymous notification failed: {error}");
            }
        }
        Err(error) => {
            log::warn!("Anonymous notification encoding failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn messagepack_timestamp_preserves_nanoseconds_on_both_sides_of_epoch() {
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
    }
    #[test]
    fn handshake_requires_supported_version_and_protocol() {
        assert!(is_signalr_handshake(
            "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}"
        ));
        assert!(!is_signalr_handshake(
            "{\"protocol\":\"json\",\"version\":1}\u{1e}"
        ));
        assert!(!is_signalr_handshake(
            "{\"protocol\":\"messagepack\",\"version\":2}"
        ));
    }
    #[test]
    fn signalr_ping_and_payload_frame_lengths_match() {
        assert_eq!(
            encode_signalr_frame(&MsgValue::Array(vec![6.into()]))
                .expect("valid notifications fixture"),
            PING
        );
        let bytes = encode_update_message(
            UpdateType::SyncVault,
            vec![("UserId".into(), "user".into())],
            None,
        )
        .expect("valid notifications fixture");
        assert_eq!(usize::from(bytes[0]), bytes.len() - 1);
        let value =
            rmpv::decode::read_value(&mut &bytes[1..]).expect("valid notifications fixture");
        assert_eq!(value[3].as_str(), Some("ReceiveMessage"));
        assert_eq!(value[4][0]["Type"].as_i64(), Some(5));
    }
    #[test]
    fn vault_sync_carries_context_and_a_messagepack_timestamp() {
        let bytes = NotificationEvent::Account {
            date: "2026-11-13T03:00:00.123Z",
            reason: None,
        }
        .for_user("user", UpdateType::SyncVault, Some("browser"))
        .websocket_message()
        .expect("valid notifications fixture");
        let mut size = 0_usize;
        let mut prefix = 0;
        for (index, byte) in bytes.iter().enumerate() {
            size |= usize::from(byte & 0x7f) << (index * 7);
            prefix = index + 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        assert_eq!(size, bytes.len() - prefix);
        let value =
            rmpv::decode::read_value(&mut &bytes[prefix..]).expect("valid notifications fixture");
        assert_eq!(value[3].as_str(), Some("ReceiveMessage"));
        assert_eq!(value[4][0]["Type"].as_i64(), Some(5));
        assert_eq!(value[4][0]["ContextId"].as_str(), Some("browser"));
        assert_eq!(value[4][0]["Payload"]["UserId"].as_str(), Some("user"));
        assert!(
            matches!(&value[4][0]["Payload"]["Date"], MsgValue::Ext(-1, bytes) if bytes.len() == 8)
        );
    }
}
