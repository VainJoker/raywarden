use base64::{
    Engine as _,
    engine::general_purpose::STANDARD,
};
use rmpv::Value as MsgValue;
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest as _,
    Sha256,
};
use worker::{
    Env,
    Method,
    Request,
    RequestInit,
    wasm_bindgen::JsValue,
};

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::jwt,
};

pub const INTERNAL_HEADER: &str = "x-raywarden-notify-token";
pub const INTERNAL_PATH: &str = "/internal/fanout";
pub const INTERNAL_SYNC_PATH: &str = "/internal/file-sync";
pub const PING: [u8; 3] = [2, 0x91, 6];
pub const HANDSHAKE_RESPONSE: [u8; 3] = [b'{', b'}', 0x1e];

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
pub enum PublishSelector {
    User { user_id: String },
    Anonymous { request_id: String },
}

impl PublishSelector {
    pub fn tag(&self) -> String {
        match self {
            Self::User { user_id } => format!("u:{user_id}"),
            Self::Anonymous { request_id } => format!("a:{request_id}"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FanoutRequest {
    pub selector: PublishSelector,
    pub message:  String,
    pub logout:   bool,
}

#[derive(Serialize, Deserialize)]
struct InternalClaims {
    exp:       i64,
    nbf:       i64,
    iat:       i64,
    scope:     String,
    body_hash: String,
}

pub async fn internal_token(env: &Env, body: &str) -> AppResult<String> {
    let now = crate::infra::time::now_seconds();
    let claims = InternalClaims {
        exp:       now + 30,
        nbf:       now,
        iat:       now,
        scope:     "notifications.internal".to_string(),
        body_hash: hex::encode(Sha256::digest(body.as_bytes())),
    };
    let secret = crate::infra::jwt_keys::load(env).await?.access_secret;
    Ok(jwt::encode(&claims, secret.as_bytes())?)
}

pub async fn verify_internal(
    env: &Env,
    body: &str,
    token: &str,
) -> AppResult<()> {
    let secret = crate::infra::jwt_keys::load(env).await?.access_secret;
    let options = jwt::ValidationOptions {
        leeway: 0,
        ..Default::default()
    };
    let claims =
        jwt::decode::<InternalClaims>(token, secret.as_bytes(), &options)?
            .claims;
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    if claims.scope != "notifications.internal" ||
        !crate::infra::crypto::ct_eq(&claims.body_hash, &digest)
    {
        return Err(AppError::bad_request(
            "Invalid internal notification token",
        ));
    }
    Ok(())
}

pub fn is_initial_message(message: &str) -> bool {
    #[derive(Deserialize)]
    struct Handshake {
        protocol: String,
        version:  i32,
    }
    if message.len() > 1024 {
        return false;
    }
    let message = message.strip_suffix('\u{1e}').unwrap_or(message);
    serde_json::from_str::<Handshake>(message)
        .is_ok_and(|h| h.protocol == "messagepack" && h.version == 1)
}

fn framed(value: &MsgValue) -> AppResult<Vec<u8>> {
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, value)
        .map_err(|_| AppError::Internal)?;
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

fn timestamp(date: &str) -> MsgValue {
    let date = crate::infra::time::parse(date)
        .unwrap_or_else(|_| crate::infra::time::now());
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

fn update_message(
    update_type: UpdateType,
    payload: Vec<(MsgValue, MsgValue)>,
    context_id: Option<&str>,
) -> AppResult<Vec<u8>> {
    framed(&MsgValue::Array(vec![
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

/// Shared wire encoding for regular mutations and edge-completed uploads.
pub fn user_update_message(
    user_id: &str,
    kind: UpdateType,
    date: &str,
    context_id: Option<&str>,
) -> AppResult<Vec<u8>> {
    update_message(
        kind,
        vec![
            ("UserId".into(), user_id.into()),
            ("Date".into(), timestamp(date)),
        ],
        context_id,
    )
}

async fn fanout(
    env: &Env,
    selector: PublishSelector,
    bytes: &[u8],
    logout: bool,
) -> AppResult<()> {
    let Ok(namespace) = env.durable_object("NOTIFY_DO") else {
        return Ok(());
    };
    let stub = namespace.id_from_name("global")?.get_stub()?;
    let body = serde_json::to_string(&FanoutRequest {
        selector,
        message: STANDARD.encode(bytes),
        logout,
    })
    .map_err(|_| AppError::Internal)?;
    let token = internal_token(env, &body).await?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(JsValue::from_str(&body)));
    let mut request = Request::new_with_init(
        &format!("https://notify.internal{INTERNAL_PATH}"),
        &init,
    )?;
    request
        .headers_mut()?
        .set("content-type", "application/json")?;
    request.headers_mut()?.set(INTERNAL_HEADER, &token)?;
    let response = stub.fetch_with_request(request).await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::Internal);
    }
    Ok(())
}

async fn publish(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    payload: Vec<(MsgValue, MsgValue)>,
    relay_payload: serde_json::Value,
    context_id: Option<&str>,
) {
    match update_message(kind, payload, context_id) {
        Ok(message) => {
            if let Err(error) = fanout(
                env,
                PublishSelector::User {
                    user_id: user_id.to_string(),
                },
                &message,
                kind == UpdateType::LogOut,
            )
            .await
            {
                log::warn!("WebSocket notification failed: {error}");
            }
        }
        Err(error) => log::warn!("Notification encoding failed: {error}"),
    }
    if let Err(error) = super::push::send_update(
        env,
        user_id,
        kind as i32,
        &relay_payload,
        context_id,
    )
    .await
    {
        log::warn!("Mobile push failed: {error}");
    }
}

pub async fn publish_user_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    date: &str,
    context_id: Option<&str>,
) {
    publish(
        env,
        user_id,
        kind,
        vec![
            ("UserId".into(), user_id.into()),
            ("Date".into(), timestamp(date)),
        ],
        serde_json::json!({"userId":user_id,"date":date}),
        context_id,
    )
    .await;
}

pub async fn publish_key_rotation(
    env: &Env,
    user_id: &str,
    date: &str,
    context_id: Option<&str>,
) {
    publish(
        env,
        user_id,
        UpdateType::LogOut,
        vec![
            ("UserId".into(), user_id.into()),
            ("Date".into(), timestamp(date)),
            ("Reason".into(), 1.into()),
        ],
        serde_json::json!({"userId":user_id,"date":date,"reason":1}),
        context_id,
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
    publish(env,user_id,kind,vec![("Id".into(),id.into()),("UserId".into(),user_id.into()),("OrganizationId".into(),MsgValue::Nil),("CollectionIds".into(),MsgValue::Nil),("RevisionDate".into(),timestamp(date))],serde_json::json!({"id":id,"userId":user_id,"organizationId":null,"collectionIds":null,"revisionDate":date}),context_id).await;
}

pub async fn publish_folder_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    id: &str,
    date: &str,
    context_id: Option<&str>,
) {
    publish(
        env,
        user_id,
        kind,
        vec![
            ("Id".into(), id.into()),
            ("UserId".into(), user_id.into()),
            ("RevisionDate".into(), timestamp(date)),
        ],
        serde_json::json!({"id":id,"userId":user_id,"revisionDate":date}),
        context_id,
    )
    .await;
}

pub async fn publish_send_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    id: &str,
    date: &str,
    context_id: Option<&str>,
) {
    publish_folder_update(env, user_id, kind, id, date, context_id).await;
}

pub async fn publish_auth_update(
    env: &Env,
    user_id: &str,
    kind: UpdateType,
    request_id: &str,
    context_id: Option<&str>,
) {
    publish(
        env,
        user_id,
        kind,
        vec![
            ("Id".into(), request_id.into()),
            ("UserId".into(), user_id.into()),
        ],
        serde_json::json!({"id":request_id,"userId":user_id}),
        context_id,
    )
    .await;
}

pub async fn publish_anonymous_update(
    env: &Env,
    request_id: &str,
    user_id: &str,
) {
    let message = framed(&MsgValue::Array(vec![
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
                PublishSelector::Anonymous {
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
            log::warn!("Anonymous notification encoding failed: {error}")
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
            timestamp("1969-12-31T23:59:59.999999999Z"),
            MsgValue::Ext(-1, negative)
        );
        assert_eq!(
            timestamp("1970-01-01T00:00:00.000000001Z"),
            MsgValue::Ext(-1, (1_u64 << 34).to_be_bytes().to_vec())
        );
    }
    #[test]
    fn handshake_requires_supported_version_and_protocol() {
        assert!(is_initial_message(
            "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}"
        ));
        assert!(!is_initial_message(
            "{\"protocol\":\"json\",\"version\":1}\u{1e}"
        ));
        assert!(!is_initial_message(
            "{\"protocol\":\"messagepack\",\"version\":2}"
        ));
    }
    #[test]
    fn signalr_ping_and_payload_frame_lengths_match() {
        assert_eq!(framed(&MsgValue::Array(vec![6.into()])).unwrap(), PING);
        let bytes = update_message(
            UpdateType::SyncVault,
            vec![("UserId".into(), "user".into())],
            None,
        )
        .unwrap();
        assert_eq!(usize::from(bytes[0]), bytes.len() - 1);
        let value = rmpv::decode::read_value(&mut &bytes[1..]).unwrap();
        assert_eq!(value[3].as_str(), Some("ReceiveMessage"));
        assert_eq!(value[4][0]["Type"].as_i64(), Some(5));
    }
    #[test]
    fn completed_file_sync_uses_the_same_signalr_user_update_contract() {
        let bytes = user_update_message(
            "user",
            UpdateType::SyncVault,
            "2026-11-13T03:00:00.123Z",
            Some("browser"),
        )
        .unwrap();
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
        let value = rmpv::decode::read_value(&mut &bytes[prefix..]).unwrap();
        assert_eq!(value[3].as_str(), Some("ReceiveMessage"));
        assert_eq!(value[4][0]["Type"].as_i64(), Some(5));
        assert_eq!(value[4][0]["ContextId"].as_str(), Some("browser"));
        assert_eq!(value[4][0]["Payload"]["UserId"].as_str(), Some("user"));
        assert!(
            matches!(&value[4][0]["Payload"]["Date"], MsgValue::Ext(-1, bytes) if bytes.len() == 8)
        );
    }
}
