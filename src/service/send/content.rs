//! Send request validation, access policy and API projections.
use std::borrow::Cow;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) use crate::infra::config::{
    DEFAULT_SEND_TEXT_SIZE_BYTES as MAX_TEXT_SIZE_BYTES,
    send_text_size_bytes as max_text_size_bytes,
};
use crate::{
    errors::{AppError, AppResult},
    infra::crypto,
    models::send::SendRow,
    service::password,
    utils::serde::IntegerInput,
};

const SEND_PASSWORD_HASH_ITERATIONS: u32 = 100_000;
const SEND_PASSWORD_SALT_BYTES: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub(crate) enum SendKind {
    Text = 0,
    File = 1,
}

impl From<SendKind> for i32 {
    fn from(kind: SendKind) -> Self {
        kind as Self
    }
}

impl TryFrom<i32> for SendKind {
    type Error = ();

    fn try_from(kind: i32) -> Result<Self, Self::Error> {
        match kind {
            0 => Ok(Self::Text),
            1 => Ok(Self::File),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub(crate) enum SendUploadState {
    Ready = 0,
    Pending = 1,
    Failed = 2,
}

impl From<SendUploadState> for i32 {
    fn from(state: SendUploadState) -> Self {
        state as Self
    }
}

impl TryFrom<i32> for SendUploadState {
    type Error = ();

    fn try_from(state: i32) -> Result<Self, Self::Error> {
        match state {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Pending),
            2 => Ok(Self::Failed),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
enum SendAuthType {
    Password = 1,
    None = 2,
}

impl Serialize for SendAuthType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(*self as i32)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AccessCountPolicy {
    Enforce,
    Ignore,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendRequest {
    #[serde(rename = "id")]
    pub _client_supplied_id: Option<String>,
    #[serde(rename = "type")]
    pub send_type: i32,
    #[serde(rename = "key")]
    pub encrypted_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub text: Option<Value>,
    pub file: Option<Value>,
    #[serde(rename = "fileLength")]
    pub file_size_bytes: Option<IntegerInput>,
    pub password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_access_limit")]
    pub max_access_count: Option<i64>,
    #[serde(rename = "expirationDate")]
    pub expires_at: Option<String>,
    #[serde(rename = "deletionDate")]
    pub deletes_at: String,
    #[serde(rename = "disabled")]
    pub is_disabled: Option<bool>,
    #[serde(rename = "hideEmail")]
    pub is_email_hidden: Option<bool>,
    pub emails: Option<String>,
}

/// A Send has its own encryption key; account rotation only rewraps that key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateSendRequest {
    pub id: String,
    #[serde(rename = "key")]
    pub encrypted_key: String,
}

fn deserialize_access_limit<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    let limit = Option::<IntegerInput>::deserialize(deserializer)?;
    if matches!(&limit, Some(IntegerInput::String(value)) if value.trim().is_empty()) {
        return Ok(None);
    }
    limit
        .map(|value| {
            value
                .parse_i32()
                .map(i64::from)
                .map_err(serde::de::Error::custom)
        })
        .transpose()
}

pub(super) fn format_file_size(bytes: i64) -> String {
    let mut size = bytes as f64;
    let mut unit = 0;
    let units = ["bytes", "KB", "MB", "GB", "TB", "PB"];
    while size > 1024.0 && unit + 1 < units.len() {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.2} {}", units[unit])
}

pub(super) fn encode_access_id(id: &str) -> AppResult<String> {
    let id = uuid::Uuid::parse_str(id).map_err(|_error| AppError::send_unavailable())?;
    Ok(URL_SAFE_NO_PAD.encode(id.as_bytes()))
}

pub(crate) fn decode_access_id(id: &str) -> AppResult<String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_error| AppError::send_unavailable())?;
    uuid::Uuid::from_slice(&bytes)
        .map(|id| id.to_string())
        .map_err(|_error| AppError::send_unavailable())
}

pub(crate) fn validate_send_dates(
    deletes_at: &str,
    expires_at: Option<&str>,
) -> AppResult<(String, Option<String>)> {
    validate_dates_at(deletes_at, expires_at, crate::utils::time::now())
}

fn validate_dates_at(
    deletes_at: &str,
    expires_at: Option<&str>,
    now: Timestamp,
) -> AppResult<(String, Option<String>)> {
    let parse = |s: &str| {
        crate::utils::time::parse(s).map_err(|_error| AppError::bad_request("Invalid Send date"))
    };
    let deletion = parse(deletes_at)?;
    let latest = now
        .checked_add(SignedDuration::from_secs(31 * 86_400))
        .map_err(|_error| {
            AppError::bad_request("Send date window exceeds the supported timestamp range")
        })?;
    if deletion <= now || deletion > latest {
        return Err(AppError::bad_request(
            "Send deletion must be within the next 31 days",
        ));
    }
    let expiration = expires_at.map(parse).transpose()?;
    if expiration
        .as_ref()
        .is_some_and(|d| *d <= now || *d > deletion)
    {
        return Err(AppError::bad_request(
            "Send expiration must be in the future and no later than deletion",
        ));
    }
    Ok((
        crate::utils::time::format_millis(deletion),
        expiration.map(crate::utils::time::format_millis),
    ))
}

struct ContentSpec {
    value: Option<Value>,
    required_field: &'static str,
    missing_error: &'static str,
    byte_limit: usize,
}

impl SendRequest {
    pub(super) fn validate(&self) -> AppResult<(SendKind, Option<i64>)> {
        let kind = SendKind::try_from(self.send_type)
            .map_err(|()| AppError::bad_request("Unsupported Send type"))?;
        if self.emails.is_some() {
            return Err(AppError::bad_request(
                "Send email verification is not supported",
            ));
        }
        if self.name.is_empty() || self.encrypted_key.is_empty() {
            return Err(AppError::bad_request("Send name and key are required"));
        }
        if self.max_access_count.is_some_and(|n| n < 0) {
            return Err(AppError::bad_request(
                "Maximum access count cannot be negative",
            ));
        }
        Ok((kind, self.max_access_count))
    }

    pub(super) fn take_encoded_content(
        &mut self,
        kind: SendKind,
        text_limit: usize,
    ) -> AppResult<String> {
        let spec = match kind {
            SendKind::Text => ContentSpec {
                value: self.text.take(),
                required_field: "text",
                missing_error: "Encrypted Send text is required",
                byte_limit: text_limit,
            },
            SendKind::File => ContentSpec {
                value: self.file.take(),
                required_field: "fileName",
                missing_error: "Encrypted file name is required",
                byte_limit: MAX_TEXT_SIZE_BYTES,
            },
        };
        let mut content = spec
            .value
            .ok_or_else(|| AppError::bad_request("Send content is required"))?;
        let object = content
            .as_object_mut()
            .ok_or_else(|| AppError::bad_request("Invalid Send content"))?;
        object.remove("response");
        if !object
            .get(spec.required_field)
            .is_some_and(Value::is_string)
        {
            return Err(AppError::bad_request(spec.missing_error));
        }
        let encoded = serde_json::to_string(&content)
            .map_err(AppError::internal_json("Failed to serialize Send content"))?;
        if encoded.len() > spec.byte_limit {
            return Err(AppError::bad_request("Send content exceeds the size limit"));
        }
        Ok(encoded)
    }
}

pub(crate) fn new_send(
    user_id: String,
    mut payload: SendRequest,
    text_limit: usize,
) -> AppResult<SendRow> {
    let (kind, maximum) = payload.validate()?;
    let (deletes_at, expires_at) =
        validate_send_dates(&payload.deletes_at, payload.expires_at.as_deref())?;
    let now = crate::utils::time::now_rfc3339();
    let data = payload.take_encoded_content(kind, text_limit)?;
    Ok(SendRow {
        id: uuid::Uuid::new_v4().to_string(),
        user_id,
        name: payload.name,
        notes: payload.notes,
        send_type: i32::from(kind),
        data,
        encrypted_key: payload.encrypted_key,
        password_hash: None,
        password_salt: None,
        password_iterations: None,
        max_access_count: maximum,
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        expires_at,
        deletes_at,
        is_disabled: i32::from(payload.is_disabled.unwrap_or(false)),
        is_email_hidden: i32::from(payload.is_email_hidden.unwrap_or(false)),
        access_stamp: uuid::Uuid::new_v4().to_string(),
        file_id: None,
        file_size_bytes: 0,
        upload_state: i32::from(SendUploadState::Ready),
        storage_key: None,
    })
}

#[derive(Default)]
pub(super) enum SendPassword {
    #[default]
    Absent,
    Present {
        hash: String,
        salt: String,
        iterations: i32,
    },
}

impl SendPassword {
    pub(super) async fn derive(password: Option<&str>) -> AppResult<Self> {
        let Some(password) = password.filter(|p| !p.is_empty()) else {
            return Ok(Self::Absent);
        };
        if password.len() > 4096 {
            return Err(AppError::bad_request("Send password is too long"));
        }
        let salt = STANDARD.encode(crypto::random_bytes(
            SEND_PASSWORD_SALT_BYTES,
            "generate Send password salt",
        )?);
        let hash =
            password::hash_password_for_storage(password, &salt, SEND_PASSWORD_HASH_ITERATIONS)
                .await?;
        Ok(Self::Present {
            hash,
            salt,
            iterations: SEND_PASSWORD_HASH_ITERATIONS as i32,
        })
    }

    pub(super) fn apply(self, send: &mut SendRow) {
        let (hash, salt, iterations) = match self {
            Self::Absent => (None, None, None),
            Self::Present {
                hash,
                salt,
                iterations,
            } => (Some(hash), Some(salt), Some(iterations)),
        };
        send.password_hash = hash;
        send.password_salt = salt;
        send.password_iterations = iterations;
    }
}

pub(super) async fn verify_send_password(send: &SendRow, password: Option<&str>) -> AppResult<()> {
    let Some(hash) = &send.password_hash else {
        return Ok(());
    };
    let password = password
        .filter(|p| !p.is_empty() && p.len() <= 4096)
        .ok_or_else(|| AppError::Unauthorized {
            message: "Send password required".into(),
        })?;
    let salt = send
        .password_salt
        .as_deref()
        .ok_or_else(|| AppError::internal("Stored Send password salt is missing"))?;
    let iterations = match send.password_iterations {
        None => SEND_PASSWORD_HASH_ITERATIONS,
        Some(value) => u32::try_from(value)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| AppError::internal("Stored Send password iterations are invalid"))?,
    };
    if !password::verify_password(password, hash, salt, iterations).await? {
        return Err(AppError::bad_request("Invalid Send password"));
    }
    Ok(())
}

pub(super) fn validate_access(send: &SendRow, count_policy: AccessCountPolicy) -> AppResult<()> {
    let now = crate::utils::time::now();
    let is_expired = |raw: &str| crate::utils::time::parse(raw).is_ok_and(|date| date > now);
    if send.upload_state != i32::from(SendUploadState::Ready)
        || send.is_disabled != 0
        || !is_expired(&send.deletes_at)
        || send.expires_at.as_deref().is_some_and(|d| !is_expired(d))
        || (count_policy == AccessCountPolicy::Enforce
            && send
                .max_access_count
                .is_some_and(|n| send.access_count >= n))
    {
        return Err(AppError::send_unavailable());
    }
    Ok(())
}

pub(super) fn storage_key(send: &SendRow) -> Option<Cow<'_, str>> {
    send.file_id.as_deref().map(|id| {
        send.storage_key.as_deref().map_or_else(
            || Cow::Owned(format!("sends/{}/{id}", send.id)),
            Cow::Borrowed,
        )
    })
}

fn response_content(send: &SendRow) -> (Option<Value>, Option<Value>) {
    let Ok(kind) = SendKind::try_from(send.send_type) else {
        return (None, None);
    };
    let mut data: Value = serde_json::from_str(&send.data).unwrap_or(Value::Null);
    match kind {
        SendKind::Text => (Some(data), None),
        SendKind::File => {
            if let Some(object) = data.as_object_mut() {
                object.insert("id".into(), json!(send.file_id));
                object.insert("size".into(), json!(send.file_size_bytes.to_string()));
                object.insert(
                    "sizeName".into(),
                    json!(format_file_size(send.file_size_bytes)),
                );
            }
            (None, Some(data))
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendResponse {
    id: String,
    access_id: Option<String>,
    #[serde(rename = "type")]
    send_type: i32,
    name: String,
    notes: Option<String>,
    text: Option<Value>,
    file: Option<Value>,
    key: String,
    max_access_count: Option<i64>,
    access_count: i64,
    revision_date: String,
    expiration_date: Option<String>,
    deletion_date: String,
    disabled: bool,
    hide_email: bool,
    password: Option<String>,
    auth_type: SendAuthType,
    object: &'static str,
}

pub(crate) fn send_response(send: SendRow) -> SendResponse {
    let (text, file) = response_content(&send);
    let auth_type = if send.password_hash.is_some() {
        SendAuthType::Password
    } else {
        SendAuthType::None
    };
    let password = send
        .password_hash
        .as_ref()
        .and_then(|hash| STANDARD.decode(hash).ok())
        .map(|hash| URL_SAFE_NO_PAD.encode(hash));
    SendResponse {
        access_id: encode_access_id(&send.id).ok(),
        id: send.id,
        send_type: send.send_type,
        name: send.name,
        notes: send.notes,
        text,
        file,
        key: send.encrypted_key,
        max_access_count: send.max_access_count,
        access_count: send.access_count,
        revision_date: send.updated_at,
        expiration_date: send.expires_at,
        deletion_date: send.deletes_at,
        disabled: send.is_disabled != 0,
        hide_email: send.is_email_hidden != 0,
        password,
        auth_type,
        object: "send",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendAccessResponse {
    id: Option<String>,
    #[serde(rename = "type")]
    send_type: i32,
    name: String,
    text: Option<Value>,
    file: Option<Value>,
    expiration_date: Option<String>,
    creator_identifier: Option<String>,
    object: &'static str,
}

pub(super) fn send_access_response(
    send: SendRow,
    creator_identifier: Option<String>,
) -> SendAccessResponse {
    let (text, file) = response_content(&send);
    SendAccessResponse {
        id: encode_access_id(&send.id).ok(),
        send_type: send.send_type,
        name: send.name,
        text,
        file,
        expiration_date: send.expires_at,
        creator_identifier,
        object: "send-access",
    }
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::*;

    #[test]
    fn send_limits_ids_and_date_windows_are_enforced() {
        let del = crate::utils::time::now()
            .checked_add(SignedDuration::from_secs(86_400))
            .expect("day")
            .to_string();
        let base = json!({"type":0,"name":"enc","key":"k","text":{"text":"€🙂","response":"tmp"},"deletionDate":del});
        let mut req: SendRequest = serde_json::from_value(base.clone()).expect("req");
        let encoded = req
            .take_encoded_content(SendKind::Text, 64)
            .expect("content");
        assert_eq!(encoded, r#"{"text":"€🙂"}"#);
        let mut too_small: SendRequest = serde_json::from_value(base).expect("req");
        assert!(
            too_small
                .take_encoded_content(SendKind::Text, encoded.len() - 1)
                .is_err()
        );

        let id = "00112233-4455-6677-8899-aabbccddeeff";
        let access = encode_access_id(id).expect("encode");
        assert_eq!(decode_access_id(&access).expect("decode"), id);
        assert!(decode_access_id("YWJj").is_err());
        assert_eq!(format_file_size(1025), "1.00 KB");

        let now = crate::utils::time::parse("2026-11-13T03:00:00.123Z").expect("now");
        assert!(
            validate_dates_at(
                "2026-12-14T03:00:00.123Z",
                Some("2026-12-14T03:00:00.123Z"),
                now
            )
            .is_ok()
        );
        assert!(validate_dates_at("2026-12-14T03:00:00.124Z", None, now).is_err());
        assert!(validate_dates_at("2026-11-13T11:00:00.123+08:00", None, now).is_err());
        assert!(validate_dates_at("9999-12-31T23:59:59.999999999Z", None, Timestamp::MAX).is_err());
    }
}
