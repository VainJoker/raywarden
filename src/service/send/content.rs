//! Send request validation, access policy and API projections.
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
};

const SEND_PASSWORD_HASH_ITERATIONS: u32 = 100_000;
const SEND_PASSWORD_SALT_BYTES: u32 = 16;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum IntegerInput {
    Number(i64),
    String(String),
}

impl IntegerInput {
    pub(crate) fn parse_i64(&self) -> AppResult<i64> {
        match self {
            Self::Number(n) => Ok(*n),
            Self::String(s) => s
                .trim()
                .parse()
                .map_err(|_error| AppError::bad_request("Invalid number")),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(i32)]
pub(super) enum SendKind {
    Text = 0,
    File = 1,
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
            let parsed = value.parse_i64().map_err(serde::de::Error::custom)?;
            i32::try_from(parsed).map_err(serde::de::Error::custom)?;
            Ok(parsed)
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
        let mut content = match kind {
            SendKind::Text => self.text.take(),
            SendKind::File => self.file.take(),
        }
        .ok_or_else(|| AppError::bad_request("Send content is required"))?;
        let object = content
            .as_object_mut()
            .ok_or_else(|| AppError::bad_request("Invalid Send content"))?;
        object.remove("response");
        if kind == SendKind::Text && !object.get("text").is_some_and(Value::is_string) {
            return Err(AppError::bad_request("Encrypted Send text is required"));
        }
        if kind == SendKind::File && !object.get("fileName").is_some_and(Value::is_string) {
            return Err(AppError::bad_request("Encrypted file name is required"));
        }
        let encoded = serde_json::to_string(&content).map_err(AppError::internal_error)?;
        let limit = if kind == SendKind::Text {
            text_limit
        } else {
            MAX_TEXT_SIZE_BYTES
        };
        if encoded.len() > limit {
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
        send_type: kind as i32,
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
        upload_state: 0,
        storage_key: None,
    })
}

pub(super) struct SendPassword {
    hash: Option<String>,
    salt: Option<String>,
    iterations: Option<i32>,
}

impl SendPassword {
    pub(super) async fn derive(password: Option<&str>) -> AppResult<Self> {
        let Some(password) = password.filter(|p| !p.is_empty()) else {
            return Ok(Self {
                hash: None,
                salt: None,
                iterations: None,
            });
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
        Ok(Self {
            hash: Some(hash),
            salt: Some(salt),
            iterations: Some(SEND_PASSWORD_HASH_ITERATIONS as i32),
        })
    }

    pub(super) fn apply(self, send: &mut SendRow) {
        send.password_hash = self.hash;
        send.password_salt = self.salt;
        send.password_iterations = self.iterations;
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
    let salt = send.password_salt.as_deref().ok_or(AppError::Internal)?;
    let iterations = match send.password_iterations {
        None => SEND_PASSWORD_HASH_ITERATIONS,
        Some(value) => u32::try_from(value)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(AppError::Internal)?,
    };
    if !password::verify_password(password, hash, salt, iterations).await? {
        return Err(AppError::bad_request("Invalid Send password"));
    }
    Ok(())
}

pub(super) fn validate_access(send: &SendRow, check_count: bool) -> AppResult<()> {
    let now = crate::utils::time::now();
    if send.upload_state != 0
        || send.is_disabled != 0
        || crate::utils::time::parse(&send.deletes_at).map_or(true, |date| date <= now)
        || send
            .expires_at
            .as_ref()
            .is_some_and(|date| crate::utils::time::parse(date).map_or(true, |date| date <= now))
        || (check_count
            && send
                .max_access_count
                .is_some_and(|n| send.access_count >= n))
    {
        return Err(AppError::send_unavailable());
    }
    Ok(())
}

pub(super) fn storage_key(send: &SendRow) -> Option<String> {
    send.file_id.as_ref().map(|id| {
        send.storage_key
            .clone()
            .unwrap_or_else(|| format!("sends/{}/{id}", send.id))
    })
}

fn response_content(send: &SendRow) -> (Option<Value>, Option<Value>) {
    let mut data: Value = serde_json::from_str(&send.data).unwrap_or(Value::Null);
    let kind = SendKind::try_from(send.send_type);
    if matches!(kind, Ok(SendKind::File))
        && let Some(object) = data.as_object_mut()
    {
        object.insert("id".into(), json!(send.file_id));
        object.insert("size".into(), json!(send.file_size_bytes.to_string()));
        object.insert(
            "sizeName".into(),
            json!(format_file_size(send.file_size_bytes)),
        );
    }
    match kind {
        Ok(SendKind::Text) => (Some(data), None),
        Ok(SendKind::File) => (None, Some(data)),
        Err(()) => (None, None),
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
    auth_type: i32,
    object: &'static str,
}

pub(crate) fn send_response(send: SendRow) -> SendResponse {
    let (text, file) = response_content(&send);
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
        password: send
            .password_hash
            .as_ref()
            .and_then(|hash| STANDARD.decode(hash).ok())
            .map(|hash| URL_SAFE_NO_PAD.encode(hash)),
        auth_type: if send.password_hash.is_some() { 1 } else { 2 },
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
    use super::*;

    #[test]
    fn text_limits_count_utf8_json_after_removing_response_metadata() {
        let mut value = request();
        value["text"] = json!({"text":"€🙂", "response":"temporary"});
        let mut payload: SendRequest =
            serde_json::from_value(value.clone()).expect("valid test fixture");
        let expected = r#"{"text":"€🙂"}"#;
        let bytes = expected.len();
        assert_eq!(
            payload
                .take_encoded_content(SendKind::Text, bytes)
                .expect("valid test fixture"),
            expected
        );
        let mut payload: SendRequest = serde_json::from_value(value).expect("valid test fixture");
        assert!(
            payload
                .take_encoded_content(SendKind::Text, bytes - 1)
                .is_err()
        );
    }

    fn request() -> Value {
        json!({"type":0,"name":"encrypted","key":"wrapped-key",
            "text":{"text":"ciphertext"},
            "deletionDate":crate::utils::time::now().checked_add(SignedDuration::from_secs(86_400)).expect("test clock supports a day").to_string()})
    }

    #[test]
    fn access_limits_reject_i32_overflow_and_owner_responses_use_real_password_verifier() {
        for limit in [
            json!(4_294_967_297_i64),
            json!("4294967297"),
            json!(-2_147_483_649_i64),
        ] {
            let mut value = request();
            value["maxAccessCount"] = limit;
            assert!(serde_json::from_value::<SendRequest>(value).is_err());
        }
        let mut value = request();
        value["maxAccessCount"] = json!(" 2 ");
        let payload: SendRequest = serde_json::from_value(value).expect("valid limit");
        assert_eq!(payload.validate().expect("count").1, Some(2));
        let mut send = new_send("owner".into(), payload, MAX_TEXT_SIZE_BYTES).expect("send");
        assert_eq!(
            serde_json::to_value(send_response(send.clone())).expect("owner response")["password"],
            Value::Null
        );
        send.password_hash = Some(STANDARD.encode([255_u8; 32]));
        assert_eq!(
            serde_json::to_value(send_response(send.clone())).expect("owner response")["password"],
            json!(URL_SAFE_NO_PAD.encode([255_u8; 32]))
        );
        let access_id = encode_access_id(&send.id).expect("access ID");
        let access =
            serde_json::to_value(send_access_response(send, None)).expect("access response");
        assert_eq!(access["id"], json!(access_id));
        assert!(access.get("key").is_none());
        let mut value = request();
        value["id"] = json!(12);
        assert!(serde_json::from_value::<SendRequest>(value).is_err());
        let mut value = request();
        value["id"] = json!("ignored-client-id");
        assert!(serde_json::from_value::<SendRequest>(value).is_ok());
    }

    #[test]
    fn rotation_accepts_only_id_and_key_and_ignores_unrelated_client_fields() {
        let minimal: RotateSendRequest =
            serde_json::from_value(json!({"id":"send","key":"rewrapped"}))
                .expect("minimal rotation");
        assert_eq!(minimal.encrypted_key, "rewrapped");
        let extra: RotateSendRequest =
            serde_json::from_value(json!({"id":"send","key":"rewrapped",
            "type":99,"name":"must-be-ignored","notes":"ignored","file":false,
            "text":[],"deletionDate":"invalid-date","disabled":true}))
            .expect("unrelated fields ignored");
        assert_eq!(extra.id, minimal.id);
        assert_eq!(extra.encrypted_key, minimal.encrypted_key);
    }

    #[test]
    fn file_size_display_and_lifetime_use_upstream_units_and_real_timestamps() {
        for (size, expected) in [
            (0, "0.00 bytes"),
            (3, "3.00 bytes"),
            (1024, "1024.00 bytes"),
            (1025, "1.00 KB"),
            (1_048_576, "1024.00 KB"),
        ] {
            assert_eq!(format_file_size(size), expected);
        }
        let payload: SendRequest = serde_json::from_value(request()).expect("payload");
        let mut send = new_send("owner".into(), payload, MAX_TEXT_SIZE_BYTES).expect("send");
        let offset = jiff::tz::Offset::from_hours(8).expect("offset");
        send.deletes_at = crate::utils::time::now()
            .checked_sub(SignedDuration::from_hours(1))
            .expect("test clock supports an hour")
            .display_with_offset(offset)
            .to_string();
        assert!(validate_access(&send, false).is_err());
    }

    #[test]
    fn access_ids_use_uuid_bytes_and_reject_invalid_lengths() {
        let id = "00112233-4455-6677-8899-aabbccddeeff";
        let access = encode_access_id(id).expect("valid test fixture");
        assert_eq!(access, "ABEiM0RVZneImaq7zN3u_w");
        assert_eq!(decode_access_id(&access).expect("valid test fixture"), id);
        assert!(decode_access_id("YWJj").is_err());
        assert!(decode_access_id("invalid!").is_err());
    }

    #[test]
    fn dates_normalize_offsets_and_enforce_window() {
        let now = crate::utils::time::parse("2026-11-13T00:00:00Z").expect("valid test timestamp");
        let (del, exp) = validate_dates_at(
            "2026-11-14T08:00:00+08:00",
            Some("2026-11-13T01:00:00Z"),
            now,
        )
        .expect("valid test fixture");
        assert_eq!(del, "2026-11-14T00:00:00.000Z");
        assert_eq!(exp.as_deref(), Some("2026-11-13T01:00:00.000Z"));
        assert!(validate_dates_at("2026-11-12T00:00:00Z", None, now).is_err());
        assert!(validate_dates_at("2026-12-15T00:00:00Z", None, now).is_err());
        assert!(
            validate_dates_at("2026-11-14T00:00:00Z", Some("2026-11-15T00:00:00Z"), now).is_err()
        );
    }
}

#[cfg(test)]
mod date_boundaries {
    use jiff::Timestamp;

    use super::validate_dates_at;

    #[test]
    fn thirty_one_day_window_is_inclusive_and_expiry_is_strict() {
        let now =
            crate::utils::time::parse("2026-11-13T03:00:00.123Z").expect("valid test fixture");
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
        assert!(
            validate_dates_at(
                "2026-11-14T03:00:00.123Z",
                Some("2026-11-12T22:00:00.123-05:00"),
                now
            )
            .is_err()
        );
        assert!(validate_dates_at("2026-11-14T03:00:00.123Z", Some("invalid"), now).is_err());
    }

    #[test]
    fn unsupported_date_window_returns_error_without_overflow() {
        assert!(validate_dates_at("9999-12-31T23:59:59.999999999Z", None, Timestamp::MAX).is_err());
    }
}
