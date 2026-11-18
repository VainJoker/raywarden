//! Send rows, request types and their non-SQL behavior.
use base64::{
    Engine as _,
    engine::general_purpose::{
        STANDARD,
        URL_SAFE_NO_PAD,
    },
};
use jiff::{
    SignedDuration,
    Timestamp,
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};

use crate::{
    errors::AppError,
    infra::crypto,
};

pub(super) const SEND_INACCESSIBLE_MSG: &str =
    "Send does not exist or is no longer available";
pub(super) const MAX_FILE_BYTES: i64 = 95 * 1024 * 1024;
pub(super) const MAX_TEXT_BYTES: usize = 1_887_436;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    pub(super) fn value(&self) -> Result<i64, AppError> {
        match self {
            Self::Number(n) => Ok(*n),
            Self::String(s) => s
                .trim()
                .parse()
                .map_err(|_| AppError::bad_request("Invalid number")),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SendRequestData {
    #[serde(rename = "id")]
    pub _id:              Option<String>,
    #[serde(rename = "type")]
    pub send_type:        i32,
    pub key:              String,
    pub name:             String,
    pub notes:            Option<String>,
    pub text:             Option<Value>,
    pub file:             Option<Value>,
    pub file_length:      Option<NumberOrString>,
    pub password:         Option<String>,
    #[serde(default, deserialize_with = "deserialize_access_limit")]
    pub max_access_count: Option<NumberOrString>,
    pub expiration_date:  Option<String>,
    pub deletion_date:    String,
    pub disabled:         Option<bool>,
    pub hide_email:       Option<bool>,
    pub emails:           Option<String>,
}

/// A Send has its own encryption key; account rotation only rewraps that key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateSendData {
    pub id:  String,
    pub key: String,
}

fn deserialize_access_limit<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<NumberOrString>, D::Error> {
    let limit = Option::<NumberOrString>::deserialize(deserializer)?;
    if matches!(&limit, Some(NumberOrString::String(value)) if value.trim().is_empty())
    {
        return Ok(None);
    }
    if let Some(value) = &limit {
        let value = value.value().map_err(serde::de::Error::custom)?;
        i32::try_from(value).map_err(serde::de::Error::custom)?;
    }
    Ok(limit)
}

pub(super) fn file_size_name(bytes: i64) -> String {
    let mut size = bytes as f64;
    let mut unit = 0;
    let units = ["bytes", "KB", "MB", "GB", "TB", "PB"];
    while size > 1024.0 && unit + 1 < units.len() {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.2} {}", units[unit])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SendDB {
    pub id:               String,
    pub user_id:          String,
    pub name:             String,
    pub notes:            Option<String>,
    #[serde(rename = "type")]
    pub send_type:        i32,
    pub data:             String,
    pub akey:             String,
    pub password_hash:    Option<String>,
    pub password_salt:    Option<String>,
    pub password_iter:    Option<i32>,
    pub max_access_count: Option<i64>,
    pub access_count:     i64,
    pub created_at:       String,
    pub updated_at:       String,
    pub expiration_date:  Option<String>,
    pub deletion_date:    String,
    pub disabled:         i32,
    pub hide_email:       i32,
    pub access_stamp:     String,
    pub file_id:          Option<String>,
    pub file_size:        i64,
    pub pending:          i32,
    #[serde(default)]
    pub storage_key:      Option<String>,
}

pub(super) fn now_string() -> String {
    crate::infra::time::now_rfc3339()
}

pub(super) fn inaccessible() -> AppError {
    AppError::not_found(SEND_INACCESSIBLE_MSG)
}

pub(super) fn access_id_from_uuid(id: &str) -> Result<String, AppError> {
    let id = uuid::Uuid::parse_str(id).map_err(|_| inaccessible())?;
    Ok(URL_SAFE_NO_PAD.encode(id.as_bytes()))
}

pub(super) fn uuid_from_access_id(id: &str) -> Result<String, AppError> {
    let bytes = URL_SAFE_NO_PAD.decode(id).map_err(|_| inaccessible())?;
    uuid::Uuid::from_slice(&bytes)
        .map(|id| id.to_string())
        .map_err(|_| inaccessible())
}

pub(super) fn validate_send_dates(
    deletion_date: &str,
    expiration_date: Option<&str>,
) -> Result<(String, Option<String>), AppError> {
    validate_dates_at(deletion_date, expiration_date, crate::infra::time::now())
}

fn validate_dates_at(
    deletion_date: &str,
    expiration_date: Option<&str>,
    now: Timestamp,
) -> Result<(String, Option<String>), AppError> {
    let parse = |s: &str| {
        crate::infra::time::parse(s)
            .map_err(|_| AppError::bad_request("Invalid Send date"))
    };
    let deletion = parse(deletion_date)?;
    let latest = now
        .checked_add(SignedDuration::from_secs(31 * 86_400))
        .map_err(|_| {
            AppError::bad_request(
                "Send date window exceeds the supported timestamp range",
            )
        })?;
    if deletion <= now || deletion > latest {
        return Err(AppError::bad_request(
            "Send deletion must be within the next 31 days",
        ));
    }
    let expiration = expiration_date.map(parse).transpose()?;
    if expiration
        .as_ref()
        .is_some_and(|d| *d <= now || *d > deletion)
    {
        return Err(AppError::bad_request(
            "Send expiration must be in the future and no later than deletion",
        ));
    }
    Ok((
        crate::infra::time::format_millis(deletion),
        expiration.map(crate::infra::time::format_millis),
    ))
}

impl SendRequestData {
    pub(super) fn validate(&self) -> Result<(), AppError> {
        if !matches!(self.send_type, 0 | 1) {
            return Err(AppError::bad_request("Unsupported Send type"));
        }
        if self.emails.is_some() {
            return Err(AppError::bad_request(
                "Send email verification is not supported",
            ));
        }
        if self.name.is_empty() || self.key.is_empty() {
            return Err(AppError::bad_request(
                "Send name and key are required",
            ));
        }
        if self.max_count()?.is_some_and(|n| n < 0) {
            return Err(AppError::bad_request(
                "Maximum access count cannot be negative",
            ));
        }
        Ok(())
    }

    pub(super) fn max_count(&self) -> Result<Option<i64>, AppError> {
        self.max_access_count
            .as_ref()
            .map(NumberOrString::value)
            .transpose()
    }

    pub(super) fn content(&self) -> Result<Value, AppError> {
        let mut content = match self.send_type {
            0 => self.text.clone(),
            1 => self.file.clone(),
            _ => None,
        }
        .ok_or_else(|| AppError::bad_request("Send content is required"))?;
        let object = content
            .as_object_mut()
            .ok_or_else(|| AppError::bad_request("Invalid Send content"))?;
        object.remove("response");
        if self.send_type == 0 &&
            !object.get("text").is_some_and(Value::is_string)
        {
            return Err(AppError::bad_request(
                "Encrypted Send text is required",
            ));
        }
        if self.send_type == 1 &&
            !object.get("fileName").is_some_and(Value::is_string)
        {
            return Err(AppError::bad_request(
                "Encrypted file name is required",
            ));
        }
        if serde_json::to_vec(&content)
            .map_err(|_| AppError::Internal)?
            .len() >
            MAX_TEXT_BYTES
        {
            return Err(AppError::bad_request(
                "Send content exceeds the size limit",
            ));
        }
        Ok(content)
    }
}

impl SendDB {
    pub(super) fn new(
        user_id: String,
        payload: &SendRequestData,
    ) -> Result<Self, AppError> {
        payload.validate()?;
        let (deletion_date, expiration_date) = validate_send_dates(
            &payload.deletion_date,
            payload.expiration_date.as_deref(),
        )?;
        let now = now_string();
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            name: payload.name.clone(),
            notes: payload.notes.clone(),
            send_type: payload.send_type,
            data: serde_json::to_string(&payload.content()?)
                .map_err(|_| AppError::Internal)?,
            akey: payload.key.clone(),
            password_hash: None,
            password_salt: None,
            password_iter: None,
            max_access_count: payload.max_count()?,
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            expiration_date,
            deletion_date,
            disabled: i32::from(payload.disabled.unwrap_or(false)),
            hide_email: i32::from(payload.hide_email.unwrap_or(false)),
            access_stamp: uuid::Uuid::new_v4().to_string(),
            file_id: None,
            file_size: 0,
            pending: 0,
            storage_key: None,
        })
    }

    pub(super) async fn set_password(
        &mut self,
        password: Option<&str>,
    ) -> Result<(), AppError> {
        if let Some(password) = password.filter(|p| !p.is_empty()) {
            if password.len() > 4096 {
                return Err(AppError::bad_request("Send password is too long"));
            }
            let salt = crypto::generate_salt()?;
            self.password_hash =
                Some(crypto::hash_password_for_storage(password, &salt).await?);
            self.password_salt = Some(salt);
            self.password_iter = Some(100_000);
        } else {
            self.password_hash = None;
            self.password_salt = None;
            self.password_iter = None;
        }
        Ok(())
    }

    pub(super) async fn check_password(
        &self,
        password: Option<&str>,
    ) -> Result<(), AppError> {
        let Some(hash) = &self.password_hash else {
            return Ok(());
        };
        let password = password
            .filter(|p| !p.is_empty() && p.len() <= 4096)
            .ok_or_else(|| AppError::Unauthorized {
                message: "Send password required".into(),
            })?;
        let salt = self.password_salt.as_deref().ok_or(AppError::Internal)?;
        if !crypto::verify_password(password, hash, salt).await? {
            return Err(AppError::bad_request("Invalid Send password"));
        }
        Ok(())
    }

    pub(super) fn validate_access(
        &self,
        check_count: bool,
    ) -> Result<(), AppError> {
        let now = crate::infra::time::now();
        if self.pending != 0 ||
            self.disabled != 0 ||
            crate::infra::time::parse(&self.deletion_date)
                .map_or(true, |date| date <= now) ||
            self.expiration_date.as_ref().is_some_and(|date| {
                crate::infra::time::parse(date).map_or(true, |date| date <= now)
            }) ||
            (check_count &&
                self.max_access_count
                    .is_some_and(|n| self.access_count >= n))
        {
            return Err(inaccessible());
        }
        Ok(())
    }

    pub(super) fn storage_key(&self) -> Option<String> {
        self.file_id.as_ref().map(|id| {
            self.storage_key
                .clone()
                .unwrap_or_else(|| format!("sends/{}/{id}", self.id))
        })
    }

    fn content(&self) -> Value {
        let mut data: Value =
            serde_json::from_str(&self.data).unwrap_or(Value::Null);
        if self.send_type == 1 &&
            let Some(object) = data.as_object_mut()
        {
            object.insert("id".into(), json!(self.file_id));
            object.insert("size".into(), json!(self.file_size.to_string()));
            object.insert(
                "sizeName".into(),
                json!(file_size_name(self.file_size)),
            );
        }
        data
    }

    pub(super) fn to_json(&self) -> Value {
        let content = self.content();
        json!({"id": self.id, "accessId": access_id_from_uuid(&self.id).ok(),
            "type": self.send_type, "name": self.name, "notes": self.notes,
            "text": if self.send_type == 0 { Some(&content) } else { None },
            "file": if self.send_type == 1 { Some(&content) } else { None },
            "key": self.akey, "maxAccessCount": self.max_access_count,
            "accessCount": self.access_count, "revisionDate": self.updated_at,
            "expirationDate": self.expiration_date, "deletionDate": self.deletion_date,
            "disabled": self.disabled != 0, "hideEmail": self.hide_email != 0,
            "password": self.password_hash.as_ref().and_then(|hash| STANDARD.decode(hash).ok()).map(|hash| URL_SAFE_NO_PAD.encode(hash)),
            "authType": if self.password_hash.is_some() { 1 } else { 2 }, "object": "send"})
    }

    pub(super) fn to_access_json(
        &self,
        creator_identifier: Option<&str>,
    ) -> Value {
        let content = self.content();
        json!({"id": access_id_from_uuid(&self.id).ok(), "type": self.send_type, "name": self.name,
            "text": if self.send_type == 0 { Some(&content) } else { None },
            "file": if self.send_type == 1 { Some(&content) } else { None },
            "expirationDate": self.expiration_date,
            "creatorIdentifier": creator_identifier, "object": "send-access"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        json!({"type":0,"name":"encrypted","key":"wrapped-key",
            "text":{"text":"ciphertext"},
            "deletionDate":crate::infra::time::now().checked_add(SignedDuration::from_secs(86_400)).expect("test clock supports a day").to_string()})
    }

    #[test]
    fn access_limits_reject_i32_overflow_and_owner_responses_use_real_password_verifier()
     {
        for limit in [
            json!(4_294_967_297_i64),
            json!("4294967297"),
            json!(-2_147_483_649_i64),
        ] {
            let mut value = request();
            value["maxAccessCount"] = limit;
            assert!(serde_json::from_value::<SendRequestData>(value).is_err());
        }
        let mut value = request();
        value["maxAccessCount"] = json!(" 2 ");
        let payload: SendRequestData =
            serde_json::from_value(value).expect("valid limit");
        assert_eq!(payload.max_count().expect("count"), Some(2));
        let mut send = SendDB::new("owner".into(), &payload).expect("send");
        assert_eq!(send.to_json()["password"], Value::Null);
        send.password_hash = Some(STANDARD.encode([255_u8; 32]));
        assert_eq!(
            send.to_json()["password"],
            json!(URL_SAFE_NO_PAD.encode([255_u8; 32]))
        );
        assert_eq!(
            send.to_access_json(None)["id"],
            json!(access_id_from_uuid(&send.id).expect("access ID"))
        );
        assert!(send.to_access_json(None).get("key").is_none());
        let mut value = request();
        value["id"] = json!(12);
        assert!(serde_json::from_value::<SendRequestData>(value).is_err());
        let mut value = request();
        value["id"] = json!("ignored-client-id");
        let payload: SendRequestData = serde_json::from_value(value).unwrap();
        assert_eq!(payload._id.as_deref(), Some("ignored-client-id"));
    }

    #[test]
    fn rotation_accepts_only_id_and_key_and_ignores_unrelated_client_fields() {
        let minimal: RotateSendData =
            serde_json::from_value(json!({"id":"send","key":"rewrapped"}))
                .expect("minimal rotation");
        assert_eq!(minimal.key, "rewrapped");
        let extra: RotateSendData =
            serde_json::from_value(json!({"id":"send","key":"rewrapped",
            "type":99,"name":"must-be-ignored","notes":"ignored","file":false,
            "text":[],"deletionDate":"invalid-date","disabled":true}))
            .expect("unrelated fields ignored");
        assert_eq!(extra.id, minimal.id);
        assert_eq!(extra.key, minimal.key);
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
            assert_eq!(file_size_name(size), expected);
        }
        let payload: SendRequestData =
            serde_json::from_value(request()).expect("payload");
        let mut send = SendDB::new("owner".into(), &payload).expect("send");
        let offset = jiff::tz::Offset::from_hours(8).expect("offset");
        send.deletion_date = crate::infra::time::now()
            .checked_sub(SignedDuration::from_hours(1))
            .expect("test clock supports an hour")
            .display_with_offset(offset)
            .to_string();
        assert!(send.validate_access(false).is_err());
    }

    #[test]
    fn access_ids_use_uuid_bytes_and_reject_invalid_lengths() {
        let id = "00112233-4455-6677-8899-aabbccddeeff";
        let access = access_id_from_uuid(id).unwrap();
        assert_eq!(access, "ABEiM0RVZneImaq7zN3u_w");
        assert_eq!(uuid_from_access_id(&access).unwrap(), id);
        assert!(uuid_from_access_id("YWJj").is_err());
        assert!(uuid_from_access_id("invalid!").is_err());
    }

    #[test]
    fn dates_normalize_offsets_and_enforce_window() {
        let now = crate::infra::time::parse("2026-11-13T00:00:00Z")
            .expect("valid test timestamp");
        let (del, exp) = validate_dates_at(
            "2026-11-14T08:00:00+08:00",
            Some("2026-11-13T01:00:00Z"),
            now,
        )
        .unwrap();
        assert_eq!(del, "2026-11-14T00:00:00.000Z");
        assert_eq!(exp.as_deref(), Some("2026-11-13T01:00:00.000Z"));
        assert!(validate_dates_at("2026-11-12T00:00:00Z", None, now).is_err());
        assert!(validate_dates_at("2026-12-15T00:00:00Z", None, now).is_err());
        assert!(
            validate_dates_at(
                "2026-11-14T00:00:00Z",
                Some("2026-11-15T00:00:00Z"),
                now
            )
            .is_err()
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
            crate::infra::time::parse("2026-11-13T03:00:00.123Z").unwrap();
        assert!(
            validate_dates_at(
                "2026-12-14T03:00:00.123Z",
                Some("2026-12-14T03:00:00.123Z"),
                now
            )
            .is_ok()
        );
        assert!(
            validate_dates_at("2026-12-14T03:00:00.124Z", None, now).is_err()
        );
        assert!(
            validate_dates_at("2026-11-13T11:00:00.123+08:00", None, now)
                .is_err()
        );
        assert!(
            validate_dates_at(
                "2026-11-14T03:00:00.123Z",
                Some("2026-11-12T22:00:00.123-05:00"),
                now
            )
            .is_err()
        );
        assert!(
            validate_dates_at("2026-11-14T03:00:00.123Z", Some("invalid"), now)
                .is_err()
        );
    }

    #[test]
    fn unsupported_date_window_returns_error_without_overflow() {
        assert!(
            validate_dates_at(
                "9999-12-31T23:59:59.999999999Z",
                None,
                Timestamp::MAX
            )
            .is_err()
        );
    }
}
