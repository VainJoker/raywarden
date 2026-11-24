//! Cipher requests, encrypted payload validation and stored payload
//! construction.
use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;

use crate::errors::{AppError, AppResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum CipherKind {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
    SshKey = 5,
    BankAccount = 6,
    DriversLicense = 7,
    Passport = 8,
}

impl From<CipherKind> for i32 {
    fn from(kind: CipherKind) -> Self {
        kind as Self
    }
}

impl TryFrom<i32> for CipherKind {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Login),
            2 => Ok(Self::SecureNote),
            3 => Ok(Self::Card),
            4 => Ok(Self::Identity),
            5 => Ok(Self::SshKey),
            6 => Ok(Self::BankAccount),
            7 => Ok(Self::DriversLicense),
            8 => Ok(Self::Passport),
            _ => Err(()),
        }
    }
}

impl Serialize for CipherKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32((*self).into())
    }
}

impl<'de> Deserialize<'de> for CipherKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i32::deserialize(deserializer)?;
        Self::try_from(value).map_err(|()| {
            de::Error::invalid_value(
                de::Unexpected::Signed(i64::from(value)),
                &"a valid cipher type (1=Login, 2=SecureNote, 3=Card, 4=Identity, 5=SshKey)",
            )
        })
    }
}

/// Common cipher type-specific fields shared across multiple cipher structures.
/// These represent the encrypted content fields that vary based on cipher type.
/// Used with `#[serde(flatten)]` to embed these fields into other structs.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherPayloadFields {
    // Per-item key wrapped by the user's symmetric key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    // Only one of these should exist, depending on cipher type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_account: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drivers_license: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passport: Option<Value>,
    // Common fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<i32>,
}

impl CipherPayloadFields {
    const fn active(&self, kind: CipherKind) -> Option<&Value> {
        match kind {
            CipherKind::Login => &self.login,
            CipherKind::SecureNote => &self.secure_note,
            CipherKind::Card => &self.card,
            CipherKind::Identity => &self.identity,
            CipherKind::SshKey => &self.ssh_key,
            CipherKind::BankAccount => &self.bank_account,
            CipherKind::DriversLicense => &self.drivers_license,
            CipherKind::Passport => &self.passport,
        }
        .as_ref()
    }
}

/// This struct represents the data stored in the `data` column of the `ciphers`
/// table.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherPayload {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub payload_fields: CipherPayloadFields,
}

/// Represents the "Cipher" object within incoming request payloads.
/// Used for create, update, import, and key rotation scenarios.
/// Aligned with vaultwarden's `CipherData` structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequest {
    // Id is optional as it is included only in bulk share / key rotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    // Folder id is not included in import (determined by folder_relationships)
    #[serde(default, deserialize_with = "deserialize_optional_nonempty_string")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(alias = "organizationID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub cipher_type: CipherKind,
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    #[serde(rename = "favorite")]
    pub is_favorite: Option<bool>,
    #[serde(flatten)]
    pub payload_fields: CipherPayloadFields,
    // The revision datetime (in ISO 8601 format) of the client's local copy
    // Used to prevent updating a cipher when client doesn't have the latest
    // version
    #[serde(
        rename = "lastKnownRevisionDate",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_known_revision_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "attachments2")]
    pub attachment_key_updates: Option<HashMap<String, RotateAttachmentRequest>>,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    #[serde(default, rename = "archivedDate")]
    pub archived_at: Option<String>,
    #[serde(default, alias = "encryptedByUserId")]
    pub encrypted_for: Option<String>,
    #[serde(default)]
    pub encrypted_by_key_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RotateAttachmentRequest {
    pub file_name: String,
    pub key: String,
}

/// Represents the full request payload for creating a cipher with collections.
/// Supports both camelCase and `PascalCase` for compatibility with different
/// clients.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCipherWithCollectionsRequest {
    #[serde(alias = "Cipher")]
    pub cipher: CipherRequest,
    #[serde(default)]
    #[serde(alias = "CollectionIds")]
    pub collection_ids: Vec<String>,
}

/// Request body for updating a cipher partially (PUT /api/ciphers/{id}/partial)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCipherPartialRequest {
    #[serde(default, deserialize_with = "deserialize_optional_nonempty_string")]
    pub folder_id: Option<String>,
    #[serde(rename = "favorite")]
    pub is_favorite: bool,
}

impl CipherPayload {
    fn sealed(data: String, key: Option<String>, reprompt: Option<i32>) -> Self {
        Self {
            name: String::new(),
            data: Some(data),
            notes: None,
            payload_fields: CipherPayloadFields {
                key,
                reprompt,
                ..Default::default()
            },
        }
    }

    fn from_fields(
        name: Option<String>,
        notes: Option<String>,
        mut payload_fields: CipherPayloadFields,
    ) -> Self {
        for value in [
            &mut payload_fields.login,
            &mut payload_fields.card,
            &mut payload_fields.identity,
            &mut payload_fields.secure_note,
            &mut payload_fields.ssh_key,
            &mut payload_fields.bank_account,
            &mut payload_fields.drivers_license,
            &mut payload_fields.passport,
        ]
        .into_iter()
        .flatten()
        {
            if let Some(object) = value.as_object_mut() {
                object.remove("response");
                if let Some(uris) = object.get_mut("uris").and_then(Value::as_array_mut) {
                    for uri in uris.iter_mut().filter_map(Value::as_object_mut) {
                        uri.remove("response");
                    }
                }
            }
        }
        if let Some(fields) = payload_fields.fields.as_mut().and_then(Value::as_array_mut) {
            for field in fields.iter_mut().filter_map(Value::as_object_mut) {
                field.remove("response");
            }
        }
        Self {
            name: name.unwrap_or_default(),
            data: None,
            notes,
            payload_fields,
        }
    }
}

pub(super) fn deserialize_optional_nonempty_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.filter(|value| !value.is_empty()))
}

pub(super) fn is_data_blob_encrypted(data: &str) -> bool {
    serde_json::from_str::<Value>(data).is_ok_and(|value| value.get("format_version").is_some())
}

pub(super) fn is_valid_ssh_key(ssh_key: &Value) -> bool {
    ssh_key.as_object().is_some_and(|ssh_key| {
        ["keyFingerprint", "privateKey", "publicKey"]
            .iter()
            .all(|field| {
                ssh_key
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
    })
}

pub fn normalize_optional_rfc3339(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }

    crate::utils::time::parse(value)
        .ok()
        .map(crate::utils::time::format_micros)
}

pub fn client_revision_is_stale(server_revision: &str, client_revision: Option<&str>) -> bool {
    let Some(client_revision) = client_revision else {
        return false;
    };
    let (Ok(server_revision), Ok(client_revision)) = (
        crate::utils::time::parse(server_revision),
        crate::utils::time::parse(client_revision),
    ) else {
        return false;
    };

    server_revision.duration_since(client_revision).as_secs() > 1
}

impl CipherRequest {
    pub(crate) fn into_payload(self) -> CipherPayload {
        if let Some(data) = self.data.filter(|value| is_data_blob_encrypted(value)) {
            CipherPayload::sealed(data, self.payload_fields.key, self.payload_fields.reprompt)
        } else {
            CipherPayload::from_fields(self.name, self.notes, self.payload_fields)
        }
    }

    pub fn is_blob(&self) -> bool {
        self.data.as_deref().is_some_and(is_data_blob_encrypted)
    }
    fn ensure_encrypted_for(&self, user_id: &str) -> AppResult<()> {
        if self
            .encrypted_for
            .as_deref()
            .is_some_and(|id| id != user_id)
        {
            return Err(AppError::bad_request(
                "Cipher was not encrypted for the current user",
            ));
        }
        Ok(())
    }

    pub fn validate_encryption_context(
        &self,
        user_id: &str,
        user_key_id: Option<&str>,
    ) -> AppResult<()> {
        self.ensure_encrypted_for(user_id)?;
        if let Some(key_id) = self.encrypted_by_key_id.as_deref() {
            if user_key_id != Some(key_id)
                && !crate::service::identity::account_keys::is_valid_key_id(key_id)
            {
                if user_key_id.is_some() && uuid::Uuid::parse_str(key_id).is_ok() {
                    return Err(AppError::conflict(
                        "Cipher was not encrypted with the current user key",
                    ));
                }
                return Err(AppError::bad_request(
                    "Key IDs must be 32 lowercase hexadecimal characters",
                ));
            }
            if user_key_id.is_some_and(|id| id != key_id) {
                return Err(AppError::conflict(
                    "Cipher was not encrypted with the current user key",
                ));
            }
        }
        Ok(())
    }
    pub fn validate_for_personal_vault(&self, user_id: &str) -> AppResult<()> {
        self.ensure_personal()?;
        if !self.collection_ids.is_empty() {
            return Err(AppError::bad_request("Collections are not supported"));
        }
        self.ensure_encrypted_for(user_id)?;
        if self.data.as_ref().is_some_and(|data| data.len() > 500_000) {
            return Err(AppError::bad_request("Data exceeds 500000 bytes"));
        }
        let active = self.payload_fields.active(self.cipher_type);
        if self.is_blob() {
            return Ok(());
        }
        if self
            .name
            .as_deref()
            .is_none_or(|name| name.trim().is_empty())
        {
            return Err(AppError::bad_request("The Name field is required"));
        }
        if !active.is_some_and(Value::is_object) {
            return Err(AppError::bad_request("Cipher type data is missing"));
        }
        if self.cipher_type == CipherKind::SshKey && !active.is_some_and(is_valid_ssh_key) {
            return Err(AppError::bad_request(
                "SSH key is missing required encrypted fields",
            ));
        }
        Ok(())
    }
    pub fn ensure_personal(&self) -> AppResult<()> {
        if self.organization_id.is_some() {
            return Err(AppError::bad_request("Organizations are not supported"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn renamed_cipher_fields_keep_the_client_protocol_names() {
        let request: CipherRequest = serde_json::from_value(json!({
            "type": 1, "name": "encrypted", "login": {}, "favorite": true,
            "attachments2": {"file": {"fileName": "encrypted-name", "key": "wrapped-key"}}
        }))
        .expect("valid cipher payload fixture");
        assert_eq!(request.cipher_type, CipherKind::Login);
        assert_eq!(request.is_favorite, Some(true));
        let response = serde_json::to_value(request).expect("valid cipher payload fixture");
        assert_eq!(response["type"], 1);
        assert_eq!(response["favorite"], true);
        assert_eq!(response["attachments2"]["file"]["key"], "wrapped-key");
        for internal in ["cipherType", "isFavorite", "attachmentKeyUpdates"] {
            assert!(response.get(internal).is_none());
        }
    }

    #[test]
    fn encryption_context_accepts_matching_legacy_id_but_rejects_other_users_and_old_keys() {
        let legacy = "00000000-0000-4000-8000-000000000001";
        let request: CipherRequest=serde_json::from_value(json!({"type":1,"name":"encrypted","login":{},"encryptedFor":"owner","encryptedByKeyId":legacy})).expect("valid cipher projection fixture");
        request
            .validate_encryption_context("owner", Some(legacy))
            .expect("valid cipher projection fixture");
        assert!(matches!(
            request.validate_encryption_context("owner", Some("0123456789abcdef0123456789abcdef")),
            Err(AppError::Conflict { .. })
        ));
        assert!(
            request
                .validate_encryption_context("other", Some(legacy))
                .is_err()
        );
        let request: CipherRequest = serde_json::from_value(
            json!({"type":1,"name":"encrypted","login":{},"collectionIds":["unsupported"]}),
        )
        .expect("valid cipher projection fixture");
        assert!(request.validate_for_personal_vault("owner").is_err());
    }

    #[test]
    fn personal_vault_rejects_organization_items() -> Result<(), serde_json::Error> {
        let request: CipherRequest = serde_json::from_value(json!({
            "type": 1, "name": "encrypted", "organizationId": "another-org"
        }))?;
        assert!(request.ensure_personal().is_err());
        Ok(())
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::{client_revision_is_stale, normalize_optional_rfc3339};

    #[test]
    fn offset_inputs_normalize_to_utc_microseconds() {
        for input in [
            "2026-11-13T11:00:00.123456+08:00",
            "2026-11-12T22:00:00.123456-05:00",
            "2026-11-13T03:00:00.123456Z",
        ] {
            assert_eq!(
                normalize_optional_rfc3339(Some(input)).as_deref(),
                Some("2026-11-13T03:00:00.123456Z")
            );
        }
        assert_eq!(normalize_optional_rfc3339(Some("invalid")), None);
        assert_eq!(normalize_optional_rfc3339(Some("  ")), None);
    }

    #[test]
    fn revision_grace_keeps_whole_second_truncation_and_compares_instants() {
        let client = Some("2026-11-13T11:00:00+08:00");
        assert!(!client_revision_is_stale(
            "2026-11-13T03:00:01.999999999Z",
            client
        ));
        assert!(client_revision_is_stale("2026-11-13T03:00:02Z", client));
        assert!(!client_revision_is_stale(
            "2026-11-12T22:00:00-05:00",
            client
        ));
        assert!(!client_revision_is_stale("2026-11-13T02:59:58Z", client));
        assert!(!client_revision_is_stale("invalid", client));
    }
}
