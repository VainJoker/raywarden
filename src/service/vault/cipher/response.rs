//! Cipher response shape, persisted-row conversion and client compatibility
//! projections.
use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::{Map, Value, json};

use super::request::{
    CipherKind, is_data_blob_encrypted, is_valid_ssh_key, normalize_optional_rfc3339,
};
use crate::{
    errors::AppError, models::vault::cipher::CipherRow,
    service::vault::attachment::AttachmentResponse,
};
/// Client-facing cipher projection with custom protocol serialization.
#[derive(Debug)]
pub struct CipherResponse {
    pub id: String,
    pub organization_id: Option<String>,
    cipher_type: i32,
    data: Value,
    pub is_favorite: bool,
    pub folder_id: Option<String>,
    pub deleted_at: Option<String>,
    pub archived_at: Option<String>,
    created_at: String,
    pub updated_at: String,
    pub attachments: Option<Vec<AttachmentResponse>>,
}

impl TryFrom<CipherRow> for CipherResponse {
    type Error = AppError;
    fn try_from(row: CipherRow) -> Result<Self, Self::Error> {
        let data = serde_json::from_str(&row.data).map_err(AppError::internal_json(
            "Stored cipher payload is malformed",
        ))?;
        Ok(Self::from_row_and_data(row, data))
    }
}

impl CipherResponse {
    pub(super) fn from_row_and_data(row: CipherRow, data: Value) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            cipher_type: row.cipher_type,
            data,
            is_favorite: row.is_favorite != 0,
            folder_id: row.folder_id,
            deleted_at: row.deleted_at,
            archived_at: row.archived_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            attachments: None,
        }
    }
}

#[derive(Serialize)]
struct CipherPermissions {
    delete: bool,
    restore: bool,
}

impl Serialize for CipherResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let data = &self.data;
        let blob = data
            .get("data")
            .and_then(Value::as_str)
            .filter(|data| is_data_blob_encrypted(data));
        let structured = blob.is_none().then_some(data);
        let kind = structured.and(CipherKind::try_from(self.cipher_type).ok());
        let active = |expected, field| {
            if kind != Some(expected) {
                return Value::Null;
            }
            // Historical rows may be missing their active payload.
            data.get(field)
                .filter(|value| value.is_object())
                .cloned()
                .unwrap_or_else(|| json!({}))
        };
        let field = |key| structured.and_then(|data| data.get(key));

        // Keep historical field order and nulls. Only the opaque blob may be absent.
        let mut wire = serializer.serialize_map(None)?;
        wire.serialize_entry("archivedDate", &self.archived_at)?;
        wire.serialize_entry("attachments", &self.attachments)?;
        wire.serialize_entry(
            "bankAccount",
            &active(CipherKind::BankAccount, "bankAccount"),
        )?;
        wire.serialize_entry("card", &active(CipherKind::Card, "card"))?;
        wire.serialize_entry("collectionIds", &[(); 0])?;
        wire.serialize_entry("creationDate", &self.created_at)?;
        if let Some(blob) = blob {
            wire.serialize_entry("data", blob)?;
        }
        wire.serialize_entry("deletedDate", &self.deleted_at)?;
        wire.serialize_entry(
            "driversLicense",
            &active(CipherKind::DriversLicense, "driversLicense"),
        )?;
        wire.serialize_entry("edit", &true)?;
        wire.serialize_entry("favorite", &self.is_favorite)?;
        wire.serialize_entry("fields", &normalize_fields(field("fields")))?;
        wire.serialize_entry("folderId", &self.folder_id)?;
        wire.serialize_entry("id", &self.id)?;
        wire.serialize_entry("identity", &active(CipherKind::Identity, "identity"))?;
        wire.serialize_entry("key", &data.get("key"))?;
        let mut login = active(CipherKind::Login, "login");
        normalize_login(&mut login);
        wire.serialize_entry("login", &login)?;
        wire.serialize_entry("name", &field("name"))?;
        wire.serialize_entry("notes", &field("notes"))?;
        wire.serialize_entry("object", "cipherDetails")?;
        wire.serialize_entry("organizationId", &self.organization_id)?;
        wire.serialize_entry("organizationUseTotp", &false)?;
        wire.serialize_entry("passport", &active(CipherKind::Passport, "passport"))?;
        wire.serialize_entry(
            "passwordHistory",
            &normalize_password_history(field("passwordHistory")),
        )?;
        wire.serialize_entry("permissions", &CipherPermissions {
            delete: true,
            restore: true,
        })?;
        let reprompt = data
            .get("reprompt")
            .and_then(Value::as_i64)
            .filter(|v| *v == 0 || *v == 1)
            .unwrap_or(0);
        wire.serialize_entry("reprompt", &reprompt)?;
        wire.serialize_entry("revisionDate", &self.updated_at)?;
        let mut note = active(CipherKind::SecureNote, "secureNote");
        if kind == Some(CipherKind::SecureNote) {
            normalize_secure_note(&mut note);
        }
        wire.serialize_entry("secureNote", &note)?;
        let mut ssh_key = active(CipherKind::SshKey, "sshKey");
        normalize_ssh_key(&mut ssh_key);
        wire.serialize_entry("sshKey", &ssh_key)?;
        wire.serialize_entry("type", &self.cipher_type)?;
        wire.serialize_entry("viewPassword", &true)?;
        wire.end()
    }
}

fn normalize_object_array(
    value: Option<&Value>,
    mut normalize: impl FnMut(&mut Map<String, Value>) -> bool,
) -> Value {
    if value.is_none_or(Value::is_null) {
        return Value::Null;
    }
    Value::Array(
        value
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let mut entry = entry.as_object()?.clone();
                normalize(&mut entry).then_some(Value::Object(entry))
            })
            .collect(),
    )
}

fn normalize_fields(value: Option<&Value>) -> Value {
    normalize_object_array(value, |field| {
        let kind = match field.get("type") {
            Some(Value::Number(_)) => return true,
            Some(Value::String(value)) => value.parse::<u8>().unwrap_or(1),
            _ => 1,
        };
        field.insert("type".to_owned(), json!(kind));
        true
    })
}

fn normalize_password_history(value: Option<&Value>) -> Value {
    normalize_object_array(value, |entry| {
        if !entry.get("password").is_some_and(Value::is_string) {
            return false;
        }
        let last_used_date = normalized_date(entry.get("lastUsedDate").and_then(Value::as_str));
        entry.insert("lastUsedDate".to_owned(), last_used_date);
        true
    })
}

fn normalized_date(value: Option<&str>) -> Value {
    normalize_optional_rfc3339(value)
        .map_or_else(|| json!("1970-01-01T00:00:00.000000Z"), Value::String)
}

fn normalize_login(login: &mut Value) {
    let Value::Object(map) = login else {
        return;
    };

    if let Some(uris) = map.get_mut("uris").and_then(Value::as_array_mut) {
        for uri in uris {
            let Some(uri) = uri.as_object_mut() else {
                continue;
            };
            if let Some(Value::String(match_value)) = uri.get("match") {
                let match_value = match_value.parse::<u8>().map_or(Value::Null, |v| json!(v));
                uri.insert("match".to_string(), match_value);
            }
        }
    }

    if let Some(Value::String(password_revision_date)) = map.get("passwordRevisionDate") {
        map.insert(
            "passwordRevisionDate".to_owned(),
            normalized_date(Some(password_revision_date)),
        );
    }

    let first_uri = map
        .get("uris")
        .and_then(Value::as_array)
        .and_then(|uris| uris.first())
        .and_then(|uri| uri.get("uri"))
        .cloned();

    map.insert("uri".to_string(), first_uri.unwrap_or(Value::Null));
}

fn normalize_ssh_key(ssh_key: &mut Value) {
    if !is_valid_ssh_key(ssh_key) {
        *ssh_key = Value::Null;
    }
}

fn normalize_secure_note(secure_note: &mut Value) {
    let has_numeric_type = secure_note
        .as_object()
        .and_then(|map| map.get("type"))
        .is_some_and(Value::is_number);

    if !has_numeric_type {
        *secure_note = json!({ "type": 0 });
    }
}

#[cfg(test)]
mod tests {
    use super::{super::CipherRequest, *};

    fn cipher_fields(data: &Value, cipher_type: i32) -> Value {
        let row: CipherRow = serde_json::from_value(json!({
            "id": "cipher", "user_id": "owner", "organization_id": null,
            "cipher_type": cipher_type, "data": data.to_string(), "is_favorite": 0,
            "folder_id": null, "deleted_at": null, "created_at": "now", "updated_at": "now"
        }))
        .expect("fixture");
        serde_json::to_value(CipherResponse::from_row_and_data(row, data.clone())).expect("json")
    }

    #[test]
    fn projections_isolate_active_type_seal_blobs_and_reject_corrupt_json() {
        let blob = "{ \"format_version\": 2, \"data\": \"opaque\" }";
        let req: CipherRequest = serde_json::from_value(json!({
            "type": 8, "data": blob, "name": "ignored", "passport": {"number": "ignored"}, "key": "wrapped", "reprompt": 1
        }))
        .expect("blob req");
        let stored = serde_json::to_value(req.into_payload()).expect("stored");
        assert!(!stored.to_string().contains("ignored"));
        let sealed = cipher_fields(&stored, 8);
        assert_eq!(
            (sealed["data"].as_str(), sealed["passport"].is_null()),
            (Some(blob), true)
        );

        let login = cipher_fields(
            &json!({"login": null, "secureNote": {"type": 0}, "fields": [{"type": "3"}]}),
            1,
        );
        assert!(login["login"].is_object() && login["secureNote"].is_null());
        assert_eq!(login["fields"][0]["type"], 3);

        let corrupt: CipherRow = serde_json::from_value(json!({
            "id": "bad", "user_id": "owner", "organization_id": null, "cipher_type": 1,
            "data": "{broken", "is_favorite": 0, "folder_id": null, "deleted_at": null,
            "created_at": "now", "updated_at": "now"
        }))
        .expect("corrupt row");
        assert!(CipherResponse::try_from(corrupt).is_err());
    }
}
