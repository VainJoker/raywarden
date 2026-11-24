//! Cipher response shape, persisted-row conversion and client compatibility
//! projections.
use serde::{Serialize, Serializer};
use serde_json::{Value, json};

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
        let data = serde_json::from_str(&row.data).map_err(AppError::internal_error)?;
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

/// Field order follows the historical JSON map, including explicit nulls
/// for inactive and sealed fields. Only the opaque blob field can be absent.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CipherWireResponse<'a> {
    archived_date: Option<&'a str>,
    attachments: Option<&'a [AttachmentResponse]>,
    bank_account: Value,
    card: Value,
    collection_ids: [&'static str; 0],
    creation_date: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a str>,
    deleted_date: Option<&'a str>,
    drivers_license: Value,
    edit: bool,
    favorite: bool,
    fields: Value,
    folder_id: Option<&'a str>,
    id: &'a str,
    identity: Value,
    key: Option<&'a Value>,
    login: Value,
    name: Option<&'a Value>,
    notes: Option<&'a Value>,
    object: &'static str,
    #[serde(flatten)]
    organization: CipherOrganization<'a>,
    passport: Value,
    password_history: Value,
    permissions: CipherPermissions,
    reprompt: i64,
    revision_date: &'a str,
    secure_note: Value,
    ssh_key: Value,
    #[serde(rename = "type")]
    cipher_type: i32,
    view_password: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CipherOrganization<'a> {
    organization_id: Option<&'a str>,
    organization_use_totp: bool,
}

#[derive(Serialize)]
struct CipherPermissions {
    delete: bool,
    restore: bool,
}

impl Serialize for CipherResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.wire_response().serialize(serializer)
    }
}

impl CipherResponse {
    fn wire_response(&self) -> CipherWireResponse<'_> {
        let data = &self.data;
        let blob = data
            .get("data")
            .and_then(Value::as_str)
            .filter(|data| is_data_blob_encrypted(data));
        let sealed = blob.is_some();
        let mut wire = CipherWireResponse {
            archived_date: self.archived_at.as_deref(),
            attachments: self.attachments.as_deref(),
            bank_account: Value::Null,
            card: Value::Null,
            collection_ids: [],
            creation_date: &self.created_at,
            data: blob,
            deleted_date: self.deleted_at.as_deref(),
            drivers_license: Value::Null,
            edit: true,
            favorite: self.is_favorite,
            fields: Value::Null,
            folder_id: self.folder_id.as_deref(),
            id: &self.id,
            identity: Value::Null,
            key: data.get("key"),
            login: Value::Null,
            name: None,
            notes: None,
            object: "cipherDetails",
            organization: CipherOrganization {
                organization_id: self.organization_id.as_deref(),
                organization_use_totp: false,
            },
            passport: Value::Null,
            password_history: Value::Null,
            permissions: CipherPermissions {
                delete: true,
                restore: true,
            },
            reprompt: data
                .get("reprompt")
                .and_then(Value::as_i64)
                .filter(|v| *v == 0 || *v == 1)
                .unwrap_or(0),
            revision_date: &self.updated_at,
            secure_note: Value::Null,
            ssh_key: Value::Null,
            cipher_type: self.cipher_type,
            view_password: true,
        };
        if !sealed {
            wire.name = data.get("name");
            wire.notes = data.get("notes");
            wire.fields = normalize_fields(data.get("fields"));
            wire.password_history = normalize_password_history(data.get("passwordHistory"));
            if let Ok(kind) = CipherKind::try_from(self.cipher_type) {
                wire.project_active_fields(data, kind);
            }
        }
        wire
    }
}

impl CipherWireResponse<'_> {
    fn project_active_fields(&mut self, data: &Value, kind: CipherKind) {
        // Historical rows with missing active payloads get a client-safe
        // object while malformed JSON is rejected during row conversion.
        let active = |field| {
            data.get(field)
                .filter(|value| value.is_object())
                .cloned()
                .unwrap_or_else(|| json!({}))
        };
        match kind {
            CipherKind::Login => {
                self.login = active("login");
                normalize_login(&mut self.login);
            }
            CipherKind::SecureNote => {
                self.secure_note = active("secureNote");
                normalize_secure_note(&mut self.secure_note);
            }
            CipherKind::Card => self.card = active("card"),
            CipherKind::Identity => self.identity = active("identity"),
            CipherKind::SshKey => {
                self.ssh_key = active("sshKey");
                normalize_ssh_key(&mut self.ssh_key);
            }
            CipherKind::BankAccount => self.bank_account = active("bankAccount"),
            CipherKind::DriversLicense => self.drivers_license = active("driversLicense"),
            CipherKind::Passport => self.passport = active("passport"),
        }
    }
}

fn normalize_fields(value: Option<&Value>) -> Value {
    if value.is_none_or(Value::is_null) {
        return Value::Null;
    }
    let Some(fields) = value.and_then(Value::as_array) else {
        return Value::Array(Vec::new());
    };

    Value::Array(
        fields
            .iter()
            .filter_map(|field| {
                let mut field = field.as_object()?.clone();
                match field.get("type") {
                    Some(Value::Number(_)) => {}
                    Some(Value::String(value)) => {
                        let field_type = value.parse::<u8>().unwrap_or(1);
                        field.insert("type".to_string(), json!(field_type));
                    }
                    _ => {
                        field.insert("type".to_string(), json!(1));
                    }
                }
                Some(Value::Object(field))
            })
            .collect(),
    )
}

fn normalize_password_history(value: Option<&Value>) -> Value {
    if value.is_none_or(Value::is_null) {
        return Value::Null;
    }
    let Some(history) = value.and_then(Value::as_array) else {
        return Value::Array(Vec::new());
    };

    Value::Array(
        history
            .iter()
            .filter_map(|entry| {
                let mut entry = entry.as_object()?.clone();
                if !entry.get("password").is_some_and(Value::is_string) {
                    return None;
                }

                let last_used_date = entry
                    .get("lastUsedDate")
                    .and_then(Value::as_str)
                    .and_then(|value| normalize_optional_rfc3339(Some(value)))
                    .unwrap_or_else(|| "1970-01-01T00:00:00.000000Z".to_string());
                entry.insert("lastUsedDate".to_string(), json!(last_used_date));
                Some(Value::Object(entry))
            })
            .collect(),
    )
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
        let password_revision_date = normalize_optional_rfc3339(Some(password_revision_date))
            .unwrap_or_else(|| "1970-01-01T00:00:00.000000Z".to_string());
        map.insert(
            "passwordRevisionDate".to_string(),
            json!(password_revision_date),
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

    fn cipher_with_data(data: &Value, cipher_type: i32) -> CipherResponse {
        let row: CipherRow = serde_json::from_value(json!({
            "id": "cipher", "user_id": "owner", "organization_id": null,
            "cipher_type": cipher_type, "data": data.to_string(), "is_favorite": 0,
            "folder_id": null, "deleted_at": null, "created_at": "now", "updated_at": "now"
        }))
        .expect("valid cipher projection fixture");
        CipherResponse::from_row_and_data(row, data.clone())
    }

    fn cipher_fields(data: &Value, cipher_type: i32) -> Value {
        serde_json::to_value(cipher_with_data(data, cipher_type)).expect("valid cipher projection")
    }

    #[test]
    fn wire_snapshot_keeps_field_order_and_nulls_and_omits_missing_blob() {
        assert_eq!(
            serde_json::to_string(&cipher_with_data(&json!({"login": {}}), 1))
                .expect("valid cipher projection"),
            json!({
                "archivedDate": null, "attachments": null, "bankAccount": null,
                "card": null, "collectionIds": [], "creationDate": "now",
                "deletedDate": null, "driversLicense": null, "edit": true,
                "favorite": false, "fields": null, "folderId": null, "id": "cipher",
                "identity": null, "key": null, "login": {"uri": null}, "name": null,
                "notes": null, "object": "cipherDetails", "organizationId": null,
                "organizationUseTotp": false, "passport": null, "passwordHistory": null,
                "permissions": {"delete": true, "restore": true}, "reprompt": 0,
                "revisionDate": "now", "secureNote": null, "sshKey": null,
                "type": 1, "viewPassword": true
            })
            .to_string()
        );
    }

    #[test]
    fn sealed_blob_preserves_opaque_data_and_hides_structured_fields() {
        let blob = "{ \"format_version\": 2, \"data\": \"opaque\" }";
        let request: CipherRequest = serde_json::from_value(json!({"type":8,"data":blob,"name":"ignored","passport":{"number":"ignored"},"key":"wrapped","reprompt":1})).expect("valid cipher projection fixture");
        request
            .validate_for_personal_vault("owner")
            .expect("valid cipher projection fixture");
        let stored =
            serde_json::to_value(request.into_payload()).expect("valid cipher projection fixture");
        assert!(!stored.to_string().contains("ignored"));
        let response = cipher_fields(&stored, 8);
        assert_eq!(response["data"], blob);
        assert_eq!(response["key"], "wrapped");
        assert_eq!(response["reprompt"], 1);
        for field in [
            "name",
            "notes",
            "fields",
            "passwordHistory",
            "passport",
            "login",
        ] {
            assert_eq!(response[field], Value::Null);
        }
    }

    #[test]
    fn new_cipher_types_strip_client_response_properties_and_round_trip() {
        for (kind, field) in [(6, "bankAccount"), (7, "driversLicense"), (8, "passport")] {
            let request: CipherRequest=serde_json::from_value(json!({"type":kind,"name":"encrypted",field:{"encrypted":"opaque","response":{"transient":true}},"fields":[{"name":"encrypted","response":{}}]})).expect("valid cipher projection fixture");
            request
                .validate_for_personal_vault("owner")
                .expect("valid cipher projection fixture");
            let stored = serde_json::to_value(request.into_payload())
                .expect("valid cipher projection fixture");
            assert!(stored[field].get("response").is_none());
            assert!(stored["fields"][0].get("response").is_none());
            assert_eq!(cipher_fields(&stored, kind)[field]["encrypted"], "opaque");
        }
    }

    #[test]
    fn missing_historical_payloads_get_client_safe_objects() {
        let login = cipher_fields(&json!({"login":null,"fields":[{"type":"3"}]}), 1);
        assert!(login["login"].is_object());
        assert_eq!(login["login"]["uri"], Value::Null);
        assert_eq!(login["fields"][0]["type"], 3);
        assert_eq!(
            cipher_fields(&json!({}), 2)["secureNote"],
            json!({"type":0})
        );
        for (kind, field) in [
            (3, "card"),
            (4, "identity"),
            (6, "bankAccount"),
            (7, "driversLicense"),
            (8, "passport"),
        ] {
            assert!(cipher_fields(&json!({}), kind)[field].is_object());
        }
    }

    #[test]
    fn structured_payloads_only_expose_the_active_cipher_type() {
        let data = json!({"name":"encrypted","login":{"uris":[{"uri":"encrypted-uri"}]},"secureNote":{"type":0},"card":{"number":"encrypted"},"identity":{"name":"encrypted"},"sshKey":{"publicKey":"encrypted","privateKey":"encrypted","keyFingerprint":"encrypted"},"bankAccount":{},"driversLicense":{},"passport":{}});
        let names = [
            "login",
            "secureNote",
            "card",
            "identity",
            "sshKey",
            "bankAccount",
            "driversLicense",
            "passport",
        ];
        for kind in 1..=8 {
            let fields = cipher_fields(&data, kind);
            for (index, name) in names.iter().enumerate() {
                if index + 1 == kind as usize {
                    assert!(fields[*name].is_object());
                } else {
                    assert_eq!(fields[*name], Value::Null);
                }
            }
        }
    }

    #[test]
    fn invalid_stored_json_fails_conversion_instead_of_fabricating_empty_content() {
        let row:CipherRow=serde_json::from_value(json!({"id":"bad","user_id":"owner","organization_id":null,"cipher_type":1,"data":"{broken","is_favorite":0,"folder_id":null,"deleted_at":null,"created_at":"now","updated_at":"now"})).expect("valid cipher projection fixture");
        assert!(CipherResponse::try_from(row).is_err());
    }

    #[test]
    fn item_key_survives_request_storage_and_response() -> Result<(), serde_json::Error> {
        let request: CipherRequest = serde_json::from_value(json!({
            "type": 1, "name": "encrypted-name", "key": "wrapped-item-key",
            "login": { "password": "encrypted-password" }
        }))?;
        let data = request.into_payload();
        let row: CipherRow = serde_json::from_value(json!({
            "id": "cipher", "user_id": "owner", "organization_id": null,
            "cipher_type": 1, "data": serde_json::to_string(&data)?, "is_favorite": 0,
            "folder_id": null, "deleted_at": null,
            "archived_at": "2026-01-01T00:00:00.000Z",
            "created_at": "2025-01-01T00:00:00.000Z",
            "updated_at": "2026-01-01T00:00:00.000Z"
        }))?;
        let response = serde_json::to_value(
            CipherResponse::try_from(row).expect("valid cipher projection fixture"),
        )?;
        assert_eq!(response["key"], "wrapped-item-key");
        assert_eq!(response["archivedDate"], "2026-01-01T00:00:00.000Z");
        assert_eq!(response["login"]["password"], "encrypted-password");
        assert_eq!(response["favorite"], false);
        assert_eq!(response["organizationUseTotp"], false);
        assert_eq!(response["collectionIds"], json!([]));
        assert_eq!(
            response["permissions"],
            json!({"delete":true,"restore":true})
        );
        Ok(())
    }
}
