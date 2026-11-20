//! Cipher response shape, persisted-row conversion and client compatibility
//! projections.
use serde::{
    Serialize,
    Serializer,
};
use serde_json::{
    Map,
    Value,
    json,
};

use super::request::{
    is_data_blob_encrypted,
    is_valid_ssh_key,
    normalize_optional_rfc3339,
};
use crate::{
    errors::AppError,
    models::vault::cipher::CipherRow,
    service::vault::attachment::AttachmentResponse,
};
/// Client-facing cipher projection with custom protocol serialization.
#[derive(Debug)]
pub struct CipherResponse {
    pub id:              String,
    pub organization_id: Option<String>,
    cipher_type:         i32,
    data:                Value,
    pub is_favorite:     bool,
    pub folder_id:       Option<String>,
    pub deleted_at:      Option<String>,
    pub archived_at:     Option<String>,
    created_at:          String,
    pub updated_at:      String,
    pub attachments:     Option<Vec<AttachmentResponse>>,
}

impl TryFrom<CipherRow> for CipherResponse {
    type Error = AppError;
    fn try_from(row: CipherRow) -> Result<Self, Self::Error> {
        let data = serde_json::from_str(&row.data)
            .map_err(AppError::internal_error)?;
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

impl Serialize for CipherResponse {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut response_map = cipher_fields(&self.data, self.cipher_type);
        response_map.insert("object".to_string(), json!("cipherDetails"));
        response_map.insert("id".to_string(), json!(self.id));
        response_map.insert("type".to_string(), json!(self.cipher_type));
        response_map.insert("creationDate".to_string(), json!(self.created_at));
        response_map.insert("revisionDate".to_string(), json!(self.updated_at));
        response_map.insert("deletedDate".to_string(), json!(self.deleted_at));
        response_map
            .insert("organizationId".to_string(), json!(self.organization_id));
        response_map.insert("attachments".to_string(), json!(self.attachments));
        response_map.insert("organizationUseTotp".to_string(), json!(false));
        response_map.insert("collectionIds".to_string(), json!([]));
        response_map.insert("folderId".to_string(), json!(self.folder_id));
        response_map.insert("favorite".to_string(), json!(self.is_favorite));
        response_map
            .insert("archivedDate".to_string(), json!(self.archived_at));
        response_map.insert("edit".to_string(), json!(true));
        response_map.insert("viewPassword".to_string(), json!(true));
        response_map.insert(
            "permissions".to_string(),
            json!({ "delete": true, "restore": true }),
        );

        Value::Object(response_map).serialize(serializer)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep the complete encrypted cipher response projection together"
)]
fn cipher_fields(data: &Value, cipher_type: i32) -> Map<String, Value> {
    let mut response_map = Map::new();
    let data_obj = data.as_object();
    let empty_data = Map::new();
    let data_obj = data_obj.unwrap_or(&empty_data);
    let blob = data_obj
        .get("data")
        .and_then(Value::as_str)
        .filter(|data| is_data_blob_encrypted(data));

    let name = data_obj.get("name").cloned().unwrap_or(Value::Null);
    let notes = data_obj.get("notes").cloned().unwrap_or(Value::Null);
    let fields = normalize_fields(data_obj.get("fields"));
    let password_history =
        normalize_password_history(data_obj.get("passwordHistory"));
    let reprompt = data_obj
        .get("reprompt")
        .and_then(Value::as_i64)
        .filter(|v| *v == 0 || *v == 1)
        .unwrap_or(0);

    let mut login = Value::Null;
    let mut secure_note = Value::Null;
    let mut card = Value::Null;
    let mut identity = Value::Null;
    let mut ssh_key = Value::Null;
    let mut bank_account = Value::Null;
    let mut drivers_license = Value::Null;
    let mut passport = Value::Null;

    // Like upstream's invalid type-data fallback, a historical item with
    // missing active payload must still provide an object to native
    // clients. This is separate from rejecting an unreadable D1 row.
    let active_data = |field| {
        data_obj
            .get(field)
            .filter(|value| value.is_object())
            .cloned()
            .unwrap_or_else(|| json!({}))
    };

    match cipher_type {
        1 => {
            let mut value = active_data("login");
            normalize_login(&mut value);
            login = value;
        }
        2 => {
            let mut value = active_data("secureNote");
            normalize_secure_note(&mut value);
            secure_note = value;
        }
        3 => {
            card = active_data("card");
        }
        4 => {
            identity = active_data("identity");
        }
        5 => {
            let mut value = active_data("sshKey");
            normalize_ssh_key(&mut value);
            ssh_key = value;
        }
        6 => {
            bank_account = active_data("bankAccount");
        }
        7 => {
            drivers_license = active_data("driversLicense");
        }
        8 => {
            passport = active_data("passport");
        }
        _ => {}
    }

    response_map.insert("reprompt".to_string(), json!(reprompt));
    response_map.insert(
        "key".to_string(),
        data.get("key").cloned().unwrap_or(Value::Null),
    );
    response_map.insert("name".to_string(), name);
    response_map.insert("notes".to_string(), notes);
    response_map.insert("fields".to_string(), fields);
    response_map.insert("passwordHistory".to_string(), password_history);
    response_map.insert("login".to_string(), login);
    response_map.insert("secureNote".to_string(), secure_note);
    response_map.insert("card".to_string(), card);
    response_map.insert("identity".to_string(), identity);
    response_map.insert("sshKey".to_string(), ssh_key);
    response_map.insert("bankAccount".to_string(), bank_account);
    response_map.insert("driversLicense".to_string(), drivers_license);
    response_map.insert("passport".to_string(), passport);
    if let Some(blob) = blob {
        response_map.insert("data".to_string(), json!(blob));
        for field in [
            "name",
            "notes",
            "fields",
            "passwordHistory",
            "login",
            "secureNote",
            "card",
            "identity",
            "sshKey",
            "bankAccount",
            "driversLicense",
            "passport",
        ] {
            response_map.insert(field.to_string(), Value::Null);
        }
    }

    response_map
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
                    .unwrap_or_else(|| {
                        "1970-01-01T00:00:00.000000Z".to_string()
                    });
                entry.insert("lastUsedDate".to_string(), json!(last_used_date));
                Some(Value::Object(entry))
            })
            .collect(),
    )
}

fn normalize_login(login: &mut Value) {
    // Upstream assigning the legacy uri field also promotes a null login to
    // an object. Preserve this for historical rows with explicit login:null.
    if login.is_null() {
        *login = json!({});
    }
    let Value::Object(map) = login else {
        return;
    };

    if let Some(uris) = map.get_mut("uris").and_then(Value::as_array_mut) {
        for uri in uris {
            let Some(uri) = uri.as_object_mut() else {
                continue;
            };
            if let Some(Value::String(match_value)) = uri.get("match") {
                let match_value =
                    match_value.parse::<u8>().map_or(Value::Null, |v| json!(v));
                uri.insert("match".to_string(), match_value);
            }
        }
    }

    if let Some(Value::String(password_revision_date)) =
        map.get("passwordRevisionDate")
    {
        let password_revision_date =
            normalize_optional_rfc3339(Some(password_revision_date))
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
    use super::{
        super::{
            CipherPayload,
            CipherRequest,
        },
        *,
    };

    #[test]
    fn sealed_blob_preserves_opaque_data_and_hides_structured_fields() {
        let blob = "{ \"format_version\": 2, \"data\": \"opaque\" }";
        let request: CipherRequest = serde_json::from_value(json!({"type":8,"data":blob,"name":"ignored","passport":{"number":"ignored"},"key":"wrapped","reprompt":1})).expect("valid cipher projection fixture");
        request
            .validate_for_personal_vault("owner")
            .expect("valid cipher projection fixture");
        let stored =
            serde_json::to_value(CipherPayload::from_request(&request))
                .expect("valid cipher projection fixture");
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
        for (kind, field) in
            [(6, "bankAccount"), (7, "driversLicense"), (8, "passport")]
        {
            let request: CipherRequest=serde_json::from_value(json!({"type":kind,"name":"encrypted",field:{"encrypted":"opaque","response":{"transient":true}},"fields":[{"name":"encrypted","response":{}}]})).expect("valid cipher projection fixture");
            request
                .validate_for_personal_vault("owner")
                .expect("valid cipher projection fixture");
            let stored =
                serde_json::to_value(CipherPayload::from_request(&request))
                    .expect("valid cipher projection fixture");
            assert!(stored[field].get("response").is_none());
            assert!(stored["fields"][0].get("response").is_none());
            assert_eq!(
                cipher_fields(&stored, kind)[field]["encrypted"],
                "opaque"
            );
        }
    }

    #[test]
    fn missing_historical_payloads_get_client_safe_objects() {
        let login =
            cipher_fields(&json!({"login":null,"fields":[{"type":"3"}]}), 1);
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
    fn invalid_stored_json_fails_conversion_instead_of_fabricating_empty_content()
     {
        let row:CipherRow=serde_json::from_value(json!({"id":"bad","user_id":"owner","organization_id":null,"cipher_type":1,"data":"{broken","is_favorite":0,"folder_id":null,"deleted_at":null,"created_at":"now","updated_at":"now"})).expect("valid cipher projection fixture");
        assert!(CipherResponse::try_from(row).is_err());
    }

    #[test]
    fn item_key_survives_request_storage_and_response()
    -> Result<(), serde_json::Error> {
        let request: CipherRequest = serde_json::from_value(json!({
            "type": 1, "name": "encrypted-name", "key": "wrapped-item-key",
            "login": { "password": "encrypted-password" }
        }))?;
        let data = CipherPayload::from_request(&request);
        let row: CipherRow = serde_json::from_value(json!({
            "id": "cipher", "user_id": "owner", "organization_id": null,
            "cipher_type": 1, "data": serde_json::to_string(&data)?, "is_favorite": 0,
            "folder_id": null, "deleted_at": null,
            "archived_at": "2026-01-01T00:00:00.000Z",
            "created_at": "2025-01-01T00:00:00.000Z",
            "updated_at": "2026-01-01T00:00:00.000Z"
        }))?;
        let response = serde_json::to_value(
            CipherResponse::try_from(row)
                .expect("valid cipher projection fixture"),
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
