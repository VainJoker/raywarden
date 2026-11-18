//! Pure Cipher payload validation, canonicalization and response serialization.
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
    de,
};
use serde_json::{
    Map,
    Value,
    json,
};

use super::types::{
    Cipher,
    CipherDB,
    CipherData,
    CipherRequestData,
    CipherTypeFields,
};
use crate::errors::AppError;

impl CipherData {
    pub fn from_request(request: &CipherRequestData) -> Self {
        let mut type_fields = if request.is_blob() {
            CipherTypeFields {
                key: request.type_fields.key.clone(),
                reprompt: request.type_fields.reprompt,
                ..Default::default()
            }
        } else {
            request.type_fields.clone()
        };
        for value in [
            &mut type_fields.login,
            &mut type_fields.card,
            &mut type_fields.identity,
            &mut type_fields.secure_note,
            &mut type_fields.ssh_key,
            &mut type_fields.bank_account,
            &mut type_fields.drivers_license,
            &mut type_fields.passport,
        ]
        .into_iter()
        .flatten()
        {
            if let Some(object) = value.as_object_mut() {
                object.remove("response");
                if let Some(uris) =
                    object.get_mut("uris").and_then(Value::as_array_mut)
                {
                    for uri in uris.iter_mut().filter_map(Value::as_object_mut)
                    {
                        uri.remove("response");
                    }
                }
            }
        }
        if let Some(fields) =
            type_fields.fields.as_mut().and_then(Value::as_array_mut)
        {
            for field in fields.iter_mut().filter_map(Value::as_object_mut) {
                field.remove("response");
            }
        }
        Self {
            name: if request.is_blob() {
                String::new()
            } else {
                request.name.clone().unwrap_or_default()
            },
            data: request.is_blob().then(|| request.data.clone()).flatten(),
            notes: if request.is_blob() {
                None
            } else {
                request.notes.clone()
            },
            type_fields,
        }
    }
}

// Custom deserialization function for booleans
pub(super) fn deserialize_bool_from_int<'de, D>(
    deserializer: D,
) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    // A visitor is used to handle different data types
    #[allow(clippy::too_many_lines)]
    struct BoolOrIntVisitor;

    impl de::Visitor<'_> for BoolOrIntVisitor {
        type Value = bool;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str("a boolean or an integer 0 or 1")
        }

        // Handles boolean values
        fn visit_bool<E>(self, value: bool) -> Result<bool, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        // Handles integer values (0 or 1)
        fn visit_u64<E>(self, value: u64) -> Result<bool, E>
        where
            E: de::Error,
        {
            match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(de::Error::invalid_value(
                    de::Unexpected::Unsigned(value),
                    &"0 or 1",
                )),
            }
        }
    }

    deserializer.deserialize_any(BoolOrIntVisitor)
}

// Custom deserialization function for cipher types
pub(super) fn deserialize_cipher_type<'de, D>(
    deserializer: D,
) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = i32::deserialize(deserializer)?;
    match value {
        1..=8 => Ok(value), // Valid cipher types: Login, SecureNote, Card,
        // Identity, SshKey
        _ => Err(de::Error::invalid_value(
            de::Unexpected::Signed(i64::from(value)),
            &"a valid cipher type (1=Login, 2=SecureNote, 3=Card, 4=Identity, \
              5=SshKey)",
        )),
    }
}

impl TryFrom<CipherDB> for Cipher {
    type Error = AppError;
    fn try_from(row: CipherDB) -> Result<Self, Self::Error> {
        row.into_api()
    }
}

fn cipher_from_data(val: CipherDB, data: Value) -> Cipher {
    Cipher {
        id: val.id,
        user_id: Some(val.user_id),
        organization_id: val.organization_id,
        r#type: val.r#type,
        data,
        favorite: val.favorite != 0,
        folder_id: val.folder_id,
        deleted_at: val.deleted_at,
        archived_at: val.archived_at,
        created_at: val.created_at,
        updated_at: val.updated_at,
        object: default_object(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
        attachments: None,
    }
}

impl Serialize for Cipher {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut response_map = cipher_fields(&self.data, self.r#type);
        response_map.insert("object".to_string(), json!(self.object));
        response_map.insert("id".to_string(), json!(self.id));
        response_map.insert("type".to_string(), json!(self.r#type));
        response_map.insert("creationDate".to_string(), json!(self.created_at));
        response_map.insert("revisionDate".to_string(), json!(self.updated_at));
        response_map.insert("deletedDate".to_string(), json!(self.deleted_at));
        response_map
            .insert("organizationId".to_string(), json!(self.organization_id));
        response_map.insert("attachments".to_string(), json!(self.attachments));
        response_map.insert(
            "organizationUseTotp".to_string(),
            json!(self.organization_use_totp),
        );
        response_map.insert(
            "collectionIds".to_string(),
            json!(self.collection_ids.clone().unwrap_or_default()),
        );
        response_map.insert("folderId".to_string(), json!(self.folder_id));
        response_map.insert("favorite".to_string(), json!(self.favorite));
        response_map
            .insert("archivedDate".to_string(), json!(self.archived_at));
        response_map.insert("edit".to_string(), json!(self.edit));
        response_map
            .insert("viewPassword".to_string(), json!(self.view_password));
        response_map.insert(
            "permissions".to_string(),
            json!({ "delete": self.edit, "restore": self.edit }),
        );

        Value::Object(response_map).serialize(serializer)
    }
}

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

pub(super) fn default_object() -> String {
    "cipherDetails".to_string()
}

pub(super) const fn default_true() -> bool {
    true
}

pub fn normalize_optional_rfc3339(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }

    crate::infra::time::parse(value)
        .ok()
        .map(crate::infra::time::format_micros)
}

pub fn client_revision_is_stale(
    server_revision: &str,
    client_revision: Option<&str>,
) -> bool {
    let Some(client_revision) = client_revision else {
        return false;
    };
    let (Ok(server_revision), Ok(client_revision)) = (
        crate::infra::time::parse(server_revision),
        crate::infra::time::parse(client_revision),
    ) else {
        return false;
    };

    server_revision.duration_since(client_revision).as_secs() > 1
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
    let is_valid = ssh_key.as_object().is_some_and(|ssh_key| {
        ["keyFingerprint", "privateKey", "publicKey"]
            .iter()
            .all(|field| {
                ssh_key
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
    });

    if !is_valid {
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

pub(super) fn deserialize_optional_nonempty_string<
    'de,
    D: Deserializer<'de>,
>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?
        .filter(|value| !value.is_empty()))
}

fn is_data_blob_encrypted(data: &str) -> bool {
    serde_json::from_str::<Value>(data)
        .is_ok_and(|value| value.get("format_version").is_some())
}

impl CipherRequestData {
    pub fn is_blob(&self) -> bool {
        self.data.as_deref().is_some_and(is_data_blob_encrypted)
    }
    pub fn validate_encryption_context(
        &self,
        user_id: &str,
        user_key_id: Option<&str>,
    ) -> Result<(), AppError> {
        if self
            .encrypted_for
            .as_deref()
            .is_some_and(|id| id != user_id)
        {
            return Err(AppError::bad_request(
                "Cipher was not encrypted for the current user",
            ));
        }
        if let Some(key_id) = self.encrypted_by_key_id.as_deref() {
            if user_key_id != Some(key_id) &&
                !crate::models::account_keys::is_valid_key_id(key_id)
            {
                if user_key_id.is_some() &&
                    uuid::Uuid::parse_str(key_id).is_ok()
                {
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
    pub fn validate_for_personal_vault(
        &self,
        user_id: &str,
    ) -> Result<(), AppError> {
        self.ensure_personal()?;
        if !self.collection_ids.is_empty() {
            return Err(AppError::bad_request("Collections are not supported"));
        }
        if self
            .encrypted_for
            .as_deref()
            .is_some_and(|id| id != user_id)
        {
            return Err(AppError::bad_request(
                "Cipher was not encrypted for the current user",
            ));
        }
        if self.data.as_ref().is_some_and(|data| data.len() > 500_000) {
            return Err(AppError::bad_request("Data exceeds 500000 bytes"));
        }
        let active = match self.r#type {
            1 => &self.type_fields.login,
            2 => &self.type_fields.secure_note,
            3 => &self.type_fields.card,
            4 => &self.type_fields.identity,
            5 => &self.type_fields.ssh_key,
            6 => &self.type_fields.bank_account,
            7 => &self.type_fields.drivers_license,
            8 => &self.type_fields.passport,
            _ => return Err(AppError::bad_request("Invalid cipher type")),
        };
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
        if !active.as_ref().is_some_and(Value::is_object) {
            return Err(AppError::bad_request("Cipher type data is missing"));
        }
        if self.r#type == 5 {
            let mut ssh = active.clone().unwrap_or_default();
            normalize_ssh_key(&mut ssh);
            if ssh.is_null() {
                return Err(AppError::bad_request(
                    "SSH key is missing required encrypted fields",
                ));
            }
        }
        Ok(())
    }
    pub fn ensure_personal(&self) -> Result<(), AppError> {
        if self.organization_id.is_some() {
            return Err(AppError::bad_request(
                "Organizations are not supported",
            ));
        }
        Ok(())
    }
}

impl CipherDB {
    pub fn into_api(self) -> Result<Cipher, AppError> {
        let data =
            serde_json::from_str(&self.data).map_err(|_| AppError::Internal)?;
        Ok(cipher_from_data(self, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_blob_preserves_opaque_data_and_hides_structured_fields() {
        let blob = "{ \"format_version\": 2, \"data\": \"opaque\" }";
        let request: CipherRequestData = serde_json::from_value(json!({"type":8,"data":blob,"name":"ignored","passport":{"number":"ignored"},"key":"wrapped","reprompt":1})).unwrap();
        request.validate_for_personal_vault("owner").unwrap();
        let stored =
            serde_json::to_value(CipherData::from_request(&request)).unwrap();
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
            let request: CipherRequestData=serde_json::from_value(json!({"type":kind,"name":"encrypted",field:{"encrypted":"opaque","response":{"transient":true}},"fields":[{"name":"encrypted","response":{}}]})).unwrap();
            request.validate_for_personal_vault("owner").unwrap();
            let stored =
                serde_json::to_value(CipherData::from_request(&request))
                    .unwrap();
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
        let row:CipherDB=serde_json::from_value(json!({"id":"bad","user_id":"owner","organization_id":null,"type":1,"data":"{broken","favorite":0,"folder_id":null,"deleted_at":null,"created_at":"now","updated_at":"now"})).unwrap();
        assert!(row.into_api().is_err());
    }

    #[test]
    fn encryption_context_accepts_matching_legacy_id_but_rejects_other_users_and_old_keys()
     {
        let legacy = "00000000-0000-4000-8000-000000000001";
        let request: CipherRequestData=serde_json::from_value(json!({"type":1,"name":"encrypted","login":{},"encryptedFor":"owner","encryptedByKeyId":legacy})).unwrap();
        request
            .validate_encryption_context("owner", Some(legacy))
            .unwrap();
        assert!(matches!(
            request.validate_encryption_context(
                "owner",
                Some("0123456789abcdef0123456789abcdef")
            ),
            Err(AppError::Conflict { .. })
        ));
        assert!(
            request
                .validate_encryption_context("other", Some(legacy))
                .is_err()
        );
        let request: CipherRequestData=serde_json::from_value(json!({"type":1,"name":"encrypted","login":{},"collectionIds":["unsupported"]})).unwrap();
        assert!(request.validate_for_personal_vault("owner").is_err());
    }

    #[test]
    fn item_key_survives_request_storage_and_response()
    -> Result<(), serde_json::Error> {
        let request: CipherRequestData = serde_json::from_value(json!({
            "type": 1, "name": "encrypted-name", "key": "wrapped-item-key",
            "login": { "password": "encrypted-password" }
        }))?;
        let data = CipherData::from_request(&request);
        let row: CipherDB = serde_json::from_value(json!({
            "id": "cipher", "user_id": "owner", "organization_id": null,
            "type": 1, "data": serde_json::to_string(&data)?, "favorite": 0,
            "folder_id": null, "deleted_at": null,
            "archived_at": "2026-01-01T00:00:00.000Z",
            "created_at": "2025-01-01T00:00:00.000Z",
            "updated_at": "2026-01-01T00:00:00.000Z"
        }))?;
        let response = serde_json::to_value(row.into_api().unwrap())?;
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

    #[test]
    fn personal_vault_rejects_organization_items()
    -> Result<(), serde_json::Error> {
        let request: CipherRequestData = serde_json::from_value(json!({
            "type": 1, "name": "encrypted", "organizationId": "another-org"
        }))?;
        assert!(request.ensure_personal().is_err());
        Ok(())
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::{
        client_revision_is_stale,
        normalize_optional_rfc3339,
    };

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
