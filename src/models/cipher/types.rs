//! Cipher request/response contracts and the persisted row shape.
use std::collections::HashMap;

use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;

use super::codec::{
    default_object,
    default_true,
    deserialize_bool_from_int,
    deserialize_cipher_type,
    deserialize_optional_nonempty_string,
};
use crate::models::attachment::AttachmentResponse;

/// Common cipher type-specific fields shared across multiple cipher structures.
/// These represent the encrypted content fields that vary based on cipher type.
/// Used with `#[serde(flatten)]` to embed these fields into other structs.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherTypeFields {
    // Per-item key wrapped by the user's symmetric key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key:              Option<String>,
    // Only one of these should exist, depending on cipher type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login:            Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card:             Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity:         Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note:      Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key:          Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_account:     Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drivers_license:  Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passport:         Option<Value>,
    // Common fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields:           Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt:         Option<i32>,
}

/// This struct represents the data stored in the `data` column of the `ciphers`
/// table.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherData {
    pub name:        String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data:        Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes:       Option<String>,
    #[serde(flatten)]
    pub type_fields: CipherTypeFields,
}

// The struct that is stored in the database and used in handlers.
// For serialization to JSON for the client, we implement a custom `Serialize`.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct Cipher {
    pub id:              String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id:         Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub r#type:          i32,
    pub data:            Value,
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub favorite:        bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id:       Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at:      Option<String>,
    #[serde(default)]
    pub archived_at:     Option<String>,
    pub created_at:      String,
    pub updated_at:      String,

    // Bitwarden specific field for API responses
    #[serde(default = "default_object")]
    pub object:                String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub organization_use_totp: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub edit:                  bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub view_password:         bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids:        Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attachments:           Option<Vec<AttachmentResponse>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CipherDB {
    pub id:              String,
    pub user_id:         String,
    pub organization_id: Option<String>,
    pub r#type:          i32,
    pub data:            String,
    pub favorite:        i32,
    pub folder_id:       Option<String>,
    pub deleted_at:      Option<String>,
    #[serde(default)]
    pub archived_at:     Option<String>,
    pub created_at:      String,
    pub updated_at:      String,
}

/// Represents the "Cipher" object within incoming request payloads.
/// Used for create, update, import, and key rotation scenarios.
/// Aligned with vaultwarden's `CipherData` structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequestData {
    // Id is optional as it is included only in bulk share / key rotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    // Folder id is not included in import (determined by folder_relationships)
    #[serde(
        default,
        deserialize_with = "deserialize_optional_nonempty_string"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(alias = "organizationID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    #[serde(deserialize_with = "deserialize_cipher_type")]
    pub r#type: i32,
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: Option<bool>,
    #[serde(flatten)]
    pub type_fields: CipherTypeFields,
    // The revision datetime (in ISO 8601 format) of the client's local copy
    // Used to prevent updating a cipher when client doesn't have the latest
    // version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_revision_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments2: Option<HashMap<String, AttachmentRotationData>>,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    #[serde(default)]
    pub archived_date: Option<String>,
    #[serde(default, alias = "encryptedByUserId")]
    pub encrypted_for: Option<String>,
    #[serde(default)]
    pub encrypted_by_key_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRotationData {
    pub file_name: String,
    pub key:       String,
}

/// Represents the full request payload for creating a cipher with collections.
/// Supports both camelCase and `PascalCase` for compatibility with different
/// clients.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCipherRequest {
    #[serde(alias = "Cipher")]
    pub cipher:         CipherRequestData,
    #[serde(default)]
    #[serde(alias = "CollectionIds")]
    pub collection_ids: Vec<String>,
}

/// Request body for updating a cipher partially (PUT /api/ciphers/{id}/partial)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialCipherData {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_nonempty_string"
    )]
    pub folder_id: Option<String>,
    pub favorite:  bool,
}
