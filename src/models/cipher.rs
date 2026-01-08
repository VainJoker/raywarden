use std::collections::HashSet;

use chrono::Utc;
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
use wasm_bindgen::JsValue;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
};

use crate::{
    errors::{
        AppError,
        DatabaseError,
    },
    infra::DB,
    models::attachment::AttachmentResponse,
};

// Cipher types:
//   Login = 1,
//   SecureNote = 2,
//   Card = 3,
//   Identity = 4,
//   SshKey = 5

/// Common cipher type-specific fields shared across multiple cipher structures.
/// These represent the encrypted content fields that vary based on cipher type.
/// Used with `#[serde(flatten)]` to embed these fields into other structs.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherTypeFields {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes:       Option<String>,
    #[serde(flatten)]
    pub type_fields: CipherTypeFields,
}

#[derive(Deserialize)]
struct CipherJsonArrayRow {
    ciphers_json: String,
}

#[derive(Deserialize)]
struct AffectedUserRow {
    user_id: Option<String>,
}

#[derive(Deserialize, Default)]
struct CountRow {
    count: u32,
}

// Custom deserialization function for booleans
fn deserialize_bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
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
fn deserialize_cipher_type<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = i32::deserialize(deserializer)?;
    match value {
        1..=5 => Ok(value), // Valid cipher types: Login, SecureNote, Card,
        // Identity, SshKey
        _ => Err(de::Error::invalid_value(
            de::Unexpected::Signed(i64::from(value)),
            &"a valid cipher type (1=Login, 2=SecureNote, 3=Card, 4=Identity, \
              5=SshKey)",
        )),
    }
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
    pub created_at:      String,
    pub updated_at:      String,
}

impl From<CipherDB> for Cipher {
    fn from(val: CipherDB) -> Self {
        Self {
            id:                    val.id,
            user_id:               Some(val.user_id),
            organization_id:       val.organization_id,
            r#type:                val.r#type,
            data:                  serde_json::from_str(&val.data)
                .unwrap_or_default(),
            favorite:              val.favorite != 0,
            folder_id:             val.folder_id,
            deleted_at:            val.deleted_at,
            created_at:            val.created_at,
            updated_at:            val.updated_at,
            object:                default_object(),
            organization_use_totp: false,
            edit:                  true,
            view_password:         true,
            collection_ids:        None,
            attachments:           None,
        }
    }
}

#[allow(clippy::too_many_lines)]
impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut response_map = Map::new();

        response_map.insert("object".to_string(), json!(self.object));
        response_map.insert("id".to_string(), json!(self.id));
        if self.user_id.is_some() {
            response_map.insert("userId".to_string(), json!(self.user_id));
        }
        response_map
            .insert("organizationId".to_string(), json!(self.organization_id));
        response_map.insert("folderId".to_string(), json!(self.folder_id));
        response_map.insert("type".to_string(), json!(self.r#type));
        response_map.insert("favorite".to_string(), json!(self.favorite));
        response_map.insert("edit".to_string(), json!(self.edit));
        response_map
            .insert("viewPassword".to_string(), json!(self.view_password));
        // new key "permissions" used by clients since v2025.6.0
        response_map.insert(
            "permissions".to_string(),
            json! ({
                "delete": self.edit,   // if edit is true, allow delete
                "restore": self.edit,  // if edit is true, allow restore
            }),
        );
        response_map.insert(
            "organizationUseTotp".to_string(),
            json!(self.organization_use_totp),
        );
        response_map
            .insert("collectionIds".to_string(), json!(self.collection_ids));
        response_map.insert("revisionDate".to_string(), json!(self.updated_at));
        response_map.insert("creationDate".to_string(), json!(self.created_at));
        response_map.insert("deletedDate".to_string(), json!(self.deleted_at));
        response_map.insert("attachments".to_string(), json!(self.attachments));

        if let Some(data_obj) = self.data.as_object() {
            let data_clone = data_obj.clone();

            response_map.insert(
                "name".to_string(),
                data_clone.get("name").cloned().unwrap_or(Value::Null),
            );
            response_map.insert(
                "notes".to_string(),
                data_clone.get("notes").cloned().unwrap_or(Value::Null),
            );
            response_map.insert(
                "fields".to_string(),
                data_clone.get("fields").cloned().unwrap_or(Value::Null),
            );
            response_map.insert(
                "passwordHistory".to_string(),
                data_clone
                    .get("passwordHistory")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            response_map.insert(
                "reprompt".to_string(),
                data_clone
                    .get("reprompt")
                    .cloned()
                    .unwrap_or(Value::Number(serde_json::Number::from(0))),
            );

            let mut login = Value::Null;
            let mut secure_note = Value::Null;
            let mut card = Value::Null;
            let mut identity = Value::Null;
            let mut ssh_key = Value::Null;

            match self.r#type {
                1 => {
                    login =
                        data_clone.get("login").cloned().unwrap_or(Value::Null);
                }
                2 => {
                    secure_note = data_clone
                        .get("secureNote")
                        .cloned()
                        .unwrap_or(Value::Null);
                }
                3 => {
                    card =
                        data_clone.get("card").cloned().unwrap_or(Value::Null);
                }
                4 => {
                    identity = data_clone
                        .get("identity")
                        .cloned()
                        .unwrap_or(Value::Null);
                }
                5 => {
                    ssh_key = data_clone
                        .get("sshKey")
                        .cloned()
                        .unwrap_or(Value::Null);
                }
                _ => {}
            }

            response_map.insert("login".to_string(), login);
            response_map.insert("secureNote".to_string(), secure_note);
            response_map.insert("card".to_string(), card);
            response_map.insert("identity".to_string(), identity);
            response_map.insert("sshKey".to_string(), ssh_key);
        } else {
            response_map.insert("name".to_string(), Value::Null);
            response_map.insert("notes".to_string(), Value::Null);
            response_map.insert("fields".to_string(), Value::Null);
            response_map.insert("passwordHistory".to_string(), Value::Null);
            response_map.insert("reprompt".to_string(), Value::Null);
            response_map.insert("login".to_string(), Value::Null);
            response_map.insert("secureNote".to_string(), Value::Null);
            response_map.insert("card".to_string(), Value::Null);
            response_map.insert("identity".to_string(), Value::Null);
            response_map.insert("sshKey".to_string(), Value::Null);
        }

        Value::Object(response_map).serialize(serializer)
    }
}

fn default_object() -> String {
    "cipherDetails".to_string()
}

const fn default_true() -> bool {
    true
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(alias = "organizationID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    #[serde(deserialize_with = "deserialize_cipher_type")]
    pub r#type: i32,
    pub name: String,
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

/// Response for listing ciphers (GET /api/ciphers)
/// Now we don't use this struct, we use `RawJson` instead. But we keep it here
/// for reference.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct CipherListResponse {
    pub data:               Vec<Value>,
    pub object:             String,
    pub continuation_token: Option<String>,
}

/// Request body for updating a cipher partially (PUT /api/ciphers/{id}/partial)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialCipherData {
    pub folder_id: Option<String>,
    pub favorite:  bool,
}

impl CipherDB {
    pub async fn touch_cipher_updated_at(
        db: &D1Database,
        cipher_id: &str,
    ) -> Result<(), AppError> {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        query!(
            db,
            "UPDATE ciphers SET updated_at = ?1 WHERE id = ?2",
            now,
            cipher_id
        )
        .map_err(|_| {
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to update cipher updated_at".to_string(),
            ))
        })?
        .run()
        .await?;
        Ok(())
    }

    /// Insert a new cipher row.
    pub async fn insert_cipher(
        db: &D1Database,
        cipher: &Cipher,
        data_json: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO ciphers (id, user_id, organization_id, type, \
                     data, favorite, folder_id, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    cipher.id,
                    cipher.user_id,
                    cipher.organization_id,
                    cipher.r#type,
                    data_json,
                    cipher.favorite,
                    cipher.folder_id,
                    cipher.created_at,
                    cipher.updated_at,
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to insert cipher",
        )
        .await
    }

    /// Insert multiple ciphers using batch execution.
    pub async fn insert_ciphers_batch(
        db: &D1Database,
        ciphers: &[(Cipher, String)],
        batch_size: usize,
    ) -> Result<(), AppError> {
        if ciphers.is_empty() {
            return Ok(());
        }

        let mut statements: Vec<D1PreparedStatement> =
            Vec::with_capacity(ciphers.len());

        for (cipher, data_json) in ciphers {
            let stmt = query!(
                db,
                "INSERT INTO ciphers (id, user_id, organization_id, type, \
                 data, favorite, folder_id, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                cipher.id,
                cipher.user_id,
                cipher.organization_id,
                cipher.r#type,
                data_json,
                cipher.favorite,
                cipher.folder_id,
                cipher.created_at,
                cipher.updated_at,
            )
            .map_err(|e| {
                AppError::Database(DatabaseError::QueryFailed(format!(
                    "Failed to prepare cipher insert: {e}"
                )))
            })?;

            statements.push(stmt);
        }

        if batch_size == 0 {
            DB::run_query(
                async { db.batch(statements).await.map(|_| ()) },
                "Failed to insert ciphers",
            )
            .await
        } else {
            for chunk in statements.chunks(batch_size) {
                DB::run_query(
                    async { db.batch(chunk.to_vec()).await.map(|_| ()) },
                    "Failed to insert ciphers",
                )
                .await?;
            }

            Ok(())
        }
    }

    pub async fn update_cipher(
        db: &D1Database,
        cipher: &Cipher,
        data_json: &str,
        id: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE ciphers SET organization_id = ?1, type = ?2, data \
                     = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 \
                     WHERE id = ?7 AND user_id = ?8",
                    cipher.organization_id,
                    cipher.r#type,
                    data_json,
                    cipher.favorite,
                    cipher.folder_id,
                    cipher.updated_at,
                    id,
                    user_id,
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update cipher",
        )
        .await
    }

    pub async fn update_cipher_partial(
        db: &D1Database,
        folder_id: Option<String>,
        favorite: bool,
        now: &str,
        id: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE ciphers SET folder_id = ?1, favorite = ?2, \
                     updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
                    folder_id,
                    favorite,
                    now,
                    id,
                    user_id,
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to update cipher",
        )
        .await
    }

    pub async fn soft_delete_cipher(
        db: &D1Database,
        id: &str,
        user_id: &str,
        now: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 \
                     WHERE id = ?2 AND user_id = ?3",
                    now,
                    id,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to soft-delete cipher",
        )
        .await
    }

    pub async fn soft_delete_ciphers_bulk(
        db: &D1Database,
        user_id: &str,
        body: &str,
        now: &str,
    ) -> Result<(), AppError> {
        query!(
            db,
            "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE \
             user_id = ?2 AND id IN (SELECT value FROM json_each(?3, \
             \'$.ids\'))",
            now,
            user_id,
            body
        )
        .map_err(|e| {
            log::error!("Failed to bind bulk soft-delete query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to soft-delete ciphers".to_string(),
            ))
        })?
        .run()
        .await
        .map_err(|e| Self::map_d1_json_error(&e))
        .map(|_| ())
    }

    pub async fn hard_delete_cipher(
        db: &D1Database,
        id: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
                    id,
                    user_id
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to delete cipher",
        )
        .await
    }

    pub async fn hard_delete_ciphers_bulk(
        db: &D1Database,
        user_id: &str,
        body: &str,
    ) -> Result<(), AppError> {
        query!(
            db,
            "DELETE FROM ciphers WHERE user_id = ?1 AND id IN (SELECT value \
             FROM json_each(?2, \'$.ids\'))",
            user_id,
            body
        )
        .map_err(|e| {
            log::error!("Failed to bind bulk hard-delete query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to delete ciphers".to_string(),
            ))
        })?
        .run()
        .await
        .map_err(|e| Self::map_d1_json_error(&e))
        .map(|_| ())
    }

    pub async fn restore_cipher(
        db: &D1Database,
        id: &str,
        user_id: &str,
        now: &str,
    ) -> Result<Self, AppError> {
        query!(
            db,
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = \
             ?2 AND user_id = ?3",
            now,
            id,
            user_id
        )
        .map_err(|e| {
            log::error!("Failed to bind restore cipher query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to restore cipher".to_string(),
            ))
        })?
        .run()
        .await
        .map_err(|e| {
            log::error!("Failed to execute restore cipher query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to restore cipher".to_string(),
            ))
        })?;

        Self::fetch_for_user(db, id, user_id).await
    }

    pub async fn restore_ciphers_bulk(
        db: &D1Database,
        user_id: &str,
        body: &str,
        now: &str,
    ) -> Result<(), AppError> {
        query!(
            db,
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE \
             user_id = ?2 AND id IN (SELECT value FROM json_each(?3, \
             \'$.ids\'))",
            now,
            user_id,
            body
        )
        .map_err(|e| {
            log::error!("Failed to bind bulk restore query: {e}");
            AppError::Database(DatabaseError::QueryFailed(
                "Failed to restore ciphers".to_string(),
            ))
        })?
        .run()
        .await
        .map_err(|e| Self::map_d1_json_error(&e))
        .map(|_| ())
    }

    pub async fn move_selected(
        db: &D1Database,
        user_id: &str,
        body: &str,
        now: &str,
    ) -> Result<(), AppError> {
        db.prepare(
            "UPDATE ciphers SET folder_id = json_extract(?1, '$.folderId'), \
             updated_at = ?2 WHERE user_id = ?3 AND id IN (SELECT value FROM \
             json_each(?1, '$.ids'))",
        )
        .bind(&[
            body.to_owned().into(),
            now.to_owned().into(),
            user_id.into(),
        ])?
        .run()
        .await
        .map_err(|e| Self::map_d1_json_error(&e))
        .map(|_| ())
    }

    pub async fn list_soft_deleted_user_ids_before(
        db: &D1Database,
        cutoff_exclusive: &str,
    ) -> Result<HashSet<String>, AppError> {
        let rows: Vec<AffectedUserRow> = query!(
            db,
            "SELECT DISTINCT user_id FROM ciphers WHERE deleted_at IS NOT \
             NULL AND deleted_at < ?1 AND user_id IS NOT NULL",
            cutoff_exclusive
        )
        .map_err(|e| {
            AppError::Database(DatabaseError::QueryFailed(format!(
                "Failed to prepare affected users query: {e}"
            )))
        })?
        .all()
        .await
        .map_err(|e| {
            AppError::Database(DatabaseError::QueryFailed(format!(
                "Failed to fetch affected users: {e}"
            )))
        })?
        .results()
        .map_err(|e| {
            AppError::Database(DatabaseError::QueryFailed(format!(
                "Failed to parse affected users: {e}"
            )))
        })?;

        Ok(rows.into_iter().filter_map(|row| row.user_id).collect())
    }

    pub async fn count_soft_deleted_before(
        db: &D1Database,
        cutoff_exclusive: &str,
    ) -> Result<u32, AppError> {
        let count_row = query!(
            db,
            "SELECT COUNT(*) as count FROM ciphers WHERE deleted_at IS NOT \
             NULL AND deleted_at < ?1",
            cutoff_exclusive
        )
        .map_err(|e| {
            AppError::Database(DatabaseError::QueryFailed(format!(
                "Failed to prepare soft-delete count query: {e}"
            )))
        })?
        .first::<CountRow>(None)
        .await
        .map_err(|e| {
            AppError::Database(DatabaseError::QueryFailed(format!(
                "Failed to count soft-deleted ciphers: {e}"
            )))
        })?;

        Ok(count_row.map_or(0, |row| row.count))
    }

    pub async fn delete_soft_deleted_before(
        db: &D1Database,
        cutoff_exclusive: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND \
                     deleted_at < ?1",
                    cutoff_exclusive
                )?
                .run()
                .await
                .map(|_| ())
            },
            "Failed to purge soft-deleted ciphers",
        )
        .await
    }

    pub async fn purge_user_ciphers(
        db: &D1Database,
        user_id: &str,
    ) -> Result<(), AppError> {
        DB::run_query(
            async {
                query!(db, "DELETE FROM ciphers WHERE user_id = ?1", user_id)?
                    .run()
                    .await
                    .map(|_| ())
            },
            "Failed to purge ciphers",
        )
        .await
    }

    pub async fn fetch_for_user(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
    ) -> Result<Self, AppError> {
        db.prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
            .bind(&[cipher_id.to_string().into(), user_id.to_string().into()])
            .map_err(|e| {
                log::error!("Failed to bind fetch cipher query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch cipher".to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to execute fetch cipher query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch cipher".to_string(),
                ))
            })?
            .ok_or_else(|| AppError::not_found("Cipher not found"))
    }

    pub async fn ensure_cipher_for_user(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
    ) -> Result<Self, AppError> {
        let cipher: Option<Self> = db
            .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
            .bind(&[cipher_id.into(), user_id.into()])?
            .first(None)
            .await
            .map_err(|e| {
                log::error!("Failed to fetch cipher for user: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to fetch cipher".to_string(),
                ))
            })?;

        let cipher = cipher.ok_or_else(|| {
            AppError::Database(DatabaseError::QueryFailed(
                "Cipher not found".to_string(),
            ))
        })?;

        if cipher.organization_id.is_some() {
            return Err(AppError::Database(DatabaseError::QueryFailed(
                "Organization attachments are not supported".to_string(),
            )));
        }

        if cipher.deleted_at.is_some() {
            return Err(AppError::Database(DatabaseError::QueryFailed(
                "Cipher is deleted".to_string(),
            )));
        }

        Ok(cipher)
    }

    /// Execute a cipher JSON projection query and return the raw JSON array
    /// string. This avoids JSON parsing in Rust, significantly reducing CPU
    /// time.
    pub async fn fetch_cipher_json_array_raw(
        db: &worker::D1Database,
        attachments_enabled: bool,
        where_clause: &str,
        params: &[JsValue],
        order_clause: &str,
    ) -> Result<String, AppError> {
        let sql = Self::cipher_json_array_sql(
            attachments_enabled,
            where_clause,
            order_clause,
        );

        let row: Option<CipherJsonArrayRow> = db
            .prepare(&sql)
            .bind(params)
            .map_err(|e| {
                log::error!("Failed to bind cipher JSON projection query: {e}");
                AppError::Database(DatabaseError::QueryFailed(
                    "Failed to query ciphers".to_string(),
                ))
            })?
            .first(None)
            .await
            .map_err(|e| Self::map_d1_json_error(&e))?;

        Ok(row.map_or_else(|| "[]".to_string(), |r| r.ciphers_json))
    }

    /// Build SQL that returns ciphers as a JSON array string (using
    /// `json_group_array`).
    fn cipher_json_array_sql(
        attachments_enabled: bool,
        where_clause: &str,
        order_clause: &str,
    ) -> String {
        let cipher_expr = Self::cipher_json_expr(attachments_enabled);
        // Use a subquery to ensure ORDER BY is applied before json_group_array
        format!(
            "SELECT COALESCE(json_group_array(json(sub.cipher_json)), '[]') \
             AS ciphers_json
        FROM (
            SELECT {cipher_expr} AS cipher_json
            FROM ciphers c
            {where_clause}
            {order_clause}
        ) sub",
        )
    }

    /// Build the SQL expression for a single cipher as JSON.
    fn cipher_json_expr(attachments_enabled: bool) -> String {
        let attachments_expr = if attachments_enabled {
            "
            (
                SELECT CASE WHEN COUNT(1)=0 THEN NULL ELSE json_group_array(
                    json_object(
                        'id', a.id,
                        'url', NULL,
                        'fileName', a.file_name,
                        'size', CAST(a.file_size AS TEXT),
                        'sizeName',
                            CASE
                                WHEN a.file_size < 1024 THEN printf('%d B', \
             a.file_size)
                                WHEN a.file_size < 1048576 THEN printf('%.1f \
             KB', a.file_size / 1024.0)
                                WHEN a.file_size < 1073741824 THEN \
             printf('%.1f MB', a.file_size / 1048576.0)
                                WHEN a.file_size < 1099511627776 THEN \
             printf('%.1f GB', a.file_size / 1073741824.0)
                                ELSE printf('%.1f TB', a.file_size / \
             1099511627776.0)
                            END,
                        'key', a.akey,
                        'object', 'attachment'
                    )
                ) END
                FROM attachments a
                WHERE a.cipher_id = c.id
            )
        "
        } else {
            "NULL"
        };

        format!(
            "json_object(
            'object', 'cipherDetails',
            'id', c.id,
            'userId', c.user_id,
            'organizationId', c.organization_id,
            'folderId', c.folder_id,
            'type', c.type,
            'favorite', CASE WHEN c.favorite THEN json('true') ELSE \
             json('false') END,
            'edit', json('true'),
            'viewPassword', json('true'),
            'permissions', json_object('delete', json('true'), 'restore', \
             json('true')),
            'organizationUseTotp', json('false'),
            'collectionIds', NULL,
            'revisionDate', c.updated_at,
            'creationDate', c.created_at,
            'deletedDate', c.deleted_at,
            'attachments', {attachments_expr},
            'name', json_extract(c.data, '$.name'),
            'notes', json_extract(c.data, '$.notes'),
            'fields', json_extract(c.data, '$.fields'),
            'passwordHistory', json_extract(c.data, '$.passwordHistory'),
            'reprompt', COALESCE(json_extract(c.data, '$.reprompt'), 0),
            'login', CASE WHEN c.type = 1 THEN json_extract(c.data, '$.login') \
             ELSE NULL END,
            'secureNote', CASE WHEN c.type = 2 THEN json_extract(c.data, \
             '$.secureNote') ELSE NULL END,
            'card', CASE WHEN c.type = 3 THEN json_extract(c.data, '$.card') \
             ELSE NULL END,
            'identity', CASE WHEN c.type = 4 THEN json_extract(c.data, \
             '$.identity') ELSE NULL END,
            'sshKey', CASE WHEN c.type = 5 THEN json_extract(c.data, \
             '$.sshKey') ELSE NULL END
        )"
        )
    }

    pub fn map_d1_json_error(err: &worker::Error) -> AppError {
        let msg = err.to_string();
        let is_invalid_json = msg.contains("malformed JSON") ||
            msg.contains("Invalid JSON") ||
            msg.contains("json_each") && msg.contains("JSON") ||
            msg.contains("json_extract") && msg.contains("JSON");

        if is_invalid_json {
            log::warn!("Invalid JSON body (D1): {msg}");
            AppError::Params("Invalid JSON body".to_string())
        } else {
            log::error!("D1 query failed: {msg}");
            AppError::Database(DatabaseError::QueryFailed(
                "Database query failed".to_string(),
            ))
        }
    }
}
