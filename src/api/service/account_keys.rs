//! Account envelope changes commit with the exact vault generation they read.
use std::collections::HashSet;

use serde_json::Value;
use uuid::Uuid;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
    wasm_bindgen::JsValue,
};

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            notifications::{
                self,
                UpdateType,
            },
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    infra::{
        admin_notify::{
            self,
            Event,
        },
        db,
    },
    models::{
        account_keys::{
            AccountSnapshot,
            ValidatedAccountKeys,
            is_valid_key_id,
        },
        cipher::CipherData,
        user::{
            RotateAccountData,
            UserDB,
        },
    },
    send,
};

const CIPHERS: &[&str] = &[
    "id",
    "user_id",
    "organization_id",
    "type",
    "data",
    "favorite",
    "folder_id",
    "deleted_at",
    "archived_at",
    "created_at",
    "updated_at",
];
const FOLDERS: &[&str] = &["id", "name", "created_at", "updated_at"];
const ATTACHMENTS: &[&str] = &[
    "id",
    "cipher_id",
    "file_name",
    "file_size",
    "akey",
    "storage_key",
    "created_at",
    "updated_at",
];
const PASSKEYS: &[&str] = &[
    "id",
    "slot",
    "credential_id",
    "public_key",
    "sign_count",
    "credential_use",
    "prf_status",
    "encrypted_public_key",
    "encrypted_user_key",
    "encrypted_private_key",
    "account_snapshot",
    "updated_at",
];

struct CollectionSnapshot {
    table:   &'static str,
    columns: &'static [&'static str],
    filter:  &'static str,
    rows:    Vec<Value>,
}
impl CollectionSnapshot {
    async fn load(
        db: &D1Database,
        table: &'static str,
        columns: &'static [&'static str],
        owner: &str,
        filter: &'static str,
    ) -> AppResult<Self> {
        let sql = format!(
            "SELECT {} FROM {table} WHERE {filter} ORDER BY id",
            columns.join(",")
        );
        let rows = db::run_query(
            async {
                db.prepare(&sql)
                    .bind(&[owner.into()])?
                    .all()
                    .await?
                    .results::<Value>()
            },
            "Failed to read rotation source rows",
        )
        .await?;
        Ok(Self {
            table,
            columns,
            filter,
            rows,
        })
    }
    fn guards(
        &self,
        db: &D1Database,
        owner: &str,
    ) -> AppResult<Vec<D1PreparedStatement>> {
        let mut guards = vec![super::cipher_mutation::guard(
            db,
            &format!(
                "(SELECT COUNT(*) FROM {} WHERE {})=?2",
                self.table, self.filter
            ),
            &[owner.into(), JsValue::from_f64(self.rows.len() as f64)],
        )?];
        let predicates = self
            .columns
            .iter()
            .enumerate()
            .map(|(i, column)| format!("{column} IS ?{}", i + 2))
            .collect::<Vec<_>>()
            .join(" AND ");
        let predicate = format!(
            "EXISTS(SELECT 1 FROM {} WHERE {} AND {predicates})",
            self.table, self.filter
        );
        for row in &self.rows {
            let mut values = vec![owner.into()];
            for column in self.columns {
                values.push(scalar(&row[*column])?);
            }
            guards
                .push(super::cipher_mutation::guard(db, &predicate, &values)?);
        }
        Ok(guards)
    }
    fn rows(&self) -> AppResult<Vec<Value>> {
        Ok(self.rows.clone())
    }
    fn ids(&self) -> AppResult<HashSet<String>> {
        Ok(self
            .rows
            .iter()
            .filter_map(|row| row["id"].as_str().map(str::to_string))
            .collect())
    }
}
fn scalar(value: &Value) -> AppResult<JsValue> {
    Ok(match value {
        Value::Null => JsValue::NULL,
        Value::String(value) => value.as_str().into(),
        Value::Number(value) => {
            JsValue::from_f64(value.as_f64().ok_or(AppError::Internal)?)
        }
        Value::Bool(value) => JsValue::from_f64(f64::from(u8::from(*value))),
        _ => return Err(AppError::Internal),
    })
}

pub struct RotationInput {
    pub keys:             ValidatedAccountKeys,
    pub data:             RotateAccountData,
    pub wrapped_user_key: String,
    pub old_user_key_id:  Option<String>,
    pub new_user_key_id:  Option<String>,
    pub upgrade:          Option<Value>,
    pub passkeys:         Vec<Value>,
    pub password: Option<(
        String,
        String,
        i32,
        i32,
        Option<i32>,
        Option<i32>,
        Option<String>,
    )>,
}

pub async fn rotate(
    state: &AppState,
    claims: &Claims,
    user: &UserDB,
    input: RotationInput,
) -> AppResult<()> {
    let db = state.get_db();
    let changes_password = input.password.is_some();
    input.keys.validate_rotation(user)?;
    for id in input.new_user_key_id.iter() {
        if !is_valid_key_id(id) &&
            !(input.new_user_key_id == user.user_key_id &&
                !input.keys.is_v2())
        {
            return Err(AppError::bad_request(
                "Key id must be 32 lowercase hex characters",
            ));
        }
    }
    if input.old_user_key_id != user.user_key_id {
        return Err(AppError::conflict(
            "The current user key changed. Sync and retry.",
        ));
    }
    if input.wrapped_user_key.trim().is_empty() {
        return Err(AppError::bad_request("Wrapped user key is required"));
    }
    if let Some(upgrade) = &input.upgrade {
        if ["wrappedUserKey1", "wrappedUserKey2"].iter().any(|field| {
            upgrade[*field].as_str().is_none_or(|s| s.trim().is_empty())
        }) {
            return Err(AppError::bad_request(
                "Both V2 upgrade wrapped user keys are required",
            ));
        }
    }
    let is_upgrade =
        input.password.is_none() && input.upgrade.is_some() && !user.is_v2();
    let ciphers = CollectionSnapshot::load(
        &db,
        "ciphers",
        CIPHERS,
        &claims.sub,
        "user_id=?1",
    )
    .await?;
    let folders = CollectionSnapshot::load(
        &db,
        "folders",
        FOLDERS,
        &claims.sub,
        "user_id=?1",
    )
    .await?;
    let attachments = CollectionSnapshot::load(
        &db,
        "attachments",
        ATTACHMENTS,
        &claims.sub,
        "cipher_id IN (SELECT id FROM ciphers WHERE user_id=?1)",
    )
    .await?;
    let passkeys = CollectionSnapshot::load(
        &db,
        "webauthn_credentials",
        PASSKEYS,
        &claims.sub,
        "user_id=?1",
    )
    .await?;
    let cipher_ids = input
        .data
        .ciphers
        .iter()
        .filter_map(|c| c.id.clone())
        .collect::<HashSet<_>>();
    let folder_ids = input
        .data
        .folders
        .iter()
        .filter_map(|f| f.id.clone())
        .collect::<HashSet<_>>();
    if cipher_ids.len() != input.data.ciphers.len() ||
        cipher_ids != ciphers.ids()? ||
        folder_ids.len() !=
            input.data.folders.iter().filter(|f| f.id.is_some()).count() ||
        folder_ids != folders.ids()?
    {
        return Err(AppError::conflict(
            "Every existing cipher and folder must occur exactly once in key \
             rotation",
        ));
    }
    for cipher in &input.data.ciphers {
        cipher.validate_for_personal_vault(&claims.sub)?;
        cipher.validate_encryption_context(
            &claims.sub,
            input.new_user_key_id.as_deref(),
        )?;
    }
    let attachment_rows = attachments.rows()?;
    for cipher in &input.data.ciphers {
        if let Some(files) = &cipher.attachments2 {
            for id in files.keys() {
                if !attachment_rows.iter().any(|row| {
                    row["id"].as_str() == Some(id.as_str()) &&
                        row["cipher_id"].as_str() == cipher.id.as_deref()
                }) {
                    return Err(AppError::bad_request(
                        "Rotated attachment does not belong to the cipher",
                    ));
                }
            }
        }
    }
    let expected_attachments = attachments.ids()?;
    let provided_attachments = input
        .data
        .ciphers
        .iter()
        .flat_map(|c| c.attachments2.iter().flat_map(|a| a.keys().cloned()))
        .collect::<Vec<_>>();
    if provided_attachments.len() != expected_attachments.len() ||
        provided_attachments.into_iter().collect::<HashSet<_>>() !=
            expected_attachments
    {
        return Err(AppError::conflict(
            "Every existing attachment must be rewrapped during rotation",
        ));
    }
    let expected_passkeys = passkeys
        .rows()?
        .into_iter()
        .filter(|row| {
            row["credential_use"] == "login" &&
                row["encrypted_user_key"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()) &&
                row["encrypted_private_key"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty())
        })
        .map(|row| row["slot"].to_string())
        .collect::<HashSet<_>>();
    let provided_passkeys = input
        .passkeys
        .iter()
        .filter_map(|row| row["id"].as_str().map(str::to_string))
        .collect::<HashSet<_>>();
    if provided_passkeys.len() != input.passkeys.len() ||
        provided_passkeys != expected_passkeys
    {
        return Err(AppError::conflict(
            "Every enabled passkey must be rewrapped during rotation",
        ));
    }
    let now = crate::infra::time::now_rfc3339();
    let write_token = Uuid::new_v4().to_string();
    let (send_writes, send_guards) = send::rotation_statements(
        &db,
        &claims.sub,
        &input.data.sends,
        &now,
        &write_token,
    )
    .await?;
    let snapshot = AccountSnapshot::from_user(user).to_json()?;
    let (hash, salt, kdf, iterations, memory, parallelism, hint) = if let Some(
        (hash, key_salt, kdf, iterations, memory, parallelism, hint),
    ) =
        input.password
    {
        (
            hash,
            Some(key_salt),
            kdf,
            iterations,
            memory,
            parallelism,
            hint,
        )
    } else {
        (
            user.master_password_hash.clone(),
            user.password_salt.clone(),
            user.kdf_type,
            user.kdf_iterations,
            user.kdf_memory,
            user.kdf_parallelism,
            user.master_password_hint.clone(),
        )
    };
    let new_snapshot = AccountSnapshot {
        key:                input.wrapped_user_key.clone(),
        user_key_id:        input.new_user_key_id.clone(),
        private_key:        input.keys.private_key.clone(),
        public_key:         input.keys.public_key.clone(),
        signed_public_key:  input.keys.signed_public_key.clone(),
        security_state:     input.keys.security_state.clone(),
        security_version:   input.keys.security_version,
        signature_key_pair: input.keys.signature_key_pair.clone(),
    }
    .to_json()?;
    let final_stamp = if is_upgrade {
        user.security_stamp.clone()
    } else {
        Uuid::new_v4().to_string()
    };
    let upgrade = if is_upgrade {
        input.upgrade.map(|v| v.to_string())
    } else {
        None
    };
    let sql = format!(
        "UPDATE users SET \
         key=?1,private_key=?2,public_key=?3,signed_public_key=?4,\
         security_state=?5,security_version=?6,signature_key_pair=?7,\
         user_key_id=?8,v2_upgrade_token=?9,security_stamp=?10,\
         account_write_token=?11,master_password_hash=?12,password_salt=?13,\
         kdf_type=?14,kdf_iterations=?15,kdf_memory=?16,kdf_parallelism=?17,\
         master_password_hint=?18,security_stamp_exceptions=NULL,\
         updated_at=CASE WHEN updated_at>=?19 THEN \
         strftime('%Y-%m-%dT%H:%M:%fZ',julianday(updated_at)+1.0/86400000) \
         ELSE ?19 END WHERE id=?20 AND security_stamp=?21 AND \
         master_password_hash=?22 AND ({}) AND NOT EXISTS(SELECT 1 FROM \
         attachments_pending p JOIN ciphers c ON c.id=p.cipher_id WHERE \
         c.user_id=?20) AND EXISTS(SELECT 1 FROM devices WHERE user_id=?20 \
         AND identifier=?24 AND session_token=?25) RETURNING id",
        AccountSnapshot::matches_sql(23)
    );
    let bind: Vec<JsValue> = vec![
        input.wrapped_user_key.into(),
        input.keys.private_key.into(),
        input.keys.public_key.into(),
        js(input.keys.signed_public_key),
        js(input.keys.security_state),
        js(input.keys.security_version),
        js(input.keys.signature_key_pair),
        js(input.new_user_key_id),
        js(upgrade),
        final_stamp.into(),
        write_token.clone().into(),
        hash.into(),
        js(salt),
        kdf.into(),
        iterations.into(),
        js(memory),
        js(parallelism),
        js(hint),
        now.clone().into(),
        claims.sub.clone().into(),
        claims.sstamp.clone().into(),
        user.master_password_hash.clone().into(),
        snapshot.into(),
        claims.device().unwrap_or_default().into(),
        claims.session_token.clone().into(),
    ];
    let mut writes: Vec<D1PreparedStatement> =
        vec![db.prepare(&sql).bind(&bind)?];
    for source in [&ciphers, &folders, &attachments, &passkeys] {
        writes.extend(source.guards(&db, &claims.sub)?);
    }
    writes.extend(send_guards);
    writes.extend(send_writes);
    for cipher in &input.data.ciphers {
        let id = cipher.id.as_deref().ok_or(AppError::Internal)?;
        let data = serde_json::to_string(&CipherData::from_request(cipher))
            .map_err(|_| AppError::Internal)?;
        writes.push(query!(
            &db,
            "UPDATE ciphers SET data=?1,updated_at=?2 WHERE id=?3 AND \
             user_id=?4 AND EXISTS(SELECT 1 FROM users WHERE id=?4 AND \
             account_write_token=?5)",
            data,
            now,
            id,
            claims.sub,
            write_token
        )?);
        if let Some(attachments) = &cipher.attachments2 {
            for (attachment_id, attachment) in attachments {
                if attachment.key.trim().is_empty() ||
                    attachment.file_name.trim().is_empty()
                {
                    return Err(AppError::bad_request(
                        "Rotated attachment keys and names are required",
                    ));
                }
                writes.push(query!(
                    &db,
                    "UPDATE attachments SET \
                     file_name=?1,akey=?2,updated_at=?3 WHERE id=?4 AND \
                     cipher_id=?5 AND EXISTS(SELECT 1 FROM users WHERE id=?6 \
                     AND account_write_token=?7)",
                    attachment.file_name,
                    attachment.key,
                    now,
                    attachment_id,
                    id,
                    claims.sub,
                    write_token
                )?);
            }
        }
    }
    for folder in &input.data.folders {
        if let Some(id) = &folder.id {
            writes.push(query!(
                &db,
                "UPDATE folders SET name=?1,updated_at=?2 WHERE id=?3 AND \
                 user_id=?4 AND EXISTS(SELECT 1 FROM users WHERE id=?4 AND \
                 account_write_token=?5)",
                folder.name,
                now,
                id,
                claims.sub,
                write_token
            )?);
        }
    }
    for passkey in input.passkeys {
        let id = passkey["id"].as_str().ok_or(AppError::Internal)?;
        let public = passkey["encryptedPublicKey"]
            .as_str()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                AppError::bad_request("Passkey encryptedPublicKey is required")
            })?;
        let key = passkey["encryptedUserKey"]
            .as_str()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                AppError::bad_request("Passkey encryptedUserKey is required")
            })?;
        writes.push(query!(
            &db,
            "UPDATE webauthn_credentials SET \
             encrypted_public_key=?1,encrypted_user_key=?2,account_snapshot=?\
             7,updated_at=?3 WHERE user_id=?4 AND CAST(slot AS TEXT)=?5 AND \
             EXISTS(SELECT 1 FROM users WHERE id=?4 AND \
             account_write_token=?6)",
            public,
            key,
            now,
            claims.sub,
            id,
            write_token,
            new_snapshot
        )?);
    }
    for statement in [
        "DELETE FROM twofactor WHERE user_uuid=?1 AND atype=5 AND \
         EXISTS(SELECT 1 FROM users WHERE id=?1 AND account_write_token=?2)",
        "DELETE FROM auth_requests WHERE user_id=?1 AND EXISTS(SELECT 1 FROM \
         users WHERE id=?1 AND account_write_token=?2)",
    ] {
        writes.push(
            db.prepare(statement).bind(&[
                claims.sub.clone().into(),
                write_token.clone().into(),
            ])?,
        );
    }
    let results = db.batch(writes).await.map_err(|error| {
        if error
            .to_string()
            .contains(super::cipher_mutation::CONFLICT_SENTINEL)
        {
            AppError::conflict(
                "The vault changed during key rotation. Sync and retry.",
            )
        } else {
            super::cipher_mutation::map_database_error(error)
        }
    })?;
    if results
        .first()
        .ok_or(AppError::Internal)?
        .results::<Value>()?
        .is_empty()
    {
        return Err(AppError::conflict(
            "The vault changed during key rotation. Sync and retry.",
        ));
    }
    if changes_password {
        notifications::publish_user_update(
            &state.env,
            &claims.sub,
            UpdateType::LogOut,
            &now,
            claims.device(),
        )
        .await;
    } else {
        notifications::publish_key_rotation(
            &state.env,
            &claims.sub,
            &now,
            claims.device(),
        )
        .await;
    }
    admin_notify::emit(
        &state.env,
        if changes_password {
            Event::PasswordChange
        } else {
            Event::AccountSecurityChanged
        },
        &user.id,
    )
    .await;
    Ok(())
}
fn js<T: serde::Serialize>(value: Option<T>) -> JsValue {
    value.map_or(JsValue::NULL, |v| {
        serde_json::to_value(v)
            .ok()
            .map_or(JsValue::NULL, |v| match v {
                Value::String(s) => s.into(),
                Value::Number(n) => {
                    n.as_f64().map_or(JsValue::NULL, JsValue::from_f64)
                }
                _ => JsValue::NULL,
            })
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn change_credentials(
    state: &AppState,
    claims: &Claims,
    user: &UserDB,
    hash: &str,
    salt: &str,
    key: &str,
    kdf: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
    hint: Option<&str>,
) -> AppResult<()> {
    if hash.trim().is_empty() || key.trim().is_empty() {
        return Err(AppError::bad_request(
            "Password hash and wrapped key must not be empty",
        ));
    }
    let db = state.get_db();
    let token = Uuid::new_v4().to_string();
    let now = crate::infra::time::now_rfc3339();
    let previous = AccountSnapshot::from_user(user).to_json()?;
    let sql = format!(
        "UPDATE users SET \
         master_password_hash=?1,password_salt=?2,key=?3,kdf_type=?4,\
         kdf_iterations=?5,kdf_memory=?6,kdf_parallelism=?7,\
         master_password_hint=?8,security_stamp=?9,account_write_token=?9,\
         v2_upgrade_token=NULL,security_stamp_exceptions=NULL,updated_at=?10 \
         WHERE id=?11 AND security_stamp=?12 AND master_password_hash=?13 AND \
         ({}) AND EXISTS(SELECT 1 FROM devices WHERE user_id=?11 AND \
         identifier=?15 AND session_token=?16) RETURNING id",
        AccountSnapshot::matches_sql(14)
    );
    let writes = vec![
        db.prepare(&sql).bind(&[
            hash.into(),
            salt.into(),
            key.into(),
            kdf.into(),
            iterations.into(),
            js(memory),
            js(parallelism),
            js(hint),
            token.clone().into(),
            now.into(),
            user.id.clone().into(),
            claims.sstamp.clone().into(),
            user.master_password_hash.clone().into(),
            previous.clone().into(),
            claims.device().unwrap_or_default().into(),
            claims.session_token.clone().into(),
        ])?,
        query!(
            &db,
            "DELETE FROM twofactor WHERE user_uuid=?1 AND atype=5 AND \
             EXISTS(SELECT 1 FROM users WHERE id=?1 AND \
             account_write_token=?2)",
            user.id,
            token
        )?,
        query!(
            &db,
            "DELETE FROM auth_requests WHERE user_id=?1 AND EXISTS(SELECT 1 \
             FROM users WHERE id=?1 AND account_write_token=?2)",
            user.id,
            token
        )?,
        query!(
            &db,
            "UPDATE webauthn_credentials SET \
             account_snapshot=json_set(account_snapshot,'$.key',?1) WHERE \
             user_id=?2 AND account_snapshot=?3 AND EXISTS(SELECT 1 FROM \
             users WHERE id=?2 AND account_write_token=?4)",
            key,
            user.id,
            previous,
            token
        )?,
    ];
    let rows = db::run_query(
        async { db.batch(writes).await },
        "Failed to change account credentials",
    )
    .await?;
    if rows[0].results::<Value>()?.is_empty() {
        return Err(AppError::conflict(
            "Account changed during credential update. Retry.",
        ));
    }
    Ok(())
}
