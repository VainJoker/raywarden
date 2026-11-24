//! Account rotation snapshots and guarded persistence.
use std::collections::HashSet;

use serde_json::Value;
use worker::{D1Database, D1PreparedStatement, query, wasm_bindgen::JsValue};

use super::AccountSnapshot;
use crate::{
    errors::{AppError, AppResult, DatabaseError},
    infra::db,
    models::{
        identity::{device::SessionSnapshot, user::UserRow},
        mutation::map_database_error,
        page::{PageOrder, PageQuery},
    },
};

const CIPHERS: &[&str] = &[
    "id",
    "user_id",
    "organization_id",
    "cipher_type",
    "data",
    "is_favorite",
    "folder_id",
    "deleted_at",
    "archived_at",
    "created_at",
    "updated_at",
];
const CIPHER_TEXT_COLUMNS: &[&str] = &[
    "id",
    "user_id",
    "organization_id",
    "data",
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
    "file_size_bytes",
    "encrypted_key",
    "storage_key",
    "created_at",
    "updated_at",
];
const ATTACHMENT_TEXT_COLUMNS: &[&str] = &[
    "id",
    "cipher_id",
    "file_name",
    "encrypted_key",
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
const PASSKEY_TEXT_COLUMNS: &[&str] = &[
    "id",
    "credential_id",
    "public_key",
    "credential_use",
    "encrypted_public_key",
    "encrypted_user_key",
    "encrypted_private_key",
    "account_snapshot",
    "updated_at",
];

pub struct CollectionSnapshot {
    table: &'static str,
    columns: &'static [&'static str],
    filter: &'static str,
    rows: Vec<Value>,
}
impl CollectionSnapshot {
    pub async fn ciphers(db: &D1Database, owner: &str) -> AppResult<Self> {
        Self::load(
            db,
            "ciphers",
            CIPHERS,
            CIPHER_TEXT_COLUMNS,
            owner,
            "user_id=?1",
            "user_id=?",
        )
        .await
    }
    pub async fn folders(db: &D1Database, owner: &str) -> AppResult<Self> {
        Self::load(
            db,
            "folders",
            FOLDERS,
            FOLDERS,
            owner,
            "user_id=?1",
            "user_id=?",
        )
        .await
    }
    pub async fn attachments(db: &D1Database, owner: &str) -> AppResult<Self> {
        Self::load(
            db,
            "attachments",
            ATTACHMENTS,
            ATTACHMENT_TEXT_COLUMNS,
            owner,
            "cipher_id IN (SELECT id FROM ciphers WHERE user_id=?1)",
            "cipher_id IN (SELECT id FROM ciphers WHERE user_id=?)",
        )
        .await
    }
    pub async fn passkeys(db: &D1Database, owner: &str) -> AppResult<Self> {
        Self::load(
            db,
            "webauthn_credentials",
            PASSKEYS,
            PASSKEY_TEXT_COLUMNS,
            owner,
            "user_id=?1",
            "user_id=?",
        )
        .await
    }

    async fn load(
        db: &D1Database,
        table: &'static str,
        columns: &'static [&'static str],
        text_columns: &'static [&'static str],
        owner: &str,
        filter: &'static str,
        page_filter: &'static str,
    ) -> AppResult<Self> {
        let query = PageQuery {
            table,
            filter: page_filter,
            text_columns,
            order: PageOrder::RowId,
            related_bytes: None,
        };
        let mut rows = query.fetch_all::<Value>(db, &db::d1_params![owner]).await?;
        rows.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
        Ok(Self {
            table,
            columns,
            filter,
            rows,
        })
    }
    pub fn guards(&self, db: &D1Database, owner: &str) -> AppResult<Vec<D1PreparedStatement>> {
        let mut guards = vec![crate::models::mutation::guard(
            db,
            &format!(
                "(SELECT COUNT(*) FROM {} WHERE {})=?2",
                self.table, self.filter
            ),
            &db::d1_params![owner, self.rows.len() as f64],
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
            let mut values = Vec::with_capacity(self.columns.len() + 1);
            values.push(JsValue::from_str(owner));
            for column in self.columns {
                values.push(json_scalar_binding(&row[*column])?);
            }
            guards.push(crate::models::mutation::guard(db, &predicate, &values)?);
        }
        Ok(guards)
    }
    pub fn rows(&self) -> &[Value] {
        &self.rows
    }
    pub fn ids(&self) -> HashSet<&str> {
        self.rows
            .iter()
            .filter_map(|row| row["id"].as_str())
            .collect()
    }
}
fn json_scalar_binding(value: &Value) -> AppResult<JsValue> {
    Ok(match value {
        Value::Null => JsValue::NULL,
        Value::String(value) => value.as_str().into(),
        Value::Number(value) => JsValue::from_f64(value.as_f64().ok_or(AppError::Internal)?),
        Value::Bool(value) => JsValue::from_f64(f64::from(u8::from(*value))),
        _ => return Err(AppError::Internal),
    })
}

pub fn claim_rotation(
    db: &D1Database,
    user: &UserRow,
    session: &SessionSnapshot<'_>,
    next: &UserRow,
    write_token: &str,
    now: &str,
) -> AppResult<D1PreparedStatement> {
    let snapshot = AccountSnapshot::json_from_user(user)?;
    let revision_sql = crate::models::mutation::next_user_revision_sql(19);
    let sql = format!(
        "UPDATE users SET \
         key=?1,private_key=?2,public_key=?3,signed_public_key=?4,\
         security_state=?5,security_version=?6,signature_key_pair=?7,\
         user_key_id=?8,v2_upgrade_token=?9,security_stamp=?10,\
         account_write_token=?11,master_password_hash=?12,password_salt=?13,\
         kdf_type=?14,kdf_iterations=?15,kdf_memory=?16,kdf_parallelism=?17,\
         master_password_hint=?18,password_iterations=?28,\
         security_stamp_exceptions=NULL,updated_at={revision_sql} WHERE \
         id=?20 AND security_stamp=?21 AND master_password_hash=?22 AND \
         password_salt IS ?26 AND password_iterations=?27 AND ({}) AND NOT \
         EXISTS(SELECT 1 FROM attachments_pending p JOIN ciphers c ON \
         c.id=p.cipher_id WHERE c.user_id=?20) AND EXISTS(SELECT 1 FROM \
         devices WHERE user_id=?20 AND device_id=?24 AND session_token=?25) \
         RETURNING id, updated_at",
        AccountSnapshot::matches_sql(23)
    );
    let bind = db::d1_params![
        next.key,
        next.private_key,
        next.public_key,
        next.signed_public_key,
        next.security_state,
        next.security_version,
        next.signature_key_pair,
        next.user_key_id,
        next.v2_upgrade_token,
        next.security_stamp,
        write_token,
        next.master_password_hash,
        next.password_salt,
        next.kdf_type,
        next.kdf_iterations,
        next.kdf_memory,
        next.kdf_parallelism,
        next.master_password_hint,
        now,
        session.user_id,
        session.security_stamp,
        user.master_password_hash,
        snapshot,
        session.device_id,
        session.session_token,
        user.password_salt,
        user.password_iterations,
        next.password_iterations,
    ];
    Ok(db.prepare(&sql).bind(&bind)?)
}
pub fn cipher_write(
    db: &D1Database,
    owner: &str,
    id: &str,
    data: &str,
    now: &str,
    write_token: &str,
) -> AppResult<D1PreparedStatement> {
    Ok(query!(
        db,
        "UPDATE ciphers SET data=?1,updated_at=?2 WHERE id=?3 AND user_id=?4 \
         AND EXISTS(SELECT 1 FROM users WHERE id=?4 AND \
         account_write_token=?5)",
        data,
        now,
        id,
        owner,
        write_token
    )?)
}
#[derive(Clone, Copy)]
pub struct RotatedAttachmentWrite<'a> {
    pub owner: &'a str,
    pub cipher: &'a str,
    pub attachment_id: &'a str,
    pub file_name: &'a str,
    pub key: &'a str,
    pub now: &'a str,
    pub write_token: &'a str,
}

pub fn attachment_write(
    db: &D1Database,
    write: RotatedAttachmentWrite<'_>,
) -> AppResult<D1PreparedStatement> {
    let RotatedAttachmentWrite {
        owner,
        cipher,
        attachment_id,
        file_name,
        key,
        now,
        write_token,
    } = write;
    Ok(query!(
        db,
        "UPDATE attachments SET file_name=?1,encrypted_key=?2,updated_at=?3 \
         WHERE id=?4 AND cipher_id=?5 AND EXISTS(SELECT 1 FROM users WHERE \
         id=?6 AND account_write_token=?7)",
        file_name,
        key,
        now,
        attachment_id,
        cipher,
        owner,
        write_token
    )?)
}
pub fn folder_write(
    db: &D1Database,
    owner: &str,
    id: &str,
    name: &str,
    now: &str,
    write_token: &str,
) -> AppResult<D1PreparedStatement> {
    Ok(query!(
        db,
        "UPDATE folders SET name=?1,updated_at=?2 WHERE id=?3 AND user_id=?4 \
         AND EXISTS(SELECT 1 FROM users WHERE id=?4 AND \
         account_write_token=?5)",
        name,
        now,
        id,
        owner,
        write_token
    )?)
}
#[derive(Clone, Copy)]
pub struct RotatedPasskeyWrite<'a> {
    pub owner: &'a str,
    pub id: &'a str,
    pub public: &'a str,
    pub key: &'a str,
    pub snapshot: &'a str,
    pub now: &'a str,
    pub write_token: &'a str,
}

pub fn passkey_write(
    db: &D1Database,
    write: RotatedPasskeyWrite<'_>,
) -> AppResult<D1PreparedStatement> {
    let RotatedPasskeyWrite {
        owner,
        id,
        public,
        key,
        snapshot,
        now,
        write_token,
    } = write;
    Ok(query!(
        db,
        "UPDATE webauthn_credentials SET \
         encrypted_public_key=?1,encrypted_user_key=?2,account_snapshot=?7,\
         updated_at=?3 WHERE user_id=?4 AND CAST(slot AS TEXT)=?5 AND \
         EXISTS(SELECT 1 FROM users WHERE id=?4 AND account_write_token=?6)",
        public,
        key,
        now,
        owner,
        id,
        write_token,
        snapshot
    )?)
}

fn invalidation_writes(
    db: &D1Database,
    owner: &str,
    write_token: &str,
) -> AppResult<Vec<D1PreparedStatement>> {
    let mut writes = Vec::new();
    for statement in [
        "DELETE FROM two_factors WHERE user_id=?1 AND provider_type=5 AND \
         EXISTS(SELECT 1 FROM users WHERE id=?1 AND account_write_token=?2)",
        "DELETE FROM auth_requests WHERE user_id=?1 AND EXISTS(SELECT 1 FROM \
         users WHERE id=?1 AND account_write_token=?2)",
    ] {
        writes.push(
            db.prepare(statement)
                .bind(&[owner.into(), write_token.into()])?,
        );
    }
    Ok(writes)
}

pub(crate) async fn commit(
    db: &D1Database,
    owner: &str,
    write_token: &str,
    mut writes: Vec<D1PreparedStatement>,
) -> AppResult<String> {
    use crate::models::mutation::RevisionRow;

    writes.extend(invalidation_writes(db, owner, write_token)?);
    let results = db
        .batch(writes)
        .await
        .map_err(|error| DatabaseError::account_rotation(error, map_database_error))?;
    let revisions = db::decode_results::<RevisionRow>(results.first().ok_or(AppError::Internal)?)?;
    revisions
        .into_iter()
        .next()
        .map(|row| row.updated_at)
        .ok_or_else(DatabaseError::account_rotation_conflict)
}

#[derive(Clone, Copy)]
pub struct CredentialRotation<'a> {
    pub user: &'a UserRow,
    pub session: &'a SessionSnapshot<'a>,
    pub next: &'a UserRow,
    pub token: &'a str,
    pub now: &'a str,
}

pub async fn change_credentials(
    db: &D1Database,
    rotation: CredentialRotation<'_>,
) -> AppResult<()> {
    let CredentialRotation {
        user,
        session,
        next,
        token,
        now,
    } = rotation;
    let private_key_changed = next.private_key != user.private_key;
    let previous = AccountSnapshot::json_from_user(user)?;
    let revision_sql = crate::models::mutation::next_user_revision_sql(10);
    let sql = format!(
        "UPDATE users SET \
         master_password_hash=?1,password_salt=?2,key=?3,kdf_type=?4,\
         kdf_iterations=?5,kdf_memory=?6,kdf_parallelism=?7,\
         master_password_hint=?8,security_stamp=?9,account_write_token=?9,\
         v2_upgrade_token=NULL,security_stamp_exceptions=NULL,\
         updated_at={revision_sql},password_iterations=?19,private_key=?20,\
         public_key=?21 WHERE id=?11 AND security_stamp=?12 AND \
         master_password_hash=?13 AND password_salt IS ?17 AND \
         password_iterations=?18 AND ({}) AND EXISTS(SELECT 1 FROM devices \
         WHERE user_id=?11 AND device_id=?15 AND session_token=?16) RETURNING \
         id",
        AccountSnapshot::matches_sql(14)
    );
    let claim = db.prepare(&sql).bind(&db::d1_params![
        next.master_password_hash,
        next.password_salt.as_deref().unwrap_or_default(),
        next.key,
        next.kdf_type,
        next.kdf_iterations,
        next.kdf_memory,
        next.kdf_parallelism,
        next.master_password_hint,
        token,
        now,
        user.id,
        session.security_stamp,
        user.master_password_hash,
        previous,
        session.device_id,
        session.session_token,
        user.password_salt,
        user.password_iterations,
        next.password_iterations,
        next.private_key,
        next.public_key,
    ])?;
    let mut writes = vec![claim];
    writes.extend(invalidation_writes(db, &user.id, token)?);
    writes.push(if private_key_changed {
        query!(
            &db,
            "UPDATE webauthn_credentials SET \
             encrypted_public_key=NULL,encrypted_user_key=NULL,\
             encrypted_private_key=NULL,account_snapshot=NULL,prf_status=CASE \
             WHEN prf_status=0 THEN 1 ELSE prf_status END,updated_at=?1 WHERE \
             user_id=?2 AND EXISTS(SELECT 1 FROM users WHERE id=?2 AND \
             account_write_token=?3)",
            now,
            user.id,
            token
        )?
    } else {
        query!(
            &db,
            "UPDATE webauthn_credentials SET \
             account_snapshot=json_set(account_snapshot,'$.key',?1) WHERE \
             user_id=?2 AND account_snapshot=?3 AND EXISTS(SELECT 1 FROM \
             users WHERE id=?2 AND account_write_token=?4)",
            next.key,
            user.id,
            previous,
            token
        )?
    });
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
