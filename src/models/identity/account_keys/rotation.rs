//! Account rotation snapshots and guarded persistence.
use std::collections::HashSet;

use serde_json::Value;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
    wasm_bindgen::JsValue,
};

use super::AccountSnapshot;
use crate::{
    errors::{
        AppError,
        AppResult,
        DatabaseError,
    },
    infra::db,
    models::{
        identity::{
            device::SessionSnapshot,
            user::UserRow,
        },
        mutation::{
            CONFLICT_SENTINEL,
            map_database_error,
        },
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

pub struct CollectionSnapshot {
    table:   &'static str,
    columns: &'static [&'static str],
    filter:  &'static str,
    rows:    Vec<Value>,
}
impl CollectionSnapshot {
    pub async fn ciphers(db: &D1Database, owner: &str) -> AppResult<Self> {
        Self::load(db, "ciphers", CIPHERS, owner, "user_id=?1").await
    }
    pub async fn folders(db: &D1Database, owner: &str) -> AppResult<Self> {
        Self::load(db, "folders", FOLDERS, owner, "user_id=?1").await
    }
    pub async fn attachments(db: &D1Database, owner: &str) -> AppResult<Self> {
        Self::load(
            db,
            "attachments",
            ATTACHMENTS,
            owner,
            "cipher_id IN (SELECT id FROM ciphers WHERE user_id=?1)",
        )
        .await
    }
    pub async fn passkeys(db: &D1Database, owner: &str) -> AppResult<Self> {
        Self::load(db, "webauthn_credentials", PASSKEYS, owner, "user_id=?1")
            .await
    }

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
    pub fn guards(
        &self,
        db: &D1Database,
        owner: &str,
    ) -> AppResult<Vec<D1PreparedStatement>> {
        let mut guards = vec![crate::models::mutation::guard(
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
                values.push(json_scalar_binding(&row[*column])?);
            }
            guards
                .push(crate::models::mutation::guard(db, &predicate, &values)?);
        }
        Ok(guards)
    }
    pub fn rows(&self) -> &[Value] {
        &self.rows
    }
    pub fn ids(&self) -> HashSet<String> {
        self.rows
            .iter()
            .filter_map(|row| row["id"].as_str().map(str::to_string))
            .collect()
    }
}
fn json_scalar_binding(value: &Value) -> AppResult<JsValue> {
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

pub fn claim_rotation(
    db: &D1Database,
    user: &UserRow,
    session: &SessionSnapshot<'_>,
    next: &UserRow,
    write_token: &str,
    now: &str,
) -> AppResult<D1PreparedStatement> {
    let snapshot = AccountSnapshot::from_user(user).to_json()?;
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
         RETURNING id",
        AccountSnapshot::matches_sql(23)
    );
    let bind: Vec<JsValue> = vec![
        next.key.clone().into(),
        next.private_key.clone().into(),
        next.public_key.clone().into(),
        nullable_binding(next.signed_public_key.clone()),
        nullable_binding(next.security_state.clone()),
        nullable_binding(next.security_version),
        nullable_binding(next.signature_key_pair.clone()),
        nullable_binding(next.user_key_id.clone()),
        nullable_binding(next.v2_upgrade_token.clone()),
        next.security_stamp.clone().into(),
        write_token.into(),
        next.master_password_hash.clone().into(),
        nullable_binding(next.password_salt.clone()),
        next.kdf_type.into(),
        next.kdf_iterations.into(),
        nullable_binding(next.kdf_memory),
        nullable_binding(next.kdf_parallelism),
        nullable_binding(next.master_password_hint.clone()),
        now.into(),
        session.user_id.into(),
        session.security_stamp.into(),
        user.master_password_hash.clone().into(),
        snapshot.into(),
        session.device_id.into(),
        session.session_token.into(),
        nullable_binding(user.password_salt.clone()),
        user.password_iterations.into(),
        next.password_iterations.into(),
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
#[allow(
    clippy::too_many_arguments,
    reason = "Bind complete attachment metadata and the rotation capability \
              in one guarded statement"
)]
pub fn attachment_write(
    db: &D1Database,
    owner: &str,
    cipher: &str,
    attachment_id: &str,
    file_name: &str,
    key: &str,
    now: &str,
    write_token: &str,
) -> AppResult<D1PreparedStatement> {
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
#[allow(
    clippy::too_many_arguments,
    reason = "Bind complete passkey material and the rotation capability in \
              one guarded statement"
)]
pub fn passkey_write(
    db: &D1Database,
    owner: &str,
    id: &str,
    public: &str,
    key: &str,
    snapshot: &str,
    now: &str,
    write_token: &str,
) -> AppResult<D1PreparedStatement> {
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
) -> AppResult<()> {
    writes.extend(invalidation_writes(db, owner, write_token)?);
    let results = db.batch(writes).await.map_err(|error| {
        DatabaseError::account_rotation(
            error,
            CONFLICT_SENTINEL,
            map_database_error,
        )
    })?;
    if results
        .first()
        .ok_or(AppError::Internal)?
        .results::<Value>()?
        .is_empty()
    {
        return Err(DatabaseError::account_rotation_conflict());
    }
    Ok(())
}

fn nullable_binding<T: Into<JsValue>>(value: Option<T>) -> JsValue {
    value.map_or(JsValue::NULL, Into::into)
}

pub async fn change_credentials(
    db: &D1Database,
    user: &UserRow,
    session: &SessionSnapshot<'_>,
    next: &UserRow,
    token: &str,
    now: &str,
) -> AppResult<()> {
    let private_key_changed = next.private_key != user.private_key;
    let previous = AccountSnapshot::from_user(user).to_json()?;
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
    let mut writes = vec![
        db.prepare(&sql).bind(&[
            next.master_password_hash.clone().into(),
            next.password_salt.clone().unwrap_or_default().into(),
            next.key.clone().into(),
            next.kdf_type.into(),
            next.kdf_iterations.into(),
            nullable_binding(next.kdf_memory),
            nullable_binding(next.kdf_parallelism),
            nullable_binding(next.master_password_hint.clone()),
            token.into(),
            now.into(),
            user.id.clone().into(),
            session.security_stamp.into(),
            user.master_password_hash.clone().into(),
            previous.clone().into(),
            session.device_id.into(),
            session.session_token.into(),
            nullable_binding(user.password_salt.clone()),
            user.password_iterations.into(),
            next.password_iterations.into(),
            next.private_key.clone().into(),
            next.public_key.clone().into(),
        ])?,
        query!(
            &db,
            "DELETE FROM two_factors WHERE user_id=?1 AND provider_type=5 AND \
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
    ];
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
