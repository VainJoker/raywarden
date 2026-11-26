pub mod rotation;

use serde::{Deserialize, Serialize};
use worker::{D1Database, query};

use super::{
    authorization::{map_session_write_error, session_guard},
    device::SessionSnapshot,
    user::UserRow,
};
use crate::{
    errors::{AppError, AppResult},
    infra::db,
    models::mutation::next_user_revision_sql,
};

/// Persisted asymmetric account-key columns, independent of request validation.
#[derive(Debug, Clone)]
pub struct AccountKeyMaterial {
    pub private_key: String,
    pub public_key: String,
    pub signed_public_key: Option<String>,
    pub security_state: Option<String>,
    pub security_version: Option<i32>,
    pub signature_key_pair: Option<String>,
}

#[derive(Deserialize)]
pub struct PublicKeyRow {
    pub id: String,
    pub public_key: String,
}

pub async fn set_key_id(db: &D1Database, session: &SessionSnapshot<'_>, id: &str) -> AppResult<()> {
    let now = crate::utils::time::now_rfc3339();
    let revision_sql = next_user_revision_sql(2);
    let statement = query!(
        db,
        format!(
            "UPDATE users SET user_key_id=?1, \
                 updated_at={revision_sql} WHERE id=?3 AND \
                 user_key_id IS NULL RETURNING id"
        ),
        id,
        now,
        session.user_id
    )?;
    let results = db
        .batch(vec![session_guard(db, session)?, statement])
        .await
        .map_err(|error| map_session_write_error("Failed to initialize user key ID", &error))?;
    let row: Option<serde_json::Value> = results
        .last()
        .ok_or_else(|| AppError::internal("Missing user key ID initialization batch result"))?
        .results()?
        .into_iter()
        .next();
    if row.is_none() {
        return Err(AppError::bad_request("User key ID is already initialized"));
    }
    Ok(())
}

pub async fn public_key(db: &D1Database, user: &str) -> AppResult<PublicKeyRow> {
    db::query_first(
        query!(
            db,
            "SELECT id, public_key FROM users WHERE id=?1 AND \
                 public_key<>''",
            user
        ),
        None,
        "Failed to fetch public key",
    )
    .await?
    .ok_or_else(|| AppError::not_found("Public key"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountSnapshot<Text = String> {
    pub key: Text,
    pub user_key_id: Option<Text>,
    pub private_key: Text,
    pub public_key: Text,
    pub signed_public_key: Option<Text>,
    pub security_state: Option<Text>,
    pub security_version: Option<i32>,
    pub signature_key_pair: Option<Text>,
}
impl AccountSnapshot {
    pub fn borrowed(user: &UserRow) -> AccountSnapshot<&str> {
        AccountSnapshot {
            key: user.key.as_str(),
            user_key_id: user.user_key_id.as_deref(),
            private_key: user.private_key.as_str(),
            public_key: user.public_key.as_str(),
            signed_public_key: user.signed_public_key.as_deref(),
            security_state: user.security_state.as_deref(),
            security_version: user.security_version,
            signature_key_pair: user.signature_key_pair.as_deref(),
        }
    }

    pub fn as_borrowed(&self) -> AccountSnapshot<&str> {
        AccountSnapshot {
            key: self.key.as_str(),
            user_key_id: self.user_key_id.as_deref(),
            private_key: self.private_key.as_str(),
            public_key: self.public_key.as_str(),
            signed_public_key: self.signed_public_key.as_deref(),
            security_state: self.security_state.as_deref(),
            security_version: self.security_version,
            signature_key_pair: self.signature_key_pair.as_deref(),
        }
    }

    pub fn matches_user(&self, user: &UserRow) -> bool {
        self.as_borrowed() == Self::borrowed(user)
    }

    pub fn users_match(left: &UserRow, right: &UserRow) -> bool {
        Self::borrowed(left) == Self::borrowed(right)
    }

    pub fn from_user(user: &UserRow) -> Self {
        Self {
            key: user.key.clone(),
            user_key_id: user.user_key_id.clone(),
            private_key: user.private_key.clone(),
            public_key: user.public_key.clone(),
            signed_public_key: user.signed_public_key.clone(),
            security_state: user.security_state.clone(),
            security_version: user.security_version,
            signature_key_pair: user.signature_key_pair.clone(),
        }
    }

    pub async fn load(db: &D1Database, user_id: &str) -> AppResult<Self> {
        db::query_first(
            db.prepare(
                "SELECT key,user_key_id,private_key,public_key,\
                 signed_public_key,security_state,security_version,\
                 signature_key_pair FROM users WHERE id=?1",
            )
            .bind(&db::d1_params![user_id]),
            None,
            "Failed to load account encryption state",
        )
        .await?
        .ok_or_else(|| AppError::not_found("Account"))
    }

    pub fn to_json(&self) -> AppResult<String> {
        serde_json::to_string(self).map_err(AppError::internal_json(
            "Failed to serialize account key snapshot",
        ))
    }

    pub fn json_from_user(user: &UserRow) -> AppResult<String> {
        serde_json::to_string(&Self::borrowed(user)).map_err(AppError::internal_json(
            "Failed to serialize account key snapshot",
        ))
    }

    pub fn matches_sql(parameter: usize) -> String {
        Self::matches_sql_expression("", &format!("?{parameter}"))
    }

    /// Compare against a snapshot expression from the query itself. The
    /// qualifier and expression are SQL fragments supplied by the model.
    pub(super) fn matches_sql_expression(qualifier: &str, snapshot: &str) -> String {
        [
            "key",
            "user_key_id",
            "private_key",
            "public_key",
            "signed_public_key",
            "security_state",
            "security_version",
            "signature_key_pair",
        ]
        .map(|column| format!("{qualifier}{column} IS json_extract({snapshot}, '$.{column}')"))
        .join(" AND ")
    }
}
