use serde_json::Value;
use worker::query;

use crate::{
    api::AppState,
    errors::{
        AppError,
        DatabaseError,
    },
    models::user::User,
};

pub struct UserKdfParams {
    pub kdf_type:        Option<i32>,
    pub kdf_iterations:  Option<i32>,
    pub kdf_memory:      Option<i32>,
    pub kdf_parallelism: Option<i32>,
}

pub async fn get_kdf_params_by_email(
    state: &AppState,
    email: &str,
) -> Result<UserKdfParams, AppError> {
    let db = state.get_db();

    let stmt = db.prepare(
        "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM \
         users WHERE email = ?1",
    );
    let query = stmt.bind(&[email.into()])?;

    let row: Option<Value> = query.first(None).await.map_err(|e| {
        log::warn!("get_kdf_params_by_email query failed: {e}");
        AppError::Database(DatabaseError::QueryFailed(e.to_string()))
    })?;

    if let Some(row) = row {
        let kdf_type = row
            .get("kdf_type")
            .and_then(serde_json::Value::as_i64)
            .map(|value| value as i32);
        let kdf_iterations = row
            .get("kdf_iterations")
            .and_then(serde_json::Value::as_i64)
            .map(|value| value as i32);
        let kdf_memory = row
            .get("kdf_memory")
            .and_then(serde_json::Value::as_i64)
            .map(|value| value as i32);
        let kdf_parallelism = row
            .get("kdf_parallelism")
            .and_then(serde_json::Value::as_i64)
            .map(|value| value as i32);

        Ok(UserKdfParams {
            kdf_type,
            kdf_iterations,
            kdf_memory,
            kdf_parallelism,
        })
    } else {
        Ok(UserKdfParams {
            kdf_type:        None,
            kdf_iterations:  None,
            kdf_memory:      None,
            kdf_parallelism: None,
        })
    }
}

pub async fn insert_user(
    state: &AppState,
    user: &User,
) -> Result<(), AppError> {
    let db = state.get_db();

    query!(
        &db,
        "INSERT INTO users (id, name, email, master_password_hash, \
         master_password_hint, password_salt, key, private_key, public_key, \
         kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, \
         security_stamp, totp_recover, created_at, updated_at) VALUES (?1, \
         ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
         ?17)",
        user.id,
        user.name,
        user.email,
        user.master_password_hash,
        user.master_password_hint,
        user.password_salt,
        user.key,
        user.private_key,
        user.public_key,
        user.kdf_type,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism,
        user.security_stamp,
        user.totp_recover,
        user.created_at,
        user.updated_at
    )
    .map_err(|e| {
        log::warn!("insert_user bind failed: {e}");
        AppError::Database(DatabaseError::QueryFailed(e.to_string()))
    })?
    .run()
    .await
    .map_err(|e| {
        log::warn!("insert_user run failed: {e}");
        AppError::Database(DatabaseError::QueryFailed(e.to_string()))
    })?;

    Ok(())
}
