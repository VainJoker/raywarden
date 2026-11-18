use serde::Deserialize;
use worker::{
    D1Database,
    query,
};

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::db,
    models::webauthn::now_string,
};

#[derive(Deserialize)]
pub struct ApiKeyDB {
    pub encrypted_key: String,
    pub key_hash:      String,
    pub updated_at:    String,
}
impl ApiKeyDB {
    pub async fn find(db: &D1Database, user: &str) -> AppResult<Option<Self>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT encrypted_key,key_hash,updated_at FROM \
                     user_api_keys WHERE user_id=?1",
                    user
                )?
                .first(None)
                .await
            },
            "Failed to fetch API key",
        )
        .await
    }
    pub async fn replace(
        db: &D1Database,
        user: &str,
        encrypted: &str,
        hash: &str,
    ) -> AppResult<()> {
        let now = now_string();
        db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "DELETE FROM devices WHERE user_id=?1 AND \
                         EXISTS(SELECT 1 FROM user_api_key_sessions s WHERE \
                         s.user_id=devices.user_id AND \
                         s.device_id=devices.identifier AND \
                         s.session_token=devices.session_token)",
                        user
                    )?,
                    query!(
                        db,
                        "DELETE FROM user_api_key_sessions WHERE user_id=?1",
                        user
                    )?,
                    query!(
                        db,
                        "INSERT INTO \
                         user_api_keys(user_id,encrypted_key,key_hash,\
                         updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(user_id) \
                         DO UPDATE SET \
                         encrypted_key=excluded.encrypted_key,\
                         key_hash=excluded.key_hash,updated_at=excluded.\
                         updated_at",
                        user,
                        encrypted,
                        hash,
                        now
                    )?,
                    query!(
                        db,
                        "UPDATE users SET updated_at=?1 WHERE id=?2",
                        now,
                        user
                    )?,
                ])
                .await
            },
            "Failed to rotate API key",
        )
        .await?;
        Ok(())
    }
    pub async fn bind_session(
        db: &D1Database,
        user: &str,
        device: &str,
        session: &str,
        key_hash: &str,
    ) -> AppResult<()> {
        let bound: Option<String> = db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO \
                     user_api_key_sessions(user_id,device_id,session_token) \
                     SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM user_api_keys \
                     WHERE user_id=?1 AND key_hash=?4) AND EXISTS(SELECT 1 \
                     FROM devices WHERE user_id=?1 AND identifier=?2 AND \
                     session_token=?3) ON CONFLICT(user_id,device_id) DO \
                     UPDATE SET session_token=excluded.session_token \
                     RETURNING user_id",
                    user,
                    device,
                    session,
                    key_hash
                )?
                .first(Some("user_id"))
                .await
            },
            "Failed to bind API key session",
        )
        .await?;
        if bound.is_none() {
            return Err(AppError::bad_request(
                "API key was rotated or session changed",
            ));
        }
        Ok(())
    }
}
