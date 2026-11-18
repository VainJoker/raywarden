use jiff::{
    SignedDuration,
    Timestamp,
};
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};
use uuid::Uuid;
use worker::{
    D1Database,
    D1PreparedStatement,
    query,
};

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::db,
};

pub fn now_string() -> String {
    crate::infra::time::now_rfc3339()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialDB {
    pub id:                    String,
    pub user_id:               String,
    pub slot:                  i32,
    pub name:                  String,
    pub credential_id:         String,
    pub public_key:            String,
    pub sign_count:            i64,
    pub credential_use:        String,
    pub prf_status:            i32,
    pub encrypted_public_key:  Option<String>,
    pub encrypted_user_key:    Option<String>,
    pub encrypted_private_key: Option<String>,
    pub last_challenge:        Option<String>,
    #[serde(default)]
    pub account_snapshot:      Option<String>,
    pub created_at:            String,
    pub updated_at:            String,
}
impl CredentialDB {
    pub fn to_json(&self) -> Value {
        fn enc(s: &Option<String>) -> Value {
            s.as_ref()
                .map_or(Value::Null, |s| json!({"encryptedString":s}))
        }
        json!({"id":self.slot,"Id":self.slot,"name":self.name,"Name":self.name,
            "prfStatus":self.prf_status,"PrfStatus":self.prf_status,
            "encryptedPublicKey":self.encrypted_public_key,"EncryptedPublicKey":self.encrypted_public_key,
            "encryptedPublicKeyObject":enc(&self.encrypted_public_key),"EncryptedPublicKeyObj":enc(&self.encrypted_public_key),
            "encryptedUserKey":self.encrypted_user_key,"EncryptedUserKey":self.encrypted_user_key,
            "encryptedUserKeyObject":enc(&self.encrypted_user_key),"EncryptedUserKeyObj":enc(&self.encrypted_user_key),
            "encryptedPrivateKey":self.encrypted_private_key,"EncryptedPrivateKey":self.encrypted_private_key,
            "encryptedPrivateKeyObject":enc(&self.encrypted_private_key),"EncryptedPrivateKeyObj":enc(&self.encrypted_private_key)})
    }
    pub async fn list(
        db: &D1Database,
        user: &str,
        usage: &str,
    ) -> AppResult<Vec<Self>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM webauthn_credentials WHERE user_id=?1 AND \
                     credential_use=?2 ORDER BY slot",
                    user,
                    usage
                )?
                .all()
                .await?
                .results()
            },
            "Failed to list WebAuthn credentials",
        )
        .await
    }
    pub async fn find(db: &D1Database, id: &str) -> AppResult<Option<Self>> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM webauthn_credentials WHERE credential_id=?1",
                    id
                )?
                .first(None)
                .await
            },
            "Failed to find WebAuthn credential",
        )
        .await
    }
    pub async fn find_owned(
        db: &D1Database,
        user: &str,
        usage: &str,
        id: &str,
    ) -> AppResult<Self> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM webauthn_credentials WHERE user_id=?1 AND \
                     credential_use=?2 AND (id=?3 OR CAST(slot AS TEXT)=?3 OR \
                     credential_id=?3)",
                    user,
                    usage,
                    id
                )?
                .first(None)
                .await
            },
            "Failed to find owned WebAuthn credential",
        )
        .await?
        .ok_or_else(|| AppError::not_found("WebAuthn credential"))
    }
    pub async fn register(
        &self,
        db: &D1Database,
        challenge: &ChallengeDB,
    ) -> AppResult<()> {
        let now = now_string();
        let result = db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "INSERT INTO webauthn_credentials \
                         (id,user_id,slot,name,credential_id,public_key,\
                         sign_count,credential_use,prf_status,\
                         encrypted_public_key,encrypted_user_key,\
                         encrypted_private_key,last_challenge,created_at,\
                         updated_at,account_snapshot) SELECT \
                         ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14,?\
                         15 WHERE EXISTS(SELECT 1 FROM webauthn_challenges c \
                         JOIN users u ON u.id=c.user_id WHERE c.id=?13 AND \
                         c.user_id=?2 AND c.security_stamp=u.security_stamp  \
                         AND u.key IS json_extract(c.account_snapshot, \
                         '$.key') AND u.user_key_id IS \
                         json_extract(c.account_snapshot, '$.user_key_id') \
                         AND u.private_key IS \
                         json_extract(c.account_snapshot, '$.private_key') \
                         AND u.public_key IS json_extract(c.account_snapshot, \
                         '$.public_key') AND u.signed_public_key IS \
                         json_extract(c.account_snapshot, \
                         '$.signed_public_key') AND u.security_state IS \
                         json_extract(c.account_snapshot, '$.security_state') \
                         AND u.security_version IS \
                         json_extract(c.account_snapshot, \
                         '$.security_version') AND u.signature_key_pair IS \
                         json_extract(c.account_snapshot, \
                         '$.signature_key_pair') AND c.consumed_at IS NULL \
                         AND julianday(c.expires_at) > julianday(?14) AND \
                         EXISTS(SELECT 1 FROM devices d WHERE d.user_id=u.id \
                         AND d.identifier=c.device_id AND \
                         d.session_token=c.session_token))",
                        self.id,
                        self.user_id,
                        self.slot,
                        self.name,
                        self.credential_id,
                        self.public_key,
                        self.sign_count,
                        self.credential_use,
                        self.prf_status,
                        self.encrypted_public_key,
                        self.encrypted_user_key,
                        self.encrypted_private_key,
                        challenge.id,
                        now,
                        self.account_snapshot
                    )?,
                    query!(
                        db,
                        "UPDATE webauthn_challenges SET consumed_at=?1 WHERE \
                         id=?2 AND EXISTS(SELECT 1 FROM webauthn_credentials \
                         WHERE id=?3 AND last_challenge=?2)",
                        now,
                        challenge.id,
                        self.id
                    )?,
                    query!(
                        db,
                        "INSERT INTO \
                         twofactor(uuid,user_uuid,atype,enabled,data,\
                         last_used) SELECT ?1,?2,7,1,'{}',0 WHERE ?3='2fa' \
                         AND EXISTS(SELECT 1 FROM webauthn_credentials WHERE \
                         id=?4 AND last_challenge=?5) ON \
                         CONFLICT(user_uuid,atype) DO UPDATE SET enabled=1",
                        Uuid::new_v4().to_string(),
                        self.user_id,
                        self.credential_use,
                        self.id,
                        challenge.id
                    )?,
                    query!(
                        db,
                        "UPDATE users SET updated_at=?1,totp_recover=CASE \
                         WHEN ?3='2fa' THEN COALESCE(totp_recover,?4) ELSE \
                         totp_recover END WHERE id=?2 AND EXISTS(SELECT 1 \
                         FROM webauthn_credentials WHERE id=?5 AND \
                         last_challenge=?6)",
                        now,
                        self.user_id,
                        self.credential_use,
                        Uuid::new_v4().simple().to_string(),
                        self.id,
                        challenge.id
                    )?,
                ])
                .await
            },
            "Failed to register WebAuthn credential",
        )
        .await?;
        if result[0].meta()?.and_then(|m| m.changes).unwrap_or(0) != 1 {
            return Err(AppError::bad_request(
                "WebAuthn challenge expired or already used",
            ));
        }
        Ok(())
    }
    pub async fn accept_assertion(
        &self,
        db: &D1Database,
        challenge: &ChallengeDB,
        new_count: i64,
    ) -> AppResult<()> {
        let now = now_string();
        let results = db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "UPDATE webauthn_credentials SET \
                         sign_count=MAX(sign_count,?1),last_challenge=?2,\
                         updated_at=?3 WHERE id=?4 AND sign_count=?5 AND \
                         EXISTS(SELECT 1 FROM webauthn_challenges c WHERE \
                         c.id=?2 AND c.consumed_at IS NULL AND \
                         julianday(c.expires_at) > julianday(?3) AND \
                         (c.user_id IS NULL OR (c.user_id=?6 AND \
                         EXISTS(SELECT 1 FROM users u WHERE u.id=?6 AND \
                         u.security_stamp=c.security_stamp  AND u.key IS \
                         json_extract(c.account_snapshot, '$.key') AND \
                         u.user_key_id IS json_extract(c.account_snapshot, \
                         '$.user_key_id') AND u.private_key IS \
                         json_extract(c.account_snapshot, '$.private_key') \
                         AND u.public_key IS json_extract(c.account_snapshot, \
                         '$.public_key') AND u.signed_public_key IS \
                         json_extract(c.account_snapshot, \
                         '$.signed_public_key') AND u.security_state IS \
                         json_extract(c.account_snapshot, '$.security_state') \
                         AND u.security_version IS \
                         json_extract(c.account_snapshot, \
                         '$.security_version') AND u.signature_key_pair IS \
                         json_extract(c.account_snapshot, \
                         '$.signature_key_pair')))) AND (c.session_token IS \
                         NULL OR EXISTS(SELECT 1 FROM devices d WHERE \
                         d.user_id=?6 AND d.identifier=c.device_id AND \
                         d.session_token=c.session_token)))",
                        new_count,
                        challenge.id,
                        now,
                        self.id,
                        self.sign_count,
                        self.user_id
                    )?,
                    query!(
                        db,
                        "UPDATE webauthn_challenges SET consumed_at=?1 WHERE \
                         id=?2 AND consumed_at IS NULL AND EXISTS(SELECT 1 \
                         FROM webauthn_credentials WHERE id=?3 AND \
                         last_challenge=?2)",
                        now,
                        challenge.id,
                        self.id
                    )?,
                ])
                .await
            },
            "Failed to consume WebAuthn assertion",
        )
        .await?;
        if results[0].meta()?.and_then(|m| m.changes).unwrap_or(0) != 1 ||
            results[1].meta()?.and_then(|m| m.changes).unwrap_or(0) != 1
        {
            return Err(AppError::bad_request(
                "WebAuthn challenge expired, used or counter changed",
            ));
        }
        Ok(())
    }
    pub async fn update_keys(&self, db: &D1Database) -> AppResult<()> {
        let changed = db::run_query(
            async {
                query!(
                    db,
                    "UPDATE webauthn_credentials SET \
                     name=?1,prf_status=?2,encrypted_public_key=?3,\
                     encrypted_user_key=?4,encrypted_private_key=?5,\
                     updated_at=?6,account_snapshot=?9 WHERE id=?7 AND \
                     user_id=?8 AND EXISTS(SELECT 1 FROM users u WHERE \
                     u.id=?8 AND u.key IS json_extract(?9, '$.key') AND \
                     u.user_key_id IS json_extract(?9, '$.user_key_id') AND \
                     u.private_key IS json_extract(?9, '$.private_key') AND \
                     u.public_key IS json_extract(?9, '$.public_key') AND \
                     u.signed_public_key IS json_extract(?9, \
                     '$.signed_public_key') AND u.security_state IS \
                     json_extract(?9, '$.security_state') AND \
                     u.security_version IS json_extract(?9, \
                     '$.security_version') AND u.signature_key_pair IS \
                     json_extract(?9, '$.signature_key_pair')) RETURNING id",
                    self.name,
                    self.prf_status,
                    self.encrypted_public_key,
                    self.encrypted_user_key,
                    self.encrypted_private_key,
                    now_string(),
                    self.id,
                    self.user_id,
                    self.account_snapshot
                )?
                .first::<String>(Some("id"))
                .await
            },
            "Failed to update passkey encryption",
        )
        .await?;
        if changed.is_none() {
            return Err(AppError::conflict(
                "Account encryption changed during PRF update",
            ));
        }
        Ok(())
    }
    pub fn key_rotation_statement(
        db: &D1Database,
        user: &str,
        now: &str,
    ) -> AppResult<D1PreparedStatement> {
        Ok(query!(
            db,
            "UPDATE webauthn_credentials SET \
             encrypted_public_key=NULL,encrypted_user_key=NULL,\
             encrypted_private_key=NULL,prf_status=CASE WHEN prf_status=0 \
             THEN 1 ELSE prf_status END,updated_at=?1 WHERE user_id=?2",
            now,
            user
        )?)
    }
    pub async fn purge_2fa(db: &D1Database, user: &str) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM webauthn_credentials WHERE user_id=?1 AND \
                     credential_use='2fa'",
                    user
                )?
                .run()
                .await
            },
            "Failed to remove WebAuthn second factors",
        )
        .await?;
        Ok(())
    }
    pub async fn delete(&self, db: &D1Database) -> AppResult<()> {
        db::run_query(
            async {
                db.batch(vec![
                    query!(
                        db,
                        "DELETE FROM webauthn_credentials WHERE id=?1 AND \
                         user_id=?2",
                        self.id,
                        self.user_id
                    )?,
                    query!(
                        db,
                        "DELETE FROM twofactor WHERE user_uuid=?1 AND atype=7 \
                         AND NOT EXISTS(SELECT 1 FROM webauthn_credentials \
                         WHERE user_id=?1 AND credential_use='2fa')",
                        self.user_id
                    )?,
                    query!(
                        db,
                        "UPDATE users SET updated_at=?1 WHERE id=?2",
                        now_string(),
                        self.user_id
                    )?,
                ])
                .await
            },
            "Failed to delete WebAuthn credential",
        )
        .await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChallengeDB {
    pub id:               String,
    pub challenge:        String,
    pub purpose:          String,
    pub user_id:          Option<String>,
    pub security_stamp:   Option<String>,
    pub device_id:        Option<String>,
    pub session_token:    Option<String>,
    #[serde(default)]
    pub account_snapshot: Option<String>,
    pub rp_id:            String,
    pub origin:           String,
    pub expires_at:       String,
    pub consumed_at:      Option<String>,
}
impl ChallengeDB {
    pub fn new(
        challenge: String,
        purpose: &str,
        rp: String,
        origin: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            challenge,
            purpose: purpose.into(),
            user_id: None,
            security_stamp: None,
            device_id: None,
            session_token: None,
            account_snapshot: None,
            rp_id: rp,
            origin,
            expires_at: crate::infra::time::format_millis(
                crate::infra::time::now()
                    .checked_add(SignedDuration::from_mins(5))
                    .unwrap_or(Timestamp::MAX),
            ),
            consumed_at: None,
        }
    }
    pub async fn insert(&self, db: &D1Database) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO webauthn_challenges \
                     (id,challenge,purpose,user_id,security_stamp,device_id,\
                     session_token,rp_id,origin,expires_at,account_snapshot) \
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    self.id,
                    self.challenge,
                    self.purpose,
                    self.user_id,
                    self.security_stamp,
                    self.device_id,
                    self.session_token,
                    self.rp_id,
                    self.origin,
                    self.expires_at,
                    self.account_snapshot
                )?
                .run()
                .await
            },
            "Failed to store WebAuthn challenge",
        )
        .await?;
        Ok(())
    }
    pub async fn find_challenge(
        db: &D1Database,
        challenge: &str,
        purpose: &str,
    ) -> AppResult<Self> {
        db::run_query(
            async {
                query!(
                    db,
                    "SELECT * FROM webauthn_challenges WHERE challenge=?1 AND \
                     purpose=?2 AND consumed_at IS NULL AND \
                     julianday(expires_at) > julianday(?3)",
                    challenge,
                    purpose,
                    now_string()
                )?
                .first(None)
                .await
            },
            "Failed to fetch WebAuthn challenge",
        )
        .await?
        .ok_or_else(|| {
            AppError::bad_request("WebAuthn challenge missing or expired")
        })
    }
    pub async fn purge(db: &D1Database) -> AppResult<()> {
        db::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM webauthn_challenges WHERE \
                     julianday(expires_at) <= julianday(?1)",
                    now_string()
                )?
                .run()
                .await
            },
            "Failed to purge WebAuthn challenges",
        )
        .await?;
        Ok(())
    }
}
