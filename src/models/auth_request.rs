use jiff::{
    SignedDuration,
    Timestamp,
};
use serde::Deserialize;
use serde_json::{
    Value,
    json,
};
use uuid::Uuid;
use worker::{
    D1Database,
    query,
};

use crate::{
    errors::AppError,
    infra::{
        crypto::ct_eq,
        db,
    },
};

pub const AUTH_REQUEST_TTL_SECONDS: i64 = 300;

pub fn now_string() -> String {
    crate::infra::time::now_rfc3339()
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthRequestDB {
    pub id: String,
    pub user_id: String,
    pub request_device_identifier: String,
    pub device_type: i32,
    pub request_ip: String,
    pub access_code: String,
    pub public_key: String,
    pub security_stamp: String,
    #[serde(default)]
    pub account_snapshot: Option<String>,
    pub enc_key: Option<String>,
    pub master_password_hash: Option<String>,
    pub approved: Option<i32>,
    pub creation_date: String,
    pub expires_at: String,
    pub response_date: Option<String>,
    pub authentication_date: Option<String>,
    pub response_device_id: Option<String>,
}

impl AuthRequestDB {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_id: String,
        identifier: String,
        device_type: i32,
        request_ip: String,
        access_code: String,
        public_key: String,
        stamp: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            request_device_identifier: identifier,
            device_type,
            request_ip,
            access_code,
            public_key,
            security_stamp: stamp,
            account_snapshot: None,
            enc_key: None,
            master_password_hash: None,
            approved: None,
            creation_date: now_string(),
            expires_at: crate::infra::time::format_millis(
                crate::infra::time::now()
                    .checked_add(SignedDuration::from_secs(
                        AUTH_REQUEST_TTL_SECONDS,
                    ))
                    .unwrap_or(Timestamp::MAX),
            ),
            response_date: None,
            authentication_date: None,
            response_device_id: None,
        }
    }

    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        crate::infra::time::parse(&self.expires_at)
            .map_or(true, |expires| now >= expires)
    }

    pub fn is_active(&self) -> bool {
        !self.is_expired_at(crate::infra::time::now()) &&
            self.authentication_date.is_none()
    }

    pub fn matches_login(
        &self,
        user_id: &str,
        identifier: &str,
        device_type: i32,
        ip: &str,
        access_code: &str,
        stamp: &str,
    ) -> bool {
        self.is_active() &&
            self.approved == Some(1) &&
            self.user_id == user_id &&
            self.request_device_identifier == identifier &&
            self.device_type == device_type &&
            self.request_ip == ip &&
            ct_eq(&self.access_code, access_code) &&
            ct_eq(&self.security_stamp, stamp)
    }

    pub async fn generation_valid(
        &self,
        db: &D1Database,
    ) -> Result<bool, AppError> {
        let current = crate::models::account_keys::AccountSnapshot::load(
            db,
            &self.user_id,
        )
        .await?
        .to_json()?;
        Ok(self.account_snapshot.as_deref() == Some(current.as_str()))
    }

    pub fn to_json(&self, origin: &str) -> Value {
        json!({
            "id": self.id, "publicKey": self.public_key,
            "requestDeviceType": device_type_name(self.device_type),
            "requestIpAddress": self.request_ip, "key": self.enc_key,
            "masterPasswordHash": self.master_password_hash,
            "creationDate": self.creation_date, "responseDate": self.response_date,
            "requestApproved": self.approved == Some(1), "origin": origin,
            "object": "auth-request"
        })
    }

    pub async fn insert(&self, db: &D1Database) -> Result<(), AppError> {
        db::run_query(
            async {
                query!(
                    db,
                    "INSERT INTO auth_requests (id, user_id, \
                     request_device_identifier, device_type, request_ip, \
                     access_code, public_key, security_stamp, creation_date, \
                     expires_at, account_snapshot) VALUES (?1, ?2, ?3, ?4, \
                     ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    self.id,
                    self.user_id,
                    self.request_device_identifier,
                    self.device_type,
                    self.request_ip,
                    self.access_code,
                    self.public_key,
                    self.security_stamp,
                    self.creation_date,
                    self.expires_at,
                    self.account_snapshot
                )?
                .run()
                .await
            },
            "Failed to create authentication request",
        )
        .await?;
        Ok(())
    }

    pub async fn find_by_id(
        db: &D1Database,
        id: &str,
    ) -> Result<Option<Self>, AppError> {
        db::run_query(
            async {
                query!(db, "SELECT * FROM auth_requests WHERE id = ?1", id)?
                    .first(None)
                    .await
            },
            "Failed to fetch authentication request",
        )
        .await
    }

    pub async fn list_pending_for_user(
        db: &D1Database,
        user_id: &str,
    ) -> Result<Vec<Self>, AppError> {
        let now = now_string();
        let rows = db::run_query(
            async {
                query!(
                    db,
                    "SELECT a.* FROM auth_requests a JOIN users u ON u.id = \
                     a.user_id WHERE a.user_id = ?1 AND a.approved IS NULL \
                     AND a.authentication_date IS NULL AND \
                     julianday(a.expires_at) > julianday(?2) AND \
                     a.security_stamp = u.security_stamp AND u.key IS \
                     json_extract(a.account_snapshot, '$.key') AND \
                     u.user_key_id IS json_extract(a.account_snapshot, \
                     '$.user_key_id') AND u.private_key IS \
                     json_extract(a.account_snapshot, '$.private_key') AND \
                     u.public_key IS json_extract(a.account_snapshot, \
                     '$.public_key') AND u.signed_public_key IS \
                     json_extract(a.account_snapshot, '$.signed_public_key') \
                     AND u.security_state IS json_extract(a.account_snapshot, \
                     '$.security_state') AND u.security_version IS \
                     json_extract(a.account_snapshot, '$.security_version') \
                     AND u.signature_key_pair IS \
                     json_extract(a.account_snapshot, '$.signature_key_pair') \
                     ORDER BY a.creation_date DESC",
                    user_id,
                    now
                )?
                .all()
                .await
            },
            "Failed to list authentication requests",
        )
        .await?;
        Ok(rows.results()?)
    }

    pub async fn respond(
        &self,
        db: &D1Database,
        device_id: &str,
        approved: bool,
        key: &str,
        hash: Option<&str>,
    ) -> Result<Self, AppError> {
        let now = now_string();
        let row: Option<Self> = db::run_query(
            async {
                query!(
                    db,
                    "UPDATE auth_requests SET approved = ?1, enc_key = ?2, \
                     master_password_hash = ?3, response_date = ?4, \
                     response_device_id = ?5 WHERE id = ?6 AND user_id = ?7 \
                     AND approved IS NULL AND authentication_date IS NULL AND \
                     julianday(expires_at) > julianday(?4) AND security_stamp \
                     = (SELECT security_stamp FROM users WHERE id = ?7) AND \
                     EXISTS(SELECT 1 FROM users u WHERE \
                     u.id=auth_requests.user_id AND u.key IS \
                     json_extract(auth_requests.account_snapshot, '$.key') \
                     AND u.user_key_id IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.user_key_id') AND u.private_key IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.private_key') AND u.public_key IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.public_key') AND u.signed_public_key IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.signed_public_key') AND u.security_state IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.security_state') AND u.security_version IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.security_version') AND u.signature_key_pair IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.signature_key_pair')) RETURNING *",
                    i32::from(approved),
                    if approved { Some(key) } else { None },
                    if approved { hash } else { None },
                    now,
                    device_id,
                    self.id,
                    self.user_id
                )?
                .first(None)
                .await
            },
            "Failed to respond to authentication request",
        )
        .await?;
        row.ok_or_else(|| {
            AppError::bad_request(
                "Authentication request expired or already answered",
            )
        })
    }

    /// The conditional write prevents concurrent token exchanges from reusing
    /// approval.
    pub async fn consume(&self, db: &D1Database) -> Result<(), AppError> {
        let now = now_string();
        let id: Option<String> = db::run_query(
            async {
                query!(
                    db,
                    "UPDATE auth_requests SET authentication_date = ?1 WHERE \
                     id = ?2 AND approved = 1 AND authentication_date IS NULL \
                     AND julianday(expires_at) > julianday(?1) AND \
                     security_stamp = (SELECT security_stamp FROM users WHERE \
                     id = auth_requests.user_id) AND EXISTS(SELECT 1 FROM \
                     users u WHERE u.id=auth_requests.user_id AND u.key IS \
                     json_extract(auth_requests.account_snapshot, '$.key') \
                     AND u.user_key_id IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.user_key_id') AND u.private_key IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.private_key') AND u.public_key IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.public_key') AND u.signed_public_key IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.signed_public_key') AND u.security_state IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.security_state') AND u.security_version IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.security_version') AND u.signature_key_pair IS \
                     json_extract(auth_requests.account_snapshot, \
                     '$.signature_key_pair')) RETURNING id",
                    now,
                    self.id
                )?
                .first(Some("id"))
                .await
            },
            "Failed to consume authentication request",
        )
        .await?;
        if id.is_none() {
            return Err(AppError::bad_request(
                "Authentication request expired or already used",
            ));
        }
        Ok(())
    }
    pub async fn purge_expired(db: &D1Database) -> Result<u32, AppError> {
        let now = now_string();
        let result = db::run_query(
            async {
                query!(
                    db,
                    "DELETE FROM auth_requests WHERE julianday(expires_at) <= \
                     julianday(?1)",
                    now
                )?
                .run()
                .await
            },
            "Failed to purge expired authentication requests",
        )
        .await?;
        Ok(result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) as u32)
    }
}

fn device_type_name(device_type: i32) -> &'static str {
    match device_type {
        0 => "Android",
        1 => "iOS",
        2 => "Chrome Extension",
        3 => "Firefox Extension",
        4 => "Opera Extension",
        5 => "Edge Extension",
        6 => "Windows Desktop",
        7 => "macOS Desktop",
        8 => "Linux Desktop",
        9 => "Chrome",
        10 => "Firefox",
        11 => "Opera",
        12 => "Edge",
        13 => "Internet Explorer",
        14 => "Unknown Browser",
        15 => "Android Amazon",
        16 => "UWP",
        17 => "Safari",
        18 => "Vivaldi",
        19 => "Vivaldi Extension",
        20 => "Safari Extension",
        21 => "SDK",
        _ => "Unknown Device",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_is_bound_to_user_device_code_stamp_and_expiry() {
        let mut request = AuthRequestDB::new(
            "user".into(),
            "device".into(),
            2,
            "ip".into(),
            "code".into(),
            "pk".into(),
            "stamp".into(),
        );
        assert!(
            !request.matches_login("user", "device", 2, "ip", "code", "stamp")
        );
        request.approved = Some(1);
        assert!(
            request.matches_login("user", "device", 2, "ip", "code", "stamp")
        );
        for (user, device, kind, ip, code, stamp) in [
            ("other", "device", 2, "ip", "code", "stamp"),
            ("user", "other", 2, "ip", "code", "stamp"),
            ("user", "device", 1, "ip", "code", "stamp"),
            ("user", "device", 2, "other", "code", "stamp"),
            ("user", "device", 2, "ip", "wrong", "stamp"),
            ("user", "device", 2, "ip", "code", "old"),
        ] {
            assert!(
                !request.matches_login(user, device, kind, ip, code, stamp)
            );
        }
        request.authentication_date = Some(now_string());
        assert!(
            !request.matches_login("user", "device", 2, "ip", "code", "stamp")
        );
        request.authentication_date = None;
        assert!(
            request.is_expired_at(
                crate::infra::time::now()
                    .checked_add(SignedDuration::from_secs(301))
                    .expect("test clock supports five-minute TTL")
            )
        );
        request.expires_at = "invalid".into();
        assert!(!request.is_active());
    }
}
