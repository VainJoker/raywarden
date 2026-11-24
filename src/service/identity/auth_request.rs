//! Authentication-request creation, approval policy and client projections.
use jiff::{SignedDuration, Timestamp};
use serde::Serialize;
use uuid::Uuid;
use worker::D1Database;

use crate::{
    errors::AppResult, models::identity::auth_request::AuthRequestRow, utils::constant_time_eq,
};

pub const AUTH_REQUEST_TTL_SECONDS: i64 = 300;

pub(crate) struct CreateAuthRequest {
    pub user_id: String,
    pub device_id: String,
    pub device_type: i32,
    pub request_ip: String,
    pub access_code: String,
    pub public_key: String,
    pub security_stamp: String,
}

pub(crate) fn new_auth_request(input: CreateAuthRequest) -> AuthRequestRow {
    let CreateAuthRequest {
        user_id,
        device_id,
        device_type,
        request_ip,
        access_code,
        public_key,
        security_stamp,
    } = input;
    AuthRequestRow {
        id: Uuid::new_v4().to_string(),
        user_id,
        request_device_id: device_id,
        device_type,
        request_ip,
        access_code,
        public_key,
        security_stamp,
        account_snapshot: None,
        encrypted_key: None,
        master_password_hash: None,
        approved: None,
        created_at: crate::utils::time::now_rfc3339(),
        expires_at: crate::utils::time::format_millis(
            crate::utils::time::now()
                .checked_add(SignedDuration::from_secs(AUTH_REQUEST_TTL_SECONDS))
                .unwrap_or(Timestamp::MAX),
        ),
        responded_at: None,
        authenticated_at: None,
    }
}

pub fn is_auth_request_expired_at(row: &AuthRequestRow, now: Timestamp) -> bool {
    crate::utils::time::parse(&row.expires_at).map_or(true, |expires| now >= expires)
}

pub fn is_auth_request_active(row: &AuthRequestRow) -> bool {
    !is_auth_request_expired_at(row, crate::utils::time::now()) && row.authenticated_at.is_none()
}

pub(crate) struct LoginApprovalMatch<'a> {
    pub user_id: &'a str,
    pub device_id: &'a str,
    pub device_type: i32,
    pub request_ip: &'a str,
    pub access_code: &'a str,
    pub security_stamp: &'a str,
}

pub(crate) fn auth_request_matches_login(
    row: &AuthRequestRow,
    proof: &LoginApprovalMatch<'_>,
) -> bool {
    let LoginApprovalMatch {
        user_id,
        device_id,
        device_type,
        request_ip,
        access_code,
        security_stamp,
    } = *proof;
    is_auth_request_active(row)
        && row.approved == Some(1)
        && row.user_id == user_id
        && row.request_device_id == device_id
        && row.device_type == device_type
        && row.request_ip == request_ip
        && constant_time_eq(row.access_code.as_bytes(), access_code.as_bytes())
        && constant_time_eq(row.security_stamp.as_bytes(), security_stamp.as_bytes())
}

pub async fn auth_request_generation_matches(
    row: &AuthRequestRow,
    db: &D1Database,
) -> AppResult<bool> {
    let current = crate::models::identity::account_keys::AccountSnapshot::load(db, &row.user_id)
        .await?
        .to_json()?;
    Ok(row.account_snapshot.as_deref() == Some(current.as_str()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthRequestResponse {
    id: String,
    public_key: String,
    request_device_type: &'static str,
    request_ip_address: String,
    key: Option<String>,
    master_password_hash: Option<String>,
    creation_date: String,
    response_date: Option<String>,
    request_approved: bool,
    origin: String,
    object: &'static str,
}

impl AuthRequestResponse {
    pub(crate) fn new(row: AuthRequestRow, origin: &str) -> Self {
        Self {
            id: row.id,
            public_key: row.public_key,
            request_device_type: device_type_name(row.device_type),
            request_ip_address: row.request_ip,
            key: row.encrypted_key,
            master_password_hash: row.master_password_hash,
            creation_date: row.created_at,
            response_date: row.responded_at,
            request_approved: row.approved == Some(1),
            origin: origin.to_owned(),
            object: "auth-request",
        }
    }
}

const fn device_type_name(device_type: i32) -> &'static str {
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
        let mut request = new_auth_request(CreateAuthRequest {
            user_id: "user".into(),
            device_id: "device".into(),
            device_type: 2,
            request_ip: "ip".into(),
            access_code: "code".into(),
            public_key: "pk".into(),
            security_stamp: "stamp".into(),
        });
        let valid = || LoginApprovalMatch {
            user_id: "user",
            device_id: "device",
            device_type: 2,
            request_ip: "ip",
            access_code: "code",
            security_stamp: "stamp",
        };
        assert!(!auth_request_matches_login(&request, &valid()));
        request.approved = Some(1);
        assert!(auth_request_matches_login(&request, &valid()));
        for proof in [
            LoginApprovalMatch {
                user_id: "other",
                ..valid()
            },
            LoginApprovalMatch {
                device_id: "other",
                ..valid()
            },
            LoginApprovalMatch {
                device_type: 1,
                ..valid()
            },
            LoginApprovalMatch {
                request_ip: "other",
                ..valid()
            },
            LoginApprovalMatch {
                access_code: "wrong",
                ..valid()
            },
            LoginApprovalMatch {
                security_stamp: "old",
                ..valid()
            },
        ] {
            assert!(!auth_request_matches_login(&request, &proof));
        }
        request.authenticated_at = Some(crate::utils::time::now_rfc3339());
        assert!(!auth_request_matches_login(&request, &valid()));
        request.authenticated_at = None;
        assert!(
            crate::service::identity::auth_request::is_auth_request_expired_at(
                &request,
                crate::utils::time::now()
                    .checked_add(SignedDuration::from_secs(301))
                    .expect("test clock supports five-minute TTL")
            )
        );
        request.expires_at = "invalid".into();
        assert!(!crate::service::identity::auth_request::is_auth_request_active(&request));
    }
}
