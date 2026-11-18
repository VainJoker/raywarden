use worker::{
    Env,
    HttpRequest,
};

use crate::{
    api::service::{
        claims::Claims,
        notifications::{
            self,
            UpdateType,
        },
    },
    infra::{
        config::Config,
        jwt::{
            ValidationOptions,
            decode,
        },
    },
};

pub struct Mutation {
    claims: Claims,
    logout: bool,
}

// File handlers publish only after object storage and D1 have both committed.
// Their request can carry an optional bearer that is unrelated to a capability
// token, so the generic response hook must not publish a second event.
pub(crate) fn is_file_upload(method: &str, path: &str) -> bool {
    let path = if path.starts_with("/ciphers/") || path.starts_with("/sends/") {
        format!("/api{path}")
    } else {
        path.to_owned()
    };
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    match parts.as_slice() {
        ["api", "ciphers", _, "attachment"] => method == "POST",
        ["api", "ciphers", _, "attachment", id] => {
            method == "POST" && *id != "v2"
        }
        ["api", "ciphers", _, "attachment", _, "azure-upload"] => {
            method == "PUT"
        }
        ["api", "sends", "file"] | ["api", "sends", _, "file", _] => {
            method == "POST"
        }
        ["api", "sends", _, "file", _, "azure-upload"] => {
            matches!(method, "POST" | "PUT")
        }
        _ => false,
    }
}

impl Mutation {
    pub fn from_request(
        request: &HttpRequest,
        config: &Config,
    ) -> Option<Self> {
        if !matches!(request.method().as_str(), "POST" | "PUT" | "DELETE") {
            return None;
        }
        let path = request.uri().path();
        if matches!(
            path,
            "/api/accounts/key-management/rotate-user-account-keys" |
                "/api/accounts/key-management/rotate-user-keys"
        ) {
            return None;
        }
        if path.starts_with("/api/sends") ||
            path.starts_with("/sends/") ||
            path.starts_with("/api/ciphers") ||
            path.starts_with("/ciphers/") ||
            path.starts_with("/api/folders")
        {
            return None;
        }
        if is_file_upload(request.method().as_str(), path) {
            return None;
        }
        // Anonymous Send endpoints do not authenticate an optional bearer as
        // the Send owner. Their access must not notify that bearer's subject.
        if path.starts_with("/api/sends/access") ||
            path.contains("/access/file/")
        {
            return None;
        }
        let logout = matches!(
            path,
            "/api/accounts/security-stamp" |
                "/api/accounts/password" |
                "/api/accounts/kdf" |
                "/api/accounts/email" |
                "/api/accounts/key-management/rotate-user-account-keys"
        );
        if !logout &&
            !(path.starts_with("/api/accounts/profile") ||
                path.starts_with("/api/accounts/avatar") ||
                path == "/api/settings/domains")
        {
            return None;
        }
        let bearer = request
            .headers()
            .get("authorization")?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")?;
        let claims = decode::<Claims>(
            bearer,
            config.jwt_secret.as_bytes(),
            &ValidationOptions::default(),
        )
        .ok()?
        .claims;
        claims.validate_purpose("access").ok()?;
        Some(Self { claims, logout })
    }

    pub async fn publish(self, env: &Env) {
        let now = crate::infra::time::now_rfc3339();
        notifications::publish_user_update(
            env,
            &self.claims.sub,
            if self.logout {
                UpdateType::LogOut
            } else {
                UpdateType::SyncVault
            },
            &now,
            self.claims.device(),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::is_file_upload;

    #[test]
    fn file_commits_own_their_notification_but_metadata_and_deletes_do_not() {
        for (method, path) in [
            ("POST", "/api/ciphers/cipher/attachment"),
            ("POST", "/api/ciphers/cipher/attachment/file"),
            ("PUT", "/api/ciphers/cipher/attachment/file/azure-upload"),
            ("POST", "/api/sends/file"),
            ("POST", "/api/sends/send/file/file"),
            ("PUT", "/api/sends/send/file/file/azure-upload"),
            ("POST", "/api/sends/send/file/file/azure-upload"),
        ] {
            assert!(is_file_upload(method, path), "{method} {path}");
        }
        for (method, path) in [
            ("POST", "/api/ciphers/cipher/attachment/v2"),
            ("POST", "/api/sends/file/v2"),
            ("DELETE", "/api/ciphers/cipher/attachment/file"),
            ("POST", "/api/ciphers/cipher/attachment/file/delete"),
            ("DELETE", "/api/sends/send"),
        ] {
            assert!(!is_file_upload(method, path), "{method} {path}");
        }
    }
}
