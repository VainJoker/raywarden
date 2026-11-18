use base64::{
    Engine as _,
    engine::general_purpose::URL_SAFE_NO_PAD,
};
use serde::Deserialize;
use worker::Env;

use crate::{
    errors::{
        AppError,
        AppResult,
    },
    infra::db,
};

#[derive(Clone, Deserialize)]
pub struct JwtKeys {
    pub access_secret:  String,
    pub refresh_secret: String,
}

impl JwtKeys {
    fn validate(self) -> AppResult<Self> {
        if self.access_secret.trim().is_empty() ||
            self.refresh_secret.trim().is_empty()
        {
            return Err(AppError::bad_request("Stored JWT keys are empty"));
        }
        Ok(self)
    }
}

fn random_secret() -> AppResult<String> {
    let mut bytes = [0; 64];
    getrandom::fill(&mut bytes).map_err(|error| {
        log::error!("JWT key generation failed: {error}");
        AppError::Internal
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn initial_keys(
    access: Option<String>,
    refresh: Option<String>,
) -> AppResult<JwtKeys> {
    match (access, refresh) {
        (None, None) => Ok(JwtKeys {
            access_secret:  random_secret()?,
            refresh_secret: random_secret()?,
        }),
        (Some(access_secret), Some(refresh_secret))
            if !access_secret.trim().is_empty() &&
                !refresh_secret.trim().is_empty() =>
        {
            // Preserve the original bytes: the access key also wraps API keys.
            Ok(JwtKeys {
                access_secret,
                refresh_secret,
            })
        }
        _ => Err(AppError::bad_request(
            "First JWT initialization requires both legacy JWT secrets or \
             neither",
        )),
    }
}

fn legacy_secret(env: &Env, name: &str) -> AppResult<Option<String>> {
    // Env::secret(...).ok() also hides malformed bindings and property access
    // failures. Only an actually absent binding permits random initialization.
    let value = js_sys::Reflect::get(env, &name.into())
        .map_err(|_| AppError::Internal)?;
    if value.is_undefined() {
        return Ok(None);
    }
    value.as_string().map(Some).ok_or_else(|| {
        AppError::bad_request("Legacy JWT secret bindings must be strings")
    })
}

/// The D1 row is authoritative across Workers and Durable Objects.
/// Read errors are fatal; only an absent row permits first-time initialization.
pub async fn load(env: &Env) -> AppResult<JwtKeys> {
    let db = env.d1("warden-db")?;
    let read = || async {
        db::run_query(
            async {
                db.prepare(
                    "SELECT access_secret, refresh_secret FROM jwt_keys WHERE \
                     id = 'global'",
                )
                .first::<JwtKeys>(None)
                .await
            },
            "Failed to read JWT keys",
        )
        .await
    };
    if let Some(keys) = read().await? {
        return keys.validate();
    }
    let access = legacy_secret(env, "JWT_SECRET")?;
    let refresh = legacy_secret(env, "JWT_REFRESH_SECRET")?;
    let importing_legacy = access.is_some() && refresh.is_some();
    let keys = initial_keys(access, refresh)?;
    db::run_query(
        async {
            db.prepare(
                "INSERT OR IGNORE INTO jwt_keys (id, access_secret, \
                 refresh_secret) SELECT 'global', ?1, ?2 WHERE ?3 = 1 OR (NOT \
                 EXISTS (SELECT 1 FROM users) AND NOT EXISTS (SELECT 1 FROM \
                 user_api_keys))",
            )
            .bind(&[
                keys.access_secret.into(),
                keys.refresh_secret.into(),
                i32::from(importing_legacy).into(),
            ])?
            .run()
            .await
            .map(|_| ())
        },
        "Failed to initialize JWT keys",
    )
    .await?;
    // A concurrent initializer may have won; never use an unpersisted
    // candidate.
    read()
        .await?
        .ok_or_else(|| {
            // Generating replacement keys here would invalidate persisted API
            // key ciphertext as well as tokens after a partial database
            // restore.
            log::error!(
                "JWT keys are missing from a populated database; restore the \
                 key row or import both original legacy secrets"
            );
            AppError::Internal
        })?
        .validate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_legacy_keys_generate_two_independent_secrets() {
        let keys = initial_keys(None, None).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&keys.access_secret).unwrap().len(),
            64
        );
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&keys.refresh_secret).unwrap().len(),
            64
        );
        assert_ne!(keys.access_secret, keys.refresh_secret);
    }

    #[test]
    fn legacy_bootstrap_preserves_exact_bytes_and_rejects_partial_configuration()
     {
        let keys =
            initial_keys(Some(" access ".into()), Some(" refresh ".into()))
                .unwrap();
        assert_eq!(keys.access_secret, " access ");
        assert_eq!(keys.refresh_secret, " refresh ");
        for pair in [
            (Some("one".into()), None),
            (None, Some("two".into())),
            (Some("".into()), Some("two".into())),
            (Some("one".into()), Some(" ".into())),
        ] {
            assert!(initial_keys(pair.0, pair.1).is_err());
        }
        assert!(
            JwtKeys {
                access_secret:  " ".into(),
                refresh_secret: "valid".into(),
            }
            .validate()
            .is_err()
        );
    }
}
