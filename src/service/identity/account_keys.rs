//! Account envelope changes commit with the exact vault generation they read.
use crate::service::{
    identity::user::{
        AccountKeyPairRequest,
        KdfParams,
    },
    vault::cipher::CipherPayload,
};
mod requests;
use std::collections::HashSet;

pub(crate) use requests::RotateAccountKeysRequest;
use requests::RotateAccountPayload;
pub use requests::{
    AccountKeysRequest,
    ValidatedAccountKeys,
    account_keys_response,
    is_valid_key_id,
};
use serde_json::Value;
use uuid::Uuid;
use worker::{
    D1Database,
    D1PreparedStatement,
};

use crate::{
    app::AppContext,
    errors::{
        AppError,
        AppResult,
    },
    models::identity::{
        account_keys::{
            AccountSnapshot,
            rotation,
            rotation::CollectionSnapshot,
        },
        user::{
            StoredPassword,
            UserRow,
        },
    },
    service::{
        identity::session::Claims,
        notifications,
        notifications::{
            UpdateType,
            admin as admin_notify,
            admin::Event,
        },
        send,
    },
};

pub struct RotationPassword {
    pub password: StoredPassword,
    pub kdf:      KdfParams,
    pub hint:     Option<String>,
}

impl RotationPassword {
    fn apply_to(self, user: &mut UserRow) {
        user.master_password_hash = self.password.hash;
        user.password_salt = Some(self.password.salt);
        user.password_iterations = self.password.iterations;
        user.kdf_type = self.kdf.kdf_type;
        user.kdf_iterations = self.kdf.iterations;
        user.kdf_memory = self.kdf.memory;
        user.kdf_parallelism = self.kdf.parallelism;
        user.master_password_hint = self.hint;
    }
}

pub(super) struct CredentialChange<'a> {
    pub password: &'a StoredPassword,
    pub key:      &'a str,
    pub kdf:      KdfParams,
    pub hint:     Option<&'a str>,
    pub keys:     Option<&'a AccountKeyPairRequest>,
}

pub struct RotationInput {
    pub keys:             ValidatedAccountKeys,
    pub data:             RotateAccountPayload,
    pub wrapped_user_key: String,
    pub old_user_key_id:  Option<String>,
    pub new_user_key_id:  Option<String>,
    pub upgrade:          Option<Value>,
    pub passkeys:         Vec<Value>,
    pub password:         Option<RotationPassword>,
}

impl RotationInput {
    pub async fn apply(
        self,
        state: &AppContext,
        claims: &Claims,
        user: &UserRow,
    ) -> AppResult<()> {
        let db = state.database();
        let changes_password = self.password.is_some();
        self.validate_account(user)?;
        let is_upgrade = self.password.is_none() &&
            self.upgrade.is_some() &&
            !crate::service::identity::user::is_v2(user);
        let sources = RotationSources::load(db, &claims.sub).await?;
        sources.validate(&self)?;

        let mut batch = RotationBatch::new(db, &claims.sub);
        let (send_writes, send_guards) = send::rotation_statements(
            db,
            &claims.sub,
            &self.data.sends,
            &batch.now,
            &batch.token,
        )
        .await?;
        let final_stamp = if is_upgrade {
            user.security_stamp.clone()
        } else {
            Uuid::new_v4().to_string()
        };
        let upgrade = if is_upgrade {
            self.upgrade.map(|v| v.to_string())
        } else {
            None
        };
        let keys = self.keys.into_persistence_material()?;
        let mut next = UserRow {
            key: self.wrapped_user_key,
            private_key: keys.private_key,
            public_key: keys.public_key,
            signed_public_key: keys.signed_public_key,
            security_state: keys.security_state,
            security_version: keys.security_version,
            signature_key_pair: keys.signature_key_pair,
            user_key_id: self.new_user_key_id,
            v2_upgrade_token: upgrade,
            security_stamp: final_stamp,
            ..user.clone()
        };
        if let Some(password) = self.password {
            password.apply_to(&mut next);
        }
        let new_snapshot = AccountSnapshot::from_user(&next).to_json()?;
        batch.writes.push(rotation::claim_rotation(
            db,
            user,
            &claims.session_snapshot()?,
            &next,
            &batch.token,
            &batch.now,
        )?);
        batch.writes.extend(sources.guards()?);
        batch.writes.extend(send_guards);
        batch.writes.extend(send_writes);
        batch.write_vault_items(&self.data)?;
        batch.write_passkeys(&self.passkeys, &new_snapshot)?;
        let now = batch.commit().await?;
        if changes_password {
            notifications::publish_user_update(
                &state.env,
                &claims.sub,
                UpdateType::LogOut,
                &now,
                claims.device(),
            )
            .await;
        } else {
            notifications::publish_key_rotation(
                &state.env,
                &claims.sub,
                &now,
                claims.device(),
            )
            .await;
        }
        admin_notify::emit(
            &state.env,
            if changes_password {
                Event::PasswordChange
            } else {
                Event::AccountSecurityChanged
            },
            &user.id,
        )
        .await;
        Ok(())
    }

    fn validate_account(&self, user: &UserRow) -> AppResult<()> {
        self.keys.validate_rotation(user)?;
        if let Some(id) = &self.new_user_key_id &&
            (self.keys.is_v2() || self.new_user_key_id != user.user_key_id) &&
            !is_valid_key_id(id)
        {
            return Err(AppError::bad_request(
                "Key id must be 32 lowercase hex characters",
            ));
        }
        if self.old_user_key_id != user.user_key_id {
            return Err(AppError::conflict(
                "The current user key changed. Sync and retry.",
            ));
        }
        if self.wrapped_user_key.trim().is_empty() {
            return Err(AppError::bad_request("Wrapped user key is required"));
        }
        if let Some(upgrade) = &self.upgrade &&
            ["wrappedUserKey1", "wrappedUserKey2"].iter().any(|field| {
                upgrade[*field].as_str().is_none_or(|s| s.trim().is_empty())
            })
        {
            return Err(AppError::bad_request(
                "Both V2 upgrade wrapped user keys are required",
            ));
        }
        Ok(())
    }
}

/// The same captured rows define which items must be rewrapped and guard the
/// transaction against concurrent changes.
struct RotationSources<'a> {
    db:          &'a D1Database,
    owner:       &'a str,
    ciphers:     CollectionSnapshot,
    folders:     CollectionSnapshot,
    attachments: CollectionSnapshot,
    passkeys:    CollectionSnapshot,
}

impl<'a> RotationSources<'a> {
    async fn load(db: &'a D1Database, owner: &'a str) -> AppResult<Self> {
        Ok(Self {
            db,
            owner,
            ciphers: CollectionSnapshot::ciphers(db, owner).await?,
            folders: CollectionSnapshot::folders(db, owner).await?,
            attachments: CollectionSnapshot::attachments(db, owner).await?,
            passkeys: CollectionSnapshot::passkeys(db, owner).await?,
        })
    }

    fn validate(&self, input: &RotationInput) -> AppResult<()> {
        let cipher_ids = input
            .data
            .ciphers
            .iter()
            .filter_map(|c| c.id.clone())
            .collect::<HashSet<_>>();
        let folder_ids = input
            .data
            .folders
            .iter()
            .filter_map(|f| f.id.clone())
            .collect::<HashSet<_>>();
        if cipher_ids.len() != input.data.ciphers.len() ||
            cipher_ids != self.ciphers.ids() ||
            folder_ids.len() !=
                input
                    .data
                    .folders
                    .iter()
                    .filter(|f| f.id.is_some())
                    .count() ||
            folder_ids != self.folders.ids()
        {
            return Err(AppError::conflict(
                "Every existing cipher and folder must occur exactly once in \
                 key rotation",
            ));
        }
        for cipher in &input.data.ciphers {
            cipher.validate_for_personal_vault(self.owner)?;
            cipher.validate_encryption_context(
                self.owner,
                input.new_user_key_id.as_deref(),
            )?;
        }
        let attachment_rows = self.attachments.rows();
        for cipher in &input.data.ciphers {
            if let Some(files) = &cipher.attachment_key_updates {
                for id in files.keys() {
                    if !attachment_rows.iter().any(|row| {
                        row["id"].as_str() == Some(id.as_str()) &&
                            row["cipher_id"].as_str() == cipher.id.as_deref()
                    }) {
                        return Err(AppError::bad_request(
                            "Rotated attachment does not belong to the cipher",
                        ));
                    }
                }
            }
        }
        let expected_attachments = self.attachments.ids();
        let provided_attachments = input
            .data
            .ciphers
            .iter()
            .flat_map(|c| {
                c.attachment_key_updates
                    .iter()
                    .flat_map(|a| a.keys().cloned())
            })
            .collect::<Vec<_>>();
        if provided_attachments.len() != expected_attachments.len() ||
            provided_attachments.into_iter().collect::<HashSet<_>>() !=
                expected_attachments
        {
            return Err(AppError::conflict(
                "Every existing attachment must be rewrapped during rotation",
            ));
        }
        let expected_passkeys = self
            .passkeys
            .rows()
            .iter()
            .filter(|row| {
                row["credential_use"] == "login" &&
                    row["encrypted_user_key"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty()) &&
                    row["encrypted_private_key"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
            })
            .map(|row| row["slot"].to_string())
            .collect::<HashSet<_>>();
        let provided_passkeys = input
            .passkeys
            .iter()
            .filter_map(|row| row["id"].as_str().map(str::to_string))
            .collect::<HashSet<_>>();
        if provided_passkeys.len() != input.passkeys.len() ||
            provided_passkeys != expected_passkeys
        {
            return Err(AppError::conflict(
                "Every enabled passkey must be rewrapped during rotation",
            ));
        }
        Ok(())
    }

    fn guards(&self) -> AppResult<Vec<D1PreparedStatement>> {
        let mut guards = Vec::new();
        for source in [
            &self.ciphers,
            &self.folders,
            &self.attachments,
            &self.passkeys,
        ] {
            guards.extend(source.guards(self.db, self.owner)?);
        }
        Ok(guards)
    }
}

struct RotationBatch<'a> {
    db:     &'a D1Database,
    owner:  &'a str,
    now:    String,
    token:  String,
    writes: Vec<D1PreparedStatement>,
}

impl<'a> RotationBatch<'a> {
    fn new(db: &'a D1Database, owner: &'a str) -> Self {
        Self {
            db,
            owner,
            now: crate::utils::time::now_rfc3339(),
            token: Uuid::new_v4().to_string(),
            writes: Vec::new(),
        }
    }

    fn write_vault_items(
        &mut self,
        data: &RotateAccountPayload,
    ) -> AppResult<()> {
        for cipher in &data.ciphers {
            let id = cipher.id.as_deref().ok_or(AppError::Internal)?;
            let data =
                serde_json::to_string(&CipherPayload::from_request(cipher))
                    .map_err(AppError::internal_error)?;
            self.writes.push(rotation::cipher_write(
                self.db,
                self.owner,
                id,
                &data,
                &self.now,
                &self.token,
            )?);
            if let Some(attachments) = &cipher.attachment_key_updates {
                for (attachment_id, attachment) in attachments {
                    if attachment.key.trim().is_empty() ||
                        attachment.file_name.trim().is_empty()
                    {
                        return Err(AppError::bad_request(
                            "Rotated attachment keys and names are required",
                        ));
                    }
                    self.writes.push(rotation::attachment_write(
                        self.db,
                        self.owner,
                        id,
                        attachment_id,
                        &attachment.file_name,
                        &attachment.key,
                        &self.now,
                        &self.token,
                    )?);
                }
            }
        }
        for folder in &data.folders {
            if let Some(id) = &folder.id {
                self.writes.push(rotation::folder_write(
                    self.db,
                    self.owner,
                    id,
                    &folder.name,
                    &self.now,
                    &self.token,
                )?);
            }
        }
        Ok(())
    }

    fn write_passkeys(
        &mut self,
        passkeys: &[Value],
        new_snapshot: &str,
    ) -> AppResult<()> {
        for passkey in passkeys {
            let id = passkey["id"].as_str().ok_or(AppError::Internal)?;
            let public = passkey["encryptedPublicKey"]
                .as_str()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| {
                    AppError::bad_request(
                        "Passkey encryptedPublicKey is required",
                    )
                })?;
            let key = passkey["encryptedUserKey"]
                .as_str()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| {
                    AppError::bad_request(
                        "Passkey encryptedUserKey is required",
                    )
                })?;
            self.writes.push(rotation::passkey_write(
                self.db,
                self.owner,
                id,
                public,
                key,
                new_snapshot,
                &self.now,
                &self.token,
            )?);
        }
        Ok(())
    }

    async fn commit(self) -> AppResult<String> {
        rotation::commit(self.db, self.owner, &self.token, self.writes).await?;
        Ok(self.now)
    }
}

pub(super) async fn change_credentials(
    state: &AppContext,
    claims: &Claims,
    user: &UserRow,
    change: CredentialChange<'_>,
) -> AppResult<()> {
    if change.password.hash.trim().is_empty() || change.key.trim().is_empty() {
        return Err(AppError::bad_request(
            "Password hash and wrapped key must not be empty",
        ));
    }
    if let Some(keys) = change.keys {
        keys.validate_password_rewrap(user)?;
    }
    let private_key = change.keys.map_or(user.private_key.as_str(), |keys| {
        keys.encrypted_private_key.as_str()
    });
    let public_key = change
        .keys
        .map_or(user.public_key.as_str(), |keys| keys.public_key.as_str());
    let token = Uuid::new_v4().to_string();
    let now = crate::utils::time::now_rfc3339();
    let next = UserRow {
        master_password_hash: change.password.hash.clone(),
        password_salt: Some(change.password.salt.clone()),
        password_iterations: change.password.iterations,
        key: change.key.to_string(),
        private_key: private_key.to_string(),
        public_key: public_key.to_string(),
        kdf_type: change.kdf.kdf_type,
        kdf_iterations: change.kdf.iterations,
        kdf_memory: change.kdf.memory,
        kdf_parallelism: change.kdf.parallelism,
        master_password_hint: change.hint.map(str::to_string),
        ..user.clone()
    };
    rotation::change_credentials(
        state.database(),
        user,
        &claims.session_snapshot()?,
        &next,
        &token,
        &now,
    )
    .await
}
