//! Authenticated vault transactions; SQL and row assertions live in models.
use worker::{D1Database, D1PreparedStatement, Env};

use crate::{
    errors::AppResult,
    models::{identity::account_keys::AccountSnapshot, mutation, vault::cipher::CipherRow},
    service::{
        identity::session::{Claims, TokenUse},
        notifications::{self, UpdateType, admin, admin::Event},
    },
};

/// The session and ordered snapshot checks for a single vault write.
pub(crate) struct VaultWrite<'a> {
    db: &'a D1Database,
    env: &'a Env,
    claims: &'a Claims,
    guards: Vec<D1PreparedStatement>,
}

impl<'a> VaultWrite<'a> {
    pub(crate) const fn new(db: &'a D1Database, env: &'a Env, claims: &'a Claims) -> Self {
        Self {
            db,
            env,
            claims,
            guards: Vec::new(),
        }
    }

    pub(crate) const fn database(&self) -> &'a D1Database {
        self.db
    }

    pub(crate) fn user_id(&self) -> &str {
        &self.claims.sub
    }

    pub(crate) async fn guard_account_key(&mut self) -> AppResult<AccountSnapshot> {
        let (account, guard) = account_key_guard(self.database(), self.claims).await?;
        self.guards.push(guard);
        Ok(account)
    }

    pub(crate) fn guard_cipher(&mut self, row: &CipherRow) -> AppResult<()> {
        self.guards
            .push(mutation::cipher_snapshot_guard(self.database(), row)?);
        Ok(())
    }

    pub(crate) fn guard_folder(&mut self, folder_id: Option<&str>) -> AppResult<()> {
        self.guards.push(mutation::folder_guard(
            self.database(),
            self.user_id(),
            folder_id,
        )?);
        Ok(())
    }

    pub(crate) fn add_guard(&mut self, guard: D1PreparedStatement) {
        self.guards.push(guard);
    }

    pub(crate) fn add_guards(&mut self, guards: Vec<D1PreparedStatement>) {
        self.guards.extend(guards);
    }

    pub(crate) async fn commit(
        self,
        writes: Vec<D1PreparedStatement>,
    ) -> AppResult<CommittedVaultWrite<'a>> {
        let revision = commit(self.db, self.claims, self.guards, writes).await?;
        Ok(CommittedVaultWrite {
            env: self.env,
            claims: self.claims,
            revision,
        })
    }
}

/// The committed revision used by vault notifications for this write.
pub(crate) struct CommittedVaultWrite<'a> {
    env: &'a Env,
    claims: &'a Claims,
    revision: String,
}

impl CommittedVaultWrite<'_> {
    pub(crate) async fn publish_cipher(&self, kind: UpdateType, id: &str) {
        notifications::publish_cipher_update(
            self.env,
            &self.claims.sub,
            kind,
            id,
            &self.revision,
            self.claims.device(),
        )
        .await;
    }

    pub(crate) async fn publish_folder(&self, kind: UpdateType, id: &str) {
        notifications::publish_revision_update(
            self.env,
            &self.claims.sub,
            kind,
            id,
            &self.revision,
            self.claims.device(),
        )
        .await;
        self.emit_admin(Event::VaultChanged).await;
    }

    pub(crate) async fn publish_user(&self, kind: UpdateType) {
        notifications::publish_user_update(
            self.env,
            &self.claims.sub,
            kind,
            &self.revision,
            self.claims.device(),
        )
        .await;
    }

    pub(crate) async fn emit_admin(&self, event: Event) {
        admin::emit(self.env, event, &self.claims.sub).await;
    }
}

pub async fn account_key_guard(
    db: &D1Database,
    claims: &Claims,
) -> AppResult<(AccountSnapshot, D1PreparedStatement)> {
    claims.validate_session(db, TokenUse::Access).await?;
    mutation::account_snapshot_guard(db, &claims.sub).await
}

pub async fn commit(
    db: &D1Database,
    claims: &Claims,
    guards: Vec<D1PreparedStatement>,
    writes: Vec<D1PreparedStatement>,
) -> AppResult<String> {
    let snapshot = claims.session_snapshot()?;
    mutation::commit_session(db, &snapshot, guards, writes).await
}
