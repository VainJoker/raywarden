//! Send access, mutations, account-key rotation and lifecycle workflows.
pub(crate) mod content;
mod token;
pub(crate) mod turnstile;
pub(crate) mod upload;

use axum::http::HeaderMap;
pub use content::RotateSendRequest;
use serde::Serialize;
pub(crate) use token::{
    SendAccessTokenResponse,
    issue_access_token,
};
use worker::{
    D1Database,
    D1PreparedStatement,
    Env,
};

use self::{
    content::{
        SendAccessResponse,
        SendRequest,
        SendResponse,
        max_text_size_bytes,
        validate_send_dates,
    },
    token::{
        DOWNLOAD_SCOPE,
        TokenPurpose,
        decode_file_token,
        decode_token,
        encode_token,
    },
};
use crate::{
    app::AppContext,
    config::files::{
        send_file_token_expires_at_seconds,
        send_quota_bytes,
    },
    errors::{
        AppError,
        AppResult,
    },
    infra::storage::Storage,
    models::send::{
        SendRow,
        collection_guard,
        snapshot_guard,
    },
    service::{
        identity::session::Claims,
        notifications,
        notifications::{
            admin as admin_notify,
            admin::Event,
        },
        rate_limit,
        vault_write,
    },
};

/// Owner operations use the same authenticated session for reads and commits.
pub(crate) struct SendOwner<'a> {
    state:  &'a AppContext,
    claims: &'a Claims,
}

impl<'a> SendOwner<'a> {
    pub(crate) const fn new(state: &'a AppContext, claims: &'a Claims) -> Self {
        Self { state, claims }
    }

    pub(crate) async fn list(&self) -> AppResult<Vec<SendResponse>> {
        list_send_responses(self.state.database(), &self.claims.sub).await
    }

    pub(crate) async fn get(&self, id: &str) -> AppResult<SendRow> {
        SendRow::fetch_for_user(self.state.database(), id, &self.claims.sub)
            .await
    }

    pub(crate) async fn create_text(
        &self,
        payload: &SendRequest,
    ) -> AppResult<SendRow> {
        if payload.send_type != 0 {
            return Err(AppError::bad_request(
                "Use the file upload endpoint for file Sends",
            ));
        }
        let db = self.state.database();
        let (_, key_guard) =
            vault_write::account_key_guard(db, self.claims).await?;
        let mut send = content::new_send(
            self.claims.sub.clone(),
            payload,
            max_text_size_bytes(&self.state.env),
        )?;
        content::set_password(&mut send, payload.password.as_deref()).await?;
        let revision = self.insert(db, &send, None, key_guard).await?;
        self.notify(
            &send,
            notifications::UpdateType::SyncSendCreate,
            &revision,
        )
        .await;
        Ok(send)
    }

    pub(crate) async fn reserve_file_upload(
        &self,
        payload: &SendRequest,
    ) -> AppResult<upload::SendFileUploadResponse> {
        let env = &self.state.env;
        send_file_token_expires_at_seconds(
            env,
            crate::utils::time::now_seconds(),
        )?;
        let db = self.state.database();
        let (_, key_guard) =
            vault_write::account_key_guard(db, self.claims).await?;
        if !Storage::enabled(env) {
            return Err(AppError::bad_request("File storage is not enabled"));
        }
        if payload.send_type != 1 {
            return Err(AppError::bad_request("Send must contain a file"));
        }
        let size = payload
            .file_size_bytes
            .as_ref()
            .ok_or_else(|| AppError::bad_request("fileLength is required"))?
            .parse_i64()?;
        if size < 0 || size > upload::max_file_size_bytes(env) {
            return Err(AppError::bad_request(
                "Send file size exceeds the configured limit",
            ));
        }
        let mut send = content::new_send(
            self.claims.sub.clone(),
            payload,
            max_text_size_bytes(env),
        )?;
        send.file_id = Some(uuid::Uuid::new_v4().to_string());
        send.file_size_bytes = size;
        send.upload_state = 1;
        content::set_password(&mut send, payload.password.as_deref()).await?;
        self.insert(db, &send, send_quota_bytes(env), key_guard)
            .await?;
        upload::upload_response(self.state, send, self.claims)
    }

    pub(crate) async fn update(
        &self,
        id: &str,
        payload: SendRequest,
    ) -> AppResult<SendRow> {
        payload.validate()?;
        let (deletes_at, expires_at) = validate_send_dates(
            &payload.deletes_at,
            payload.expires_at.as_deref(),
        )?;
        let db = self.state.database();
        let (_, key_guard) =
            vault_write::account_key_guard(db, self.claims).await?;
        let existing =
            SendRow::fetch_for_user(db, id, &self.claims.sub).await?;
        let mut send = existing.clone();
        if payload.send_type != send.send_type {
            return Err(AppError::bad_request("Send type cannot change"));
        }
        if send.send_type == 0 {
            send.data = payload
                .encoded_content(max_text_size_bytes(&self.state.env))?;
        }
        send.max_access_count = payload.max_count()?;
        send.name = payload.name;
        send.notes = payload.notes;
        send.encrypted_key = payload.encrypted_key;
        send.expires_at = expires_at;
        send.deletes_at = deletes_at;
        send.is_disabled = i32::from(payload.is_disabled.unwrap_or(false));
        send.is_email_hidden =
            i32::from(payload.is_email_hidden.unwrap_or(false));
        send.updated_at = crate::utils::time::now_rfc3339();
        send.access_stamp = uuid::Uuid::new_v4().to_string();
        if let Some(password) = payload.password.as_deref() {
            content::set_password(&mut send, Some(password)).await?;
        }
        self.save_update(db, &existing, &send, vec![key_guard])
            .await?;
        Ok(send)
    }

    pub(crate) async fn remove_password(&self, id: &str) -> AppResult<SendRow> {
        let db = self.state.database();
        let existing =
            SendRow::fetch_for_user(db, id, &self.claims.sub).await?;
        let mut send = existing.clone();
        content::set_password(&mut send, None).await?;
        send.access_stamp = uuid::Uuid::new_v4().to_string();
        send.updated_at = crate::utils::time::now_rfc3339();
        self.save_update(db, &existing, &send, Vec::new()).await?;
        Ok(send)
    }

    pub(crate) async fn delete(&self, id: &str) -> AppResult<()> {
        let db = self.state.database();
        // Pending uploads can also be cancelled by their owner.
        let send = SendRow::fetch_by_id(db, id).await?;
        if send.user_id != self.claims.sub {
            return Err(AppError::send_unavailable());
        }
        let revision = vault_write::commit(
            db,
            self.claims,
            vec![snapshot_guard(db, &send)?],
            vec![send.delete_statement(db)?],
        )
        .await?;
        self.notify(
            &send,
            notifications::UpdateType::SyncSendDelete,
            &revision,
        )
        .await;
        if let Err(error) =
            crate::service::storage_cleanup::process_batch(&self.state.env, db)
                .await
        {
            log::warn!("Send deletion cleanup deferred: {error}");
        }
        Ok(())
    }

    async fn insert(
        &self,
        db: &D1Database,
        send: &SendRow,
        quota: Option<i64>,
        key_guard: D1PreparedStatement,
    ) -> AppResult<String> {
        let mut guards = vec![key_guard];
        if let Some(quota) = quota {
            guards.push(crate::models::send::quota_guard(db, send, quota)?);
        }
        vault_write::commit(db, self.claims, guards, vec![
            send.insert_statement(db)?,
        ])
        .await
    }

    async fn save_update(
        &self,
        db: &D1Database,
        existing: &SendRow,
        send: &SendRow,
        mut guards: Vec<D1PreparedStatement>,
    ) -> AppResult<()> {
        guards.push(snapshot_guard(db, existing)?);
        let revision = vault_write::commit(db, self.claims, guards, vec![
            send.update_statement(db)?,
        ])
        .await?;
        self.notify(send, notifications::UpdateType::SyncSendUpdate, &revision)
            .await;
        Ok(())
    }

    async fn notify(
        &self,
        send: &SendRow,
        kind: notifications::UpdateType,
        revision: &str,
    ) {
        notify_update(self.state, send, kind, self.claims.device(), revision)
            .await;
    }
}

/// A single authorized content access tied to the row that was checked.
pub(crate) struct SendAccess<'a> {
    state:                  &'a AppContext,
    row:                    SendRow,
    is_token_authenticated: bool,
}

impl<'a> SendAccess<'a> {
    pub(crate) async fn anonymous(
        state: &'a AppContext,
        headers: &HeaderMap,
        id: &str,
        file_id: Option<&str>,
        password: Option<&str>,
    ) -> AppResult<Self> {
        let row = SendRow::fetch_by_id(state.database(), id).await?;
        // Legacy file grants reject a mismatched file before password checks.
        if let Some(file_id) = file_id &&
            (row.send_type != 1 || row.file_id.as_deref() != Some(file_id))
        {
            return Err(AppError::send_unavailable());
        }
        authorize_anonymous(state, headers, &row, password).await?;
        Ok(Self {
            state,
            row,
            is_token_authenticated: false,
        })
    }

    pub(crate) async fn with_token(
        state: &'a AppContext,
        headers: &HeaderMap,
    ) -> AppResult<Self> {
        let claims = decode_token(state, headers)?;
        let row =
            SendRow::fetch_by_id(state.database(), &claims.send_id).await?;
        content::validate_access(&row, false)?;
        if claims.access_stamp != row.access_stamp {
            return Err(AppError::send_unavailable());
        }
        Ok(Self {
            state,
            row,
            is_token_authenticated: true,
        })
    }

    pub(crate) async fn read(mut self) -> AppResult<SendAccessResponse> {
        match (self.row.send_type, self.is_token_authenticated) {
            (0, _) => self.record_access(None).await?,
            (_, true) => {
                let revision =
                    self.row.advance_revision(self.state.database()).await?;
                self.notify_access(&revision).await;
            }
            (_, false) => {}
        }
        let db = self.state.database();
        let email = if self.row.is_email_hidden == 0 {
            self.row.creator_email(db).await?
        } else {
            None
        };
        Ok(content::send_access_response(self.row, email))
    }

    pub(crate) async fn grant_file(
        mut self,
        file_id: &str,
    ) -> AppResult<SendFileDownloadResponse> {
        if self.row.send_type != 1 {
            return Err(AppError::bad_request("Send is not a file type send"));
        }
        if self.row.file_id.as_deref() != Some(file_id) {
            return Err(AppError::send_unavailable());
        }
        let key = content::storage_key(&self.row)
            .ok_or_else(AppError::send_unavailable)?;
        if Storage::from_env(&self.state.env)?
            .open(&key)
            .await?
            .is_none()
        {
            return Err(AppError::send_unavailable());
        }
        let response = download_response(self.state, &self.row, file_id)?;
        self.record_access(Some(file_id)).await?;
        Ok(response)
    }

    async fn record_access(&mut self, file_id: Option<&str>) -> AppResult<()> {
        let revision = self
            .row
            .consume_access(self.state.database(), file_id)
            .await?;
        self.notify_access(&revision).await;
        Ok(())
    }

    async fn notify_access(&self, revision: &str) {
        notify_update(
            self.state,
            &self.row,
            notifications::UpdateType::SyncSendUpdate,
            None,
            revision,
        )
        .await;
    }
}

pub(crate) async fn authorize_file_download(
    state: &AppContext,
    token: &str,
    send_id: &str,
    file_id: &str,
) -> AppResult<String> {
    let claims = decode_file_token(
        &state.jwt_keys.access_secret,
        token,
        DOWNLOAD_SCOPE,
        send_id,
        file_id,
    )?;
    let send = SendRow::fetch_by_id(state.database(), send_id).await?;
    content::validate_access(&send, false)?;
    if send.file_id.as_deref() != Some(file_id) ||
        send.access_stamp != claims.access_stamp
    {
        return Err(AppError::send_unavailable());
    }
    content::storage_key(&send).ok_or_else(AppError::send_unavailable)
}

async fn authorize_anonymous(
    state: &AppContext,
    headers: &HeaderMap,
    send: &SendRow,
    password: Option<&str>,
) -> AppResult<()> {
    turnstile::verify_send_access(state, headers, &send.id)?;
    content::validate_access(send, true)?;
    rate_limit::check_send_access(
        state,
        format!("send:{}:{}", send.id, rate_limit::client_ip(headers)),
    )
    .await?;
    content::verify_send_password(send, password).await
}

pub(crate) async fn list_send_responses(
    db: &D1Database,
    user_id: &str,
) -> AppResult<Vec<SendResponse>> {
    Ok(SendRow::list_for_user(db, user_id)
        .await?
        .into_iter()
        .map(content::send_response)
        .collect())
}

#[derive(Serialize)]
pub(crate) struct SendFileDownloadResponse {
    id:     String,
    url:    String,
    object: &'static str,
}

fn download_response(
    state: &AppContext,
    send: &SendRow,
    file_id: &str,
) -> AppResult<SendFileDownloadResponse> {
    if send.send_type != 1 || send.file_id.as_deref() != Some(file_id) {
        return Err(AppError::send_unavailable());
    }
    let token = encode_token(state, send, TokenPurpose::Download)?;
    Ok(SendFileDownloadResponse {
        id:     file_id.to_owned(),
        url:    format!(
            "{}/api/sends/{}/{file_id}?t={token}",
            state.domain().trim_end_matches('/'),
            send.id
        ),
        object: "send-fileDownload",
    })
}

async fn notify_update(
    state: &AppContext,
    send: &SendRow,
    kind: notifications::UpdateType,
    context: Option<&str>,
    date: &str,
) {
    notifications::publish_revision_update(
        &state.env,
        &send.user_id,
        kind,
        &send.id,
        date,
        context,
    )
    .await;
    if context.is_some() {
        // As in the reference handlers, send_create also covers an owner
        // update; public access/count notifications never enter this branch.
        let event = if kind == notifications::UpdateType::SyncSendDelete {
            Event::SendDelete
        } else {
            Event::SendCreate
        };
        admin_notify::emit(&state.env, event, &send.user_id).await;
    }
}

/// Validate the whole rotation before returning statements to the account
/// transaction. The owner must include every completed Send exactly once.
pub(crate) async fn rotation_statements(
    db: &D1Database,
    user_id: &str,
    sends: &[RotateSendRequest],
    now: &str,
    write_token: &str,
) -> AppResult<(Vec<D1PreparedStatement>, Vec<D1PreparedStatement>)> {
    let existing = SendRow::all_for_user(db, user_id).await?;
    if existing.iter().any(|send| send.upload_state != 0) {
        return Err(AppError::bad_request(
            "Complete or cancel pending Send uploads before rotating keys",
        ));
    }
    let existing_ids: std::collections::HashSet<&str> =
        existing.iter().map(|s| s.id.as_str()).collect();
    let ids: std::collections::HashSet<&str> =
        sends.iter().map(|s| s.id.as_str()).collect();
    if sends.len() != ids.len() || ids != existing_ids {
        return Err(AppError::bad_request(
            "All existing Sends must be included exactly once in key rotation",
        ));
    }
    let mut guards = Vec::with_capacity(existing.len() + 1);
    guards.push(collection_guard(db, user_id, existing.len())?);
    for send in &existing {
        guards.push(snapshot_guard(db, send)?);
    }
    let mut statements = Vec::with_capacity(sends.len());
    for payload in sends {
        if payload.encrypted_key.is_empty() {
            return Err(AppError::bad_request("Rotated Send key is required"));
        }
        let send = existing
            .iter()
            .find(|send| send.id == payload.id)
            .ok_or_else(AppError::send_unavailable)?;
        statements.push(send.rotation_statement(
            db,
            &payload.encrypted_key,
            now,
            write_token,
        )?);
    }
    Ok((statements, guards))
}

pub(crate) async fn purge_expired_sends(
    env: &Env,
    db: &D1Database,
) -> AppResult<u32> {
    let abandoned_before = || {
        crate::utils::time::now()
            .checked_sub(jiff::SignedDuration::from_secs(86_400))
            .map(crate::utils::time::format_millis)
            .map_err(AppError::internal_error)
    };
    let candidates = SendRow::cleanup_candidates(
        db,
        &crate::utils::time::now_rfc3339(),
        &abandoned_before()?,
    )
    .await?;
    let mut count = 0;
    for send in candidates {
        let now = crate::utils::time::now_rfc3339();
        let cutoff = abandoned_before()?;
        match send.delete_expired(db, &now, &cutoff).await {
            Ok(()) => count += 1,
            Err(error) => {
                log::warn!("Expired Send metadata retained for retry: {error}");
            }
        }
    }
    if let Err(error) =
        crate::service::storage_cleanup::process_batch(env, db).await
    {
        log::warn!("Expired Send object cleanup deferred: {error}");
    }
    Ok(count)
}
