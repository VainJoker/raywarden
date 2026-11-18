//! Authenticated Send writes and post-commit notifications.
use worker::{
    D1Database,
    D1PreparedStatement,
};

use crate::{
    api::{
        AppState,
        service::{
            cipher_mutation,
            claims::Claims,
            notifications,
        },
    },
    errors::AppError,
    infra::admin_notify::{
        self,
        Event,
    },
    send::types::SendDB,
};

pub(super) async fn notify_update(
    state: &AppState,
    send: &SendDB,
    kind: notifications::UpdateType,
    context: Option<&str>,
    date: &str,
) {
    notifications::publish_send_update(
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

/// Reserve quota and publish the row under the captured account/session.
pub(super) async fn insert(
    db: &D1Database,
    send: &SendDB,
    quota: Option<i64>,
    claims: &Claims,
    key_guard: D1PreparedStatement,
) -> Result<(), AppError> {
    let insert = send.insert_statement(db, quota)?;
    let quota_guard = cipher_mutation::guard(
        db,
        "?1 IS NULL OR COALESCE((SELECT SUM(file_size) FROM sends WHERE \
         user_id=?2),0)+?3<=?1",
        &[
            quota
                .map(|value| wasm_bindgen::JsValue::from_f64(value as f64))
                .unwrap_or(wasm_bindgen::JsValue::NULL),
            send.user_id.clone().into(),
            (send.file_size as f64).into(),
        ],
    )?;
    cipher_mutation::commit(db, claims, vec![key_guard, quota_guard], vec![
        insert,
    ])
    .await?;
    Ok(())
}

pub(super) fn snapshot_guard(
    db: &D1Database,
    send: &SendDB,
) -> Result<D1PreparedStatement, AppError> {
    let (predicate, bindings) = send.snapshot_predicate()?;
    cipher_mutation::guard(db, &predicate, &bindings)
}

pub(super) fn upload_guard(
    db: &D1Database,
    send: &SendDB,
) -> Result<D1PreparedStatement, AppError> {
    let (predicate, bindings) = send.upload_predicate();
    cipher_mutation::guard(db, predicate, &bindings)
}

pub(super) fn collection_guard(
    db: &D1Database,
    owner: &str,
    count: usize,
) -> Result<D1PreparedStatement, AppError> {
    cipher_mutation::guard(
        db,
        "(SELECT COUNT(*) FROM sends WHERE user_id=?1)=?2",
        &[owner.into(), (count as f64).into()],
    )
}
