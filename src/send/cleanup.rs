//! Bounded expired/pending Send cleanup and persisted object deletion.
use worker::Env;

use super::mutation::snapshot_guard;
use crate::{
    api::service::cipher_mutation,
    errors::AppError,
    send::types::{
        SendDB,
        now_string,
    },
};

pub(crate) async fn purge_expired_sends(
    env: &Env,
) -> Result<u32, worker::Error> {
    let db = env.d1("warden-db")?;
    let mut count = 0;
    for send in SendDB::cleanup_candidates(&db).await? {
        let now = now_string();
        let cutoff = crate::infra::time::format_millis(
            crate::infra::time::now() - jiff::SignedDuration::from_secs(86_400),
        );
        let result: Result<(), AppError> = async {
            let expired = cipher_mutation::guard(
                &db,
                "EXISTS(SELECT 1 FROM sends WHERE id=?1 AND \
                 (julianday(deletion_date)<=julianday(?2) OR (pending<>0 AND \
                 julianday(created_at)<=julianday(?3))))",
                &[send.id.clone().into(), now.clone().into(), cutoff.into()],
            )?;
            db.batch(vec![
                snapshot_guard(&db, &send)?,
                expired,
                send.delete_statement(&db)?,
                SendDB::revision_statement(&db, &send.user_id, &now)?,
            ])
            .await?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => count += 1,
            Err(error) => {
                log::warn!("Expired Send metadata retained for retry: {error}")
            }
        }
    }
    if let Err(error) = crate::infra::storage::cleanup::drain(env, &db).await {
        log::warn!("Expired Send object cleanup deferred: {error}");
    }
    Ok(count)
}
