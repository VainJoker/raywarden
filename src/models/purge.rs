use worker::{
    D1Database,
    query,
};

use crate::{
    errors::AppResult,
    infra::db,
    models::attachment::AttachmentKeyRow,
};

pub struct PurgeDB;

impl PurgeDB {
    pub async fn stale_pending_keys(
        db: &D1Database,
        cutoff: &str,
    ) -> AppResult<Vec<String>> {
        let rows = query!(
            db,
            "SELECT cipher_id, id FROM attachments_pending WHERE \
             julianday(created_at) < julianday(?1)",
            cutoff
        )?
        .all()
        .await?
        .results::<AttachmentKeyRow>()?;
        Ok(rows
            .into_iter()
            .map(|row| format!("{}/{}", row.cipher_id, row.id))
            .collect())
    }

    pub async fn deleted_cipher_attachment_keys(
        db: &D1Database,
        cutoff: &str,
    ) -> AppResult<Vec<String>> {
        let rows = query!(
            db,
            "SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c ON \
             a.cipher_id = c.id WHERE c.deleted_at IS NOT NULL AND \
             julianday(c.deleted_at) < julianday(?1) UNION ALL SELECT \
             p.cipher_id, p.id FROM attachments_pending p JOIN ciphers c ON \
             p.cipher_id = c.id WHERE c.deleted_at IS NOT NULL AND \
             julianday(c.deleted_at) < julianday(?1)",
            cutoff
        )?
        .all()
        .await?
        .results::<AttachmentKeyRow>()?;
        Ok(rows
            .into_iter()
            .map(|row| format!("{}/{}", row.cipher_id, row.id))
            .collect())
    }

    pub async fn delete_ciphers_before(
        db: &D1Database,
        cutoff: &str,
        now: &str,
    ) -> AppResult<()> {
        let statements = vec![
            query!(
                db,
                "UPDATE users SET updated_at = ?1 WHERE id IN (SELECT user_id \
                 FROM ciphers WHERE deleted_at IS NOT NULL AND \
                 julianday(deleted_at) < julianday(?2))",
                now,
                cutoff
            )?,
            query!(
                db,
                "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND \
                 julianday(deleted_at) < julianday(?1)",
                cutoff
            )?,
        ];

        db::run_query(
            async { db.batch(statements).await.map(|_| ()) },
            "Failed to purge ciphers and update user revisions",
        )
        .await
    }
}
