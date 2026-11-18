use serde::Deserialize;
use worker::{
    D1Database,
    query,
};

use crate::{
    errors::AppResult,
    infra::db,
};

#[derive(Deserialize)]
pub struct UsageRow {
    pub name:  String,
    pub bytes: i64,
}

pub struct UsageDB;
impl UsageDB {
    pub async fn for_user(
        db: &D1Database,
        user: &str,
    ) -> AppResult<Vec<UsageRow>> {
        db::run_query(async {
            query!(db, "SELECT 'ciphers' AS name, COALESCE(SUM(length(CAST(data AS BLOB))),0) AS bytes FROM ciphers WHERE user_id=?1
             UNION ALL SELECT 'folders',COALESCE(SUM(length(CAST(name AS BLOB))),0) FROM folders WHERE user_id=?1
             UNION ALL SELECT 'sends',COALESCE(SUM(length(CAST(data AS BLOB))+length(CAST(name AS BLOB))+length(CAST(akey AS BLOB))),0) FROM sends WHERE user_id=?1
             UNION ALL SELECT 'devices',COALESCE(SUM(length(identifier)+length(name)+length(session_token)),0) FROM devices WHERE user_id=?1
             UNION ALL SELECT 'twoFactor',COALESCE(SUM(length(data)),0) FROM twofactor WHERE user_uuid=?1
             UNION ALL SELECT 'account',COALESCE(SUM(length(email)+length(key)+length(private_key)+length(public_key)
             +COALESCE(length(CAST(signed_public_key AS BLOB)),0)+COALESCE(length(CAST(security_state AS BLOB)),0)
             +COALESCE(length(CAST(signature_key_pair AS BLOB)),0)+COALESCE(length(CAST(v2_upgrade_token AS BLOB)),0)),0) FROM users WHERE id=?1
             UNION ALL SELECT 'attachmentFiles',COALESCE(SUM(a.file_size),0) FROM attachments a JOIN ciphers c ON c.id=a.cipher_id WHERE c.user_id=?1
             UNION ALL SELECT 'pendingAttachmentFiles',COALESCE(SUM(a.file_size),0) FROM attachments_pending a JOIN ciphers c ON c.id=a.cipher_id WHERE c.user_id=?1
             UNION ALL SELECT 'sendFiles',COALESCE(SUM(file_size),0) FROM sends WHERE user_id=?1", user)?.all().await?.results()
        }, "Failed to estimate user storage").await
    }
}
