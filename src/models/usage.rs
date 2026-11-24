use serde::{Deserialize, Serialize};
use worker::{D1Database, query};

use crate::{errors::AppResult, infra::db};

#[derive(Deserialize)]
pub struct UsageRow {
    pub name: UsageCategory,
    pub bytes: i64,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum UsageCategory {
    Ciphers,
    Folders,
    Sends,
    Devices,
    TwoFactor,
    Account,
    AttachmentFiles,
    PendingAttachmentFiles,
    SendFiles,
}

impl UsageCategory {
    pub const fn is_file(self) -> bool {
        matches!(
            self,
            Self::AttachmentFiles | Self::PendingAttachmentFiles | Self::SendFiles
        )
    }
}

pub async fn for_user(db: &D1Database, user: &str) -> AppResult<Vec<UsageRow>> {
    db::run_query(
        async {
            query!(
                db,
                "WITH usage(name,bytes) AS (VALUES ('ciphers',(SELECT \
                 COALESCE(SUM(length(CAST(data AS BLOB))),0) FROM ciphers \
                 WHERE user_id=?1)), ('folders',(SELECT \
                 COALESCE(SUM(length(CAST(name AS BLOB))),0) FROM folders \
                 WHERE user_id=?1)), ('sends',(SELECT \
                 COALESCE(SUM(length(CAST(data AS BLOB))+ length(CAST(name AS \
                 BLOB))+length(CAST(encrypted_key AS BLOB))),0) FROM sends \
                 WHERE user_id=?1)), ('devices',(SELECT \
                 COALESCE(SUM(length(CAST(device_id AS BLOB))+ \
                 length(CAST(name AS BLOB))+length(CAST(session_token AS \
                 BLOB))),0) FROM devices WHERE user_id=?1)), \
                 ('twoFactor',(SELECT COALESCE(SUM(length(CAST(data AS \
                 BLOB))),0) FROM two_factors WHERE user_id=?1)), \
                 ('account',(SELECT COALESCE(SUM(length(CAST(email AS BLOB))+ \
                 length(CAST(key AS BLOB))+length(CAST(private_key AS BLOB))+ \
                 length(CAST(public_key AS BLOB))+ \
                 COALESCE(length(CAST(signed_public_key AS BLOB)),0)+ \
                 COALESCE(length(CAST(security_state AS BLOB)),0)+ \
                 COALESCE(length(CAST(signature_key_pair AS BLOB)),0)+ \
                 COALESCE(length(CAST(v2_upgrade_token AS BLOB)),0)),0) FROM \
                 users WHERE id=?1)), ('attachmentFiles',(SELECT \
                 COALESCE(SUM(a.file_size_bytes),0) FROM attachments a JOIN \
                 ciphers c ON c.id=a.cipher_id WHERE c.user_id=?1)), \
                 ('pendingAttachmentFiles',(SELECT \
                 COALESCE(SUM(a.file_size_bytes),0) FROM attachments_pending \
                 a JOIN ciphers c ON c.id=a.cipher_id WHERE c.user_id=?1)), \
                 ('sendFiles',(SELECT COALESCE(SUM(file_size_bytes),0) FROM \
                 sends WHERE user_id=?1))) SELECT name,bytes FROM usage",
                user
            )?
            .all()
            .await?
            .results()
        },
        "Failed to estimate user storage",
    )
    .await
}
