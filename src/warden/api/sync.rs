use axum::{
    Json,
    extract::State,
};

use crate::{
    errors::AppError,
    models::{
        folder::{
            Folder,
            FolderResponse,
        },
        sync::Profile,
        user::User,
    },
    warden::{
        AppState,
        service::claims::Claims,
    },
};

#[worker::send]
pub async fn get_sync_data(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.sub;
    let db = state.get_db();

    // Fetch profile
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Fetch folders
    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let folders: Vec<FolderResponse> = folders_db
        .into_iter()
        .map(std::convert::Into::into)
        .collect();

    // // Fetch ciphers as raw JSON array string (no parsing in Rust!)
    // let include_attachments = attachments::attachments_enabled(env.as_ref());
    // let ciphers_json = ciphers::fetch_cipher_json_array_raw(
    //     &db,
    //     include_attachments,
    //     "WHERE c.user_id = ?1",
    //     &[user_id.clone().into()],
    //     "",
    // )
    // .await?;

    // Serialize profile and folders (small data, acceptable CPU cost)
    let profile = Profile::from_user(user)?;
    // Build a proper JSON value so Axum sets Content-Type: application/json
    let response = serde_json::json!({
        "profile": profile,
        "folders": folders,
        "collections": [],
        "policies": [],
        "ciphers": [],
        "domains": [],
        "sends": [],
        "object": "sync",
    });

    Ok(Json(response))
}
