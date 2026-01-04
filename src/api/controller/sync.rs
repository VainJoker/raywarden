use axum::{
    Json,
    extract::State,
};

use crate::{
    api::{
        AppState,
        service::claims::Claims,
    },
    errors::{
        AppError,
        AuthError,
        DatabaseError,
    },
    models::{
        folder::{
            Folder,
            FolderResponse,
        },
        sync::Profile,
        user::User,
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
        .bind(&[user_id.clone().into()])
        .map_err(map_db_error("sync:get_user bind"))?
        .first(None)
        .await
        .map_err(map_db_error("sync:get_user first"))?
        .ok_or_else(|| AppError::Auth(AuthError::UserNotFound))?;

    // Fetch folders
    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])
        .map_err(map_db_error("sync:list_folders bind"))?
        .all()
        .await
        .map_err(map_db_error("sync:list_folders all"))?
        .results()
        .map_err(map_db_error("sync:list_folders results"))?;

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
    let profile = Profile::from_user(user);
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

fn map_db_error(context: &'static str) -> impl Fn(worker::Error) -> AppError {
    move |e| {
        log::error!("{context}: {e}");
        AppError::Database(DatabaseError::QueryFailed(context.to_string()))
    }
}
