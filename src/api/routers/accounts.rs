use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{
        delete,
        get,
        post,
        put,
    },
};

use crate::api::{
    AppState,
    controller::accounts,
};

const ACCOUNT_ROTATION_MAX_BYTES: usize = 16 * 1024 * 1024;

pub fn accounts_router() -> Router<AppState> {
    Router::new()
        .route("/api/accounts/prelogin", post(accounts::prelogin))
        .route("/api/accounts/prelogin/password", post(accounts::prelogin))
        .route("/api/accounts/register", post(accounts::register))
        .route(
            "/api/accounts/verify-password",
            post(accounts::verify_password),
        )
        .route("/api/tasks", get(accounts::get_tasks))
        .route("/api/accounts/tasks", get(accounts::get_tasks))
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        .route("/api/accounts/profile", get(accounts::get_profile))
        .route("/api/accounts/profile", post(accounts::post_profile))
        .route("/api/accounts/profile", put(accounts::put_profile))
        .route("/api/accounts/avatar", put(accounts::put_avatar))
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/accounts/delete", post(accounts::delete_account))
        .route(
            "/api/accounts/key-management/rotate-user-keys",
            post(accounts::post_rotate_user_keys)
                .layer(DefaultBodyLimit::max(ACCOUNT_ROTATION_MAX_BYTES)),
        )
        .route(
            "/api/accounts/key-management/key-rotation-data",
            get(accounts::get_key_rotation_data),
        )
        .route(
            "/api/users/{id}/keys",
            get(accounts::get_account_public_keys),
        )
        .route("/api/accounts/kdf", post(accounts::post_kdf))
        .route("/api/accounts/password", post(accounts::post_password))
        .route(
            "/api/accounts/key-management/rotate-user-account-keys",
            post(accounts::post_rotatekey)
                .layer(DefaultBodyLimit::max(ACCOUNT_ROTATION_MAX_BYTES)),
        )
}
