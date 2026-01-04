use axum::{
    Router,
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

pub fn accounts_router() -> Router<AppState> {
    Router::new()
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        .route("/api/accounts/profile", get(accounts::get_profile))
        .route("/api/accounts/profile", post(accounts::post_profile))
        .route("/api/accounts/profile", put(accounts::put_profile))
        .route("/api/accounts/avatar", put(accounts::put_avatar))
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/accounts/delete", post(accounts::delete_account))
        .route("/api/accounts/kdf", post(accounts::post_kdf))
        .route("/api/accounts/password", post(accounts::post_password))
        .route(
            "/api/accounts/key-management/rotate-user-account-keys",
            post(accounts::post_rotatekey),
        )
}
