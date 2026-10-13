//! User management API functions

use keystone_core::api::{DeleteUser, SaveUser};
use keystone_core::{
    DeleteUserRequest, DeleteUserResponse, SaveUserRequest, SaveUserResponse, UserInfo,
    UsersResponse,
};

use super::client::{call, get};

/// Fetch users from the API
pub async fn fetch_users(token: &str) -> Result<Vec<UserInfo>, String> {
    let response: UsersResponse = get("/api/users", token).await?;
    Ok(response.users)
}

/// Save a user (create or update)
pub async fn save_user(token: &str, user: SaveUserRequest) -> Result<SaveUserResponse, String> {
    call::<SaveUser>(token, &user).await
}

/// Delete a user
pub async fn delete_user(token: &str, user_id: i64) -> Result<DeleteUserResponse, String> {
    let request = DeleteUserRequest { id: user_id };
    call::<DeleteUser>(token, &request).await
}
