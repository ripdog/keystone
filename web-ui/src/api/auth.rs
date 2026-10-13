//! Authentication API functions

use keystone_core::api::Login;
use keystone_core::{LoginRequest, LoginResponse};

use super::client::call_public;

/// Login to the API and get a JWT token
pub async fn login(username: &str, password: &str) -> Result<LoginResponse, String> {
    let request = LoginRequest {
        username: username.to_string(),
        password: password.to_string(),
    };

    call_public::<Login>(&request).await
}
