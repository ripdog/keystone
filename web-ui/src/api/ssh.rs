//! SSH configuration and status.
use crate::api::client;
use keystone_core::api::ApplySsh;
use keystone_core::{SshApplyResponse, SshConfig, SshStateResponse};

pub async fn fetch_ssh(token: &str) -> Result<SshStateResponse, String> {
    client::get("/api/ssh", token).await
}

pub async fn apply_ssh(token: &str, config: &SshConfig) -> Result<SshApplyResponse, String> {
    client::call::<ApplySsh>(token, config).await
}
