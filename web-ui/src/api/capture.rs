//! Packet capture API functions

use keystone_core::api::{DiscardCapture, StartCapture, StopCapture};
use keystone_core::capture::{
    CaptureInfo, CaptureNoRequest, CapturePacketsResponse, CaptureRequest, CaptureStateResponse,
};

use super::client::{call, get, get_bytes};

/// The current capture, if any, and the interfaces to capture on
pub async fn fetch_capture_state(token: &str) -> Result<CaptureStateResponse, String> {
    get("/api/capture", token).await
}

/// Start a capture; refused while another is running
pub async fn start_capture(token: &str, request: &CaptureRequest) -> Result<CaptureInfo, String> {
    call::<StartCapture>(token, request).await
}

pub async fn stop_capture(token: &str) -> Result<CaptureInfo, String> {
    call::<StopCapture>(token, &CaptureNoRequest {}).await
}

/// Delete the finished capture and its file
pub async fn discard_capture(token: &str) -> Result<CaptureStateResponse, String> {
    call::<DiscardCapture>(token, &CaptureNoRequest {}).await
}

/// Decoded packet lines from sequence number `since`
pub async fn fetch_capture_packets(
    token: &str,
    since: u64,
) -> Result<CapturePacketsResponse, String> {
    get(&format!("/api/capture/packets?since={since}"), token).await
}

/// The finished capture as a pcap file
pub async fn download_capture(token: &str) -> Result<Vec<u8>, String> {
    get_bytes("/api/capture/pcap", token).await
}
