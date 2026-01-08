//! Wizard API functions

use keystone_core::{
    WizardAdvanceRequest, WizardAdvanceResponse, WizardSaveInterfacesRequest,
    WizardSaveInterfacesResponse, WizardSkipRequest, WizardSkipResponse, WizardState,
    WizardStateResponse, WizardStep,
};

use super::client::{get, post};

/// Fetch wizard state
pub async fn fetch_wizard_state(token: &str) -> Result<WizardState, String> {
    let response: WizardStateResponse = get("/api/wizard", token).await?;
    Ok(response.state)
}

/// Advance wizard to next step
pub async fn advance_wizard(
    token: &str,
    completing_step: WizardStep,
) -> Result<WizardAdvanceResponse, String> {
    let request = WizardAdvanceRequest { completing_step };
    post("/api/wizard/advance", token, &request).await
}

/// Skip wizard entirely
pub async fn skip_wizard(token: &str, confirm: bool) -> Result<WizardSkipResponse, String> {
    let request = WizardSkipRequest {
        confirm_skip: confirm,
    };
    post("/api/wizard/skip", token, &request).await
}

/// Save interface assignments
pub async fn save_wizard_interfaces(
    token: &str,
    request: WizardSaveInterfacesRequest,
) -> Result<WizardSaveInterfacesResponse, String> {
    post("/api/wizard/interfaces", token, &request).await
}
