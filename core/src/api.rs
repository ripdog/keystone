//! Typed API endpoints shared by the daemon, web UI and CLI.
//!
//! Every JSON-body endpoint is described once by a zero-sized marker type that
//! implements [`Endpoint`]. The daemon registers routes from `E::METHOD` /
//! `E::PATH` and types its handlers with [`Req`] / [`Res`]; clients send
//! `E::Request` and parse `E::Response`. A client therefore cannot post the
//! wrong body shape to a route without a compile error.

use crate::blocky::*;
use crate::capture::*;
use crate::changes::*;
use crate::diagnostics::*;
use crate::sqm::*;
use crate::upnp::*;
use crate::*;
use serde::{Serialize, de::DeserializeOwned};

/// HTTP method of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// A daemon API endpoint with a JSON request body and JSON response.
pub trait Endpoint {
    const METHOD: HttpMethod;
    /// Daemon-relative path (the web UI prefixes `/api`). May contain
    /// `{param}` segments, filled in with [`render_path`].
    const PATH: &'static str;
    type Request: Serialize + DeserializeOwned;
    type Response: Serialize + DeserializeOwned;
}

/// Request body type of endpoint `E`.
pub type Req<E> = <E as Endpoint>::Request;
/// Response body type of endpoint `E`.
pub type Res<E> = <E as Endpoint>::Response;

/// Substitute `{name}` segments in an endpoint path template.
pub fn render_path(template: &str, params: &[(&str, &str)]) -> String {
    let mut path = template.to_string();
    for (name, value) in params {
        path = path.replace(&format!("{{{name}}}"), value);
    }
    path
}

macro_rules! endpoints {
    ($($(#[$doc:meta])* $name:ident: $method:ident $path:literal, $req:ty => $res:ty;)*) => {
        $(
            $(#[$doc])*
            pub struct $name;
            impl Endpoint for $name {
                const METHOD: HttpMethod = HttpMethod::$method;
                const PATH: &'static str = $path;
                type Request = $req;
                type Response = $res;
            }
        )*

        /// Every typed endpoint as `(name, method, path)`, for tests and tooling.
        pub const ALL_ENDPOINTS: &[(&str, HttpMethod, &str)] = &[
            $((stringify!($name), HttpMethod::$method, $path),)*
        ];
    };
}

endpoints! {
    Login: Post "/login", LoginRequest => LoginResponse;

    SaveManagedInterfaces: Post "/managed-interfaces", SaveManagedInterfacesRequest => SaveManagedInterfacesResponse;
    SaveInterfaceConfig: Post "/interface-config", SaveInterfaceConfigRequest => SaveInterfaceConfigResponse;
    /// Path parameter: `{name}` (the interface's current name); see [`render_path`].
    RenameInterface: Post "/interfaces/{name}/rename", RenameInterfaceRequest => RenameInterfaceResponse;
    /// Path parameter: `{name}` (the interface); see [`render_path`].
    ResetDhcpSession: Post "/interfaces/{name}/reset-dhcp", ResetDhcpSessionRequest => ResetDhcpSessionResponse;
    SaveVlan: Post "/vlans", SaveVlanConfigRequest => SaveVlanConfigResponse;
    SaveBridge: Post "/bridges", SaveBridgeConfigRequest => SaveBridgeConfigResponse;
    SaveUser: Post "/users", SaveUserRequest => SaveUserResponse;
    DeleteUser: Delete "/users", DeleteUserRequest => DeleteUserResponse;
    SaveGlobalSettings: Post "/settings", SaveGlobalSettingsRequest => SaveGlobalSettingsResponse;
    ConfirmNetworkd: Post "/networkd/confirm", NetworkdConfirmRequest => NetworkdConfirmResponse;

    SaveFirewallZone: Post "/firewall/zones", SaveFirewallZoneRequest => SaveFirewallZoneResponse;
    SaveZoneForward: Post "/firewall/zone-forwards", SaveZoneForwardRequest => SaveZoneForwardResponse;
    SaveInputRule: Post "/firewall/input-rules", SaveInputRuleRequest => SaveInputRuleResponse;
    ReorderInputRules: Post "/firewall/input-rules/reorder", ReorderRulesRequest => ReorderRulesResponse;
    SaveForwardRule: Post "/firewall/forward-rules", SaveForwardRuleRequest => SaveForwardRuleResponse;
    ReorderForwardRules: Post "/firewall/forward-rules/reorder", ReorderRulesRequest => ReorderRulesResponse;
    SaveAddressGroup: Post "/firewall/address-groups", SaveAddressGroupRequest => SaveAddressGroupResponse;
    SavePortGroup: Post "/firewall/port-groups", SavePortGroupRequest => SavePortGroupResponse;
    CreateSimpleForward: Post "/firewall/simple-forwards", CreateSimplePortForwardRequest => SimplePortForwardsResponse;
    /// Path parameter: `{id}` (the rule id); see [`render_path`].
    UpdateSimpleForward: Put "/firewall/simple-forwards/{id}", CreateSimplePortForwardRequest => SimplePortForwardsResponse;
    SavePortForward: Post "/firewall/port-forwards", SavePortForwardRequest => SavePortForwardResponse;
    SaveFirewallGlobalSettings: Post "/firewall/settings", SaveFirewallGlobalSettingsRequest => SaveFirewallGlobalSettingsResponse;
    ConfirmFirewall: Post "/firewall/confirm", FirewallConfirmRequest => FirewallConfirmResponse;
    /// Optional query parameter `baseline=applied` traces the last applied configuration instead of the saved one.
    TestFirewallPacket: Post "/firewall/test-packet", TestPacketRequest => TestPacketResponse;

    SaveDnsmasqConfig: Put "/dnsmasq/config", SaveDnsmasqConfigRequest => SaveDnsmasqConfigResponse;
    SaveDhcpRange: Post "/dnsmasq/ranges", SaveDhcpRangeRequest => SaveDhcpRangeResponse;
    SaveStaticLease: Post "/dnsmasq/leases", SaveStaticLeaseRequest => SaveStaticLeaseResponse;
    SaveDhcpOption: Post "/dnsmasq/options", SaveDhcpOptionRequest => SaveDhcpOptionResponse;
    SaveHostRecord: Post "/dnsmasq/hosts", SaveHostRecordRequest => SaveHostRecordResponse;
    SaveCnameRecord: Post "/dnsmasq/cnames", SaveCnameRecordRequest => SaveCnameRecordResponse;
    SaveAddressOverride: Post "/dnsmasq/overrides", SaveAddressOverrideRequest => SaveAddressOverrideResponse;

    SaveCaddyConfig: Put "/caddy/config", SaveCaddyConfigRequest => SaveCaddyConfigResponse;

    SaveSqmConfig: Put "/sqm/config", SaveSqmConfigRequest => SaveSqmConfigResponse;

    SaveUpnpConfig: Put "/upnp/config", SaveUpnpConfigRequest => SaveUpnpConfigResponse;

    SaveBlockyConfig: Put "/blocky/config", SaveBlockyConfigRequest => SaveBlockyConfigResponse;

    PauseBlocky: Post "/blocky/pause", BlockyPauseRequest => BlockyActionResponse;

    /// Run one network diagnostic (ping, traceroute, DNS lookup or TCP check).
    RunDiagnostic: Post "/diagnostics/run", DiagnosticRequest => DiagnosticResponse;

    /// Starts a capture; refused while another is running.
    StartCapture: Post "/capture", CaptureRequest => CaptureInfo;
    StopCapture: Post "/capture/stop", CaptureNoRequest => CaptureInfo;
    /// Deletes the finished capture and its file.
    DiscardCapture: Delete "/capture", CaptureNoRequest => CaptureStateResponse;

    ApplySsh: Post "/ssh/apply", SshConfig => SshApplyResponse;

    AdvanceWizard: Post "/wizard/advance", WizardAdvanceRequest => WizardAdvanceResponse;
    SkipWizard: Post "/wizard/skip", WizardSkipRequest => WizardSkipResponse;
    SaveWizardInterfaces: Post "/wizard/interfaces", WizardSaveInterfacesRequest => WizardSaveInterfacesResponse;

    /// Manual snapshot of the current configuration.
    CreateSnapshot: Post "/snapshots", CreateSnapshotRequest => SnapshotResponse;
    /// Revert pending (unapplied) changes to each component's last applied state.
    DiscardChanges: Post "/changes/discard", ComponentSelectionRequest => DiscardChangesResponse;
    /// Path parameter: `{id}` (the snapshot id); see [`render_path`].
    RestoreSnapshot: Post "/snapshots/{id}/restore", ComponentSelectionRequest => RestoreSnapshotResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn endpoint_method_and_path_pairs_are_unique() {
        let mut seen = HashSet::new();
        for (name, method, path) in ALL_ENDPOINTS {
            assert!(path.starts_with('/'), "{name}: path must start with /");
            assert!(
                seen.insert((*method, *path)),
                "{name}: duplicate {} {path}",
                method.as_str()
            );
        }
        assert!(ALL_ENDPOINTS.len() > 30);
    }

    #[test]
    fn snapshot_endpoints_render_their_ids() {
        assert_eq!(
            render_path(RestoreSnapshot::PATH, &[("id", "12")]),
            "/snapshots/12/restore"
        );
    }

    #[test]
    fn render_path_fills_parameters() {
        assert_eq!(
            render_path(UpdateSimpleForward::PATH, &[("id", "7")]),
            "/firewall/simple-forwards/7"
        );
    }
}
