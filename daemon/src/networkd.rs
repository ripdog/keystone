//! Networkd configuration file generator
//!
//! Generates systemd-networkd .network and .netdev files from InterfaceConfig and VlanConfig.

use anyhow::{Context, Result};
use keystone_core::{
    BridgeConfig, DhcpMode, Dhcpv4ClientConfig, Dhcpv6ClientConfig, InterfaceConfig, IpForwardMode,
    VlanConfig,
};
use std::collections::HashSet;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use tracing::info;
use uuid::Uuid;

/// Directory where networkd link configuration files are written.
const NETWORKD_DIR: &str = "/etc/systemd/network";
/// Directory for global systemd-networkd configuration drop-ins.
pub(crate) const NETWORKD_CONFIG_DIR: &str = "/etc/systemd/networkd.conf.d";
/// Keystone-owned global forwarding configuration.
pub(crate) const NETWORKD_ROUTER_CONFIG: &str = "50-keystone-router.conf";
/// Keep forwarding enabled at runtime and across boots; networkd reload alone
/// does not reliably apply global forwarding sysctls.
pub(crate) const ROUTER_SYSCTL_CONFIG: &str = "/etc/sysctl.d/99-zz-keystone-forwarding.conf";
const IPV4_FORWARD_SYSCTL: &str = "/proc/sys/net/ipv4/ip_forward";
const IPV6_FORWARD_SYSCTL: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

/// Prefix for keystone-managed files to distinguish from system configs
const KEYSTONE_PREFIX: &str = "50-keystone-";

/// Summary of a successfully applied networkd configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkdApplySummary {
    pub interfaces: usize,
    pub vlans: usize,
    pub bridges: usize,
}

mod pending;
pub use pending::{ConfirmOutcome, NetworkdApplyManager};

/// Captured Keystone networkd files and forwarding sysctls, used to restore
/// the previous state when a change is rolled back.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkdConfigSnapshot {
    files: Vec<(PathBuf, Vec<u8>)>,
    ipv4_forwarding: String,
    ipv6_forwarding: String,
}

impl NetworkdConfigSnapshot {
    fn capture() -> Result<Self> {
        let mut files = Vec::new();
        let network_dir = Path::new(NETWORKD_DIR);
        if network_dir.exists() {
            for entry in std::fs::read_dir(network_dir)
                .with_context(|| format!("Failed to read networkd directory: {:?}", network_dir))?
            {
                let entry = entry.context("Failed to inspect networkd directory entry")?;
                let path = entry.path();
                if is_keystone_networkd_file(&path) {
                    let content = std::fs::read(&path)
                        .with_context(|| format!("Failed to snapshot networkd file: {:?}", path))?;
                    files.push((path, content));
                }
            }
        }

        let global_path = networkd_global_config_path();
        if global_path.exists() {
            let content = std::fs::read(&global_path).with_context(|| {
                format!(
                    "Failed to snapshot networkd global config: {:?}",
                    global_path
                )
            })?;
            files.push((global_path, content));
        }

        let sysctl_path = Path::new(ROUTER_SYSCTL_CONFIG);
        if sysctl_path.exists() {
            files.push((sysctl_path.to_path_buf(), std::fs::read(sysctl_path)?));
        }

        Ok(Self {
            files,
            ipv4_forwarding: std::fs::read_to_string(IPV4_FORWARD_SYSCTL)?,
            ipv6_forwarding: std::fs::read_to_string(IPV6_FORWARD_SYSCTL)?,
        })
    }

    /// Whether two snapshots hold identical Keystone-managed files.
    fn same_files(&self, other: &Self) -> bool {
        let sorted = |snapshot: &Self| {
            let mut files = snapshot.files.clone();
            files.sort();
            files
        };
        sorted(self) == sorted(other)
    }

    fn restore(&self) -> Result<()> {
        remove_all_keystone_networkd_files()?;
        let global_path = networkd_global_config_path();
        if global_path.exists() {
            std::fs::remove_file(&global_path).with_context(|| {
                format!("Failed to remove networkd global config: {:?}", global_path)
            })?;
        }

        let sysctl_path = Path::new(ROUTER_SYSCTL_CONFIG);
        if sysctl_path.exists() {
            std::fs::remove_file(sysctl_path)?;
        }

        for (path, content) in &self.files {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to recreate networkd directory: {:?}", parent)
                })?;
            }
            atomic_write(path, content)?;
        }
        Ok(())
    }

    fn restore_runtime_forwarding(&self) -> Result<()> {
        set_forwarding_sysctl(IPV4_FORWARD_SYSCTL, self.ipv4_forwarding.trim() == "1")?;
        set_forwarding_sysctl(IPV6_FORWARD_SYSCTL, self.ipv6_forwarding.trim() == "1")
    }
}

/// Result of a successful networkd apply.
#[derive(Debug)]
pub struct NetworkdApplyOutcome {
    pub summary: NetworkdApplySummary,
    /// The state before the apply, present only when managed files actually
    /// changed (so there is something to roll back).
    pub previous: Option<NetworkdConfigSnapshot>,
}

/// Atomically install all Keystone-owned networkd files and reload networkd.
/// Existing files are restored if writing or reloading fails.
pub fn apply_configuration(
    configs: &[InterfaceConfig],
    vlans: &[VlanConfig],
    bridges: &[BridgeConfig],
) -> Result<NetworkdApplyOutcome> {
    // Validate both newly submitted and persisted configuration before doing
    // anything to root-owned networkd files.
    for config in configs {
        keystone_core::validation::single_line_fields(config).map_err(anyhow::Error::msg)?;
        keystone_core::validation::interface_name(&config.name).map_err(anyhow::Error::msg)?;
        for name in &config.vlans {
            keystone_core::validation::interface_name(name).map_err(anyhow::Error::msg)?;
        }
    }
    for config in vlans {
        keystone_core::validation::single_line_fields(config).map_err(anyhow::Error::msg)?;
        keystone_core::validation::interface_name(&config.name).map_err(anyhow::Error::msg)?;
        keystone_core::validation::interface_name(&config.parent_interface)
            .map_err(anyhow::Error::msg)?;
    }
    for config in bridges {
        keystone_core::validation::single_line_fields(config).map_err(anyhow::Error::msg)?;
        keystone_core::validation::interface_name(&config.name).map_err(anyhow::Error::msg)?;
        for name in &config.members {
            keystone_core::validation::interface_name(name).map_err(anyhow::Error::msg)?;
        }
    }

    let mut topology_errors = validate_topology(configs, vlans, bridges);
    topology_errors.extend(crate::config_validation::validate_interface_configs(
        configs,
    ));
    if !topology_errors.is_empty() {
        anyhow::bail!("{}", topology_errors.join("; "));
    }

    ensure_networkd_dir()?;
    let snapshot = NetworkdConfigSnapshot::capture()?;

    let result = apply_configuration_files(configs, vlans, bridges).and_then(|summary| {
        reload_networkd()?;
        apply_runtime_forwarding(configs)?;
        Ok(summary)
    });

    match result {
        Ok(summary) => {
            // If the files are unchanged there is nothing to roll back. If the
            // re-capture fails, assume a change to stay on the safe side.
            let changed = NetworkdConfigSnapshot::capture()
                .map(|after| !snapshot.same_files(&after))
                .unwrap_or(true);
            Ok(NetworkdApplyOutcome {
                summary,
                previous: changed.then_some(snapshot),
            })
        }
        Err(error) => {
            let restore_result = snapshot.restore();
            let reload_result = restore_result.as_ref().ok().map(|()| {
                reload_networkd()?;
                snapshot.restore_runtime_forwarding()
            });

            match (restore_result, reload_result) {
                (Ok(()), Some(Ok(()))) => anyhow::bail!(
                    "Network configuration failed and the previous files were restored: {}",
                    error
                ),
                (Ok(()), Some(Err(reload_error))) => anyhow::bail!(
                    "Network configuration failed ({}); previous files were restored but networkd could not reload them ({})",
                    error,
                    reload_error
                ),
                (Err(restore_error), _) => anyhow::bail!(
                    "Network configuration failed ({}) and restoring the previous files also failed ({})",
                    error,
                    restore_error
                ),
                (Ok(()), None) => unreachable!("reload result is present after successful restore"),
            }
        }
    }
}

fn apply_configuration_files(
    configs: &[InterfaceConfig],
    vlans: &[VlanConfig],
    bridges: &[BridgeConfig],
) -> Result<NetworkdApplySummary> {
    write_networkd_global_config(configs)?;
    write_router_sysctl_config(configs)?;

    let mut expected_paths = HashSet::new();
    let mut interface_count = 0;
    for config in configs {
        if config.enabled {
            write_network_file(config)?;
            expected_paths.insert(get_network_filepath(&config.name));
            interface_count += 1;
        }
    }

    for vlan in vlans {
        write_vlan_netdev_file(vlan)?;
        expected_paths.insert(get_vlan_netdev_filepath(&vlan.name));
    }

    for bridge in bridges {
        write_bridge_netdev_file(bridge)?;
        expected_paths.insert(get_bridge_netdev_filepath(&bridge.name));
        write_bridge_member_network_files(bridge, vlans)?;
        for member in &bridge.members {
            expected_paths.insert(get_network_filepath(member));
        }
    }

    // VLAN parents without an enabled interface config or bridge membership
    // still need a .network file to attach their VLANs.
    for (filename, content) in vlan_parent_network_files(configs, vlans, bridges) {
        let path = Path::new(NETWORKD_DIR).join(&filename);
        atomic_write(&path, content.as_bytes())?;
        expected_paths.insert(path);
    }

    remove_stale_keystone_networkd_files(&expected_paths)?;

    Ok(NetworkdApplySummary {
        interfaces: interface_count,
        vlans: vlans.len(),
        bridges: bridges.len(),
    })
}

fn networkd_global_config_path() -> PathBuf {
    Path::new(NETWORKD_CONFIG_DIR).join(NETWORKD_ROUTER_CONFIG)
}

/// Keystone-generated files are regular files named `50-keystone-*`. Directories
/// such as `50-keystone-<if>.network.d/` hold user drop-ins and are never ours.
fn is_keystone_networkd_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(KEYSTONE_PREFIX))
}

fn remove_all_keystone_networkd_files() -> Result<()> {
    let network_dir = Path::new(NETWORKD_DIR);
    if !network_dir.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(network_dir)
        .with_context(|| format!("Failed to read networkd directory: {:?}", network_dir))?
    {
        let path = entry
            .context("Failed to inspect networkd directory entry")?
            .path();
        if is_keystone_networkd_file(&path) {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to remove Keystone networkd file: {:?}", path))?;
        }
    }
    Ok(())
}

fn remove_stale_keystone_networkd_files(expected_paths: &HashSet<PathBuf>) -> Result<()> {
    let network_dir = Path::new(NETWORKD_DIR);
    if !network_dir.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(network_dir)
        .with_context(|| format!("Failed to read networkd directory: {:?}", network_dir))?
    {
        let path = entry
            .context("Failed to inspect networkd directory entry")?
            .path();
        if is_keystone_networkd_file(&path) && !expected_paths.contains(&path) {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to remove stale networkd file: {:?}", path))?;
            info!("Removed stale Keystone networkd file: {:?}", path);
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, content: impl AsRef<[u8]>) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Path has no parent: {:?}", path))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create directory: {:?}", parent))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid file name: {:?}", path))?;
    let temporary = parent.join(format!(".{}.keystone-tmp-{}", file_name, Uuid::new_v4()));

    std::fs::write(&temporary, content)
        .with_context(|| format!("Failed to write temporary file: {:?}", temporary))?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("Failed to atomically replace file: {:?}", path));
    }
    Ok(())
}

/// Generate a .network file content from an InterfaceConfig
pub fn generate_network_file(config: &InterfaceConfig) -> String {
    let mut output = String::new();

    // Header comment
    writeln!(output, "# Generated by Keystone - do not edit manually").unwrap();
    if let Some(desc) = &config.description {
        writeln!(output, "# {}", desc).unwrap();
    }
    writeln!(output).unwrap();

    // [Match] section
    writeln!(output, "[Match]").unwrap();
    writeln!(output, "Name={}", config.name).unwrap();
    writeln!(output).unwrap();

    // [Link] section (if MTU is set)
    if let Some(mtu) = config.mtu {
        writeln!(output, "[Link]").unwrap();
        writeln!(output, "MTUBytes={}", mtu).unwrap();
        writeln!(output).unwrap();
    }

    // [Network] section
    writeln!(output, "[Network]").unwrap();

    if let Some(desc) = &config.description {
        writeln!(output, "Description={}", desc).unwrap();
    }

    // DHCP mode
    writeln!(output, "DHCP={}", config.dhcp_mode).unwrap();

    // Link-local addressing
    writeln!(output, "LinkLocalAddressing={}", config.link_local).unwrap();

    // IPv6 Accept RA
    writeln!(
        output,
        "IPv6AcceptRA={}",
        bool_to_yesno(config.ipv6_accept_ra)
    )
    .unwrap();

    // Current systemd versions use protocol-specific forwarding directives.
    match config.ip_forward {
        IpForwardMode::No => {}
        IpForwardMode::Yes => {
            writeln!(output, "IPv4Forwarding=yes").unwrap();
            writeln!(output, "IPv6Forwarding=yes").unwrap();
        }
        IpForwardMode::Ipv4 => writeln!(output, "IPv4Forwarding=yes").unwrap(),
        IpForwardMode::Ipv6 => writeln!(output, "IPv6Forwarding=yes").unwrap(),
    }

    // Keystone owns source NAT in nftables. Do not also ask networkd to
    // masquerade traffic, as that duplicates policy in a second subsystem.

    if config.ipv6_send_ra {
        writeln!(output, "IPv6SendRA=yes").unwrap();
    }
    if config.dhcp_prefix_delegation.is_some() {
        writeln!(output, "DHCPPrefixDelegation=yes").unwrap();
    }

    // Static DNS servers
    for dns in &config.dns_servers {
        writeln!(output, "DNS={}", dns).unwrap();
    }

    // Search domains
    if !config.search_domains.is_empty() {
        writeln!(output, "Domains={}", config.search_domains.join(" ")).unwrap();
    }

    // Gateway (shorthand, also creates default route)
    if let Some(gw) = &config.gateway {
        writeln!(output, "Gateway={}", gw).unwrap();
    }

    // VLANs attached to this interface
    for vlan in &config.vlans {
        writeln!(output, "VLAN={}", vlan).unwrap();
    }

    // Required for online
    if !config.required_for_online {
        writeln!(output, "RequiredForOnline=no").unwrap();
    }

    // Activation policy (if not default)
    if config.activation_policy != keystone_core::ActivationPolicy::Up {
        writeln!(output, "ActivationPolicy={}", config.activation_policy).unwrap();
    }

    writeln!(output).unwrap();

    // [Address] sections for static addresses
    for addr in &config.addresses {
        writeln!(output, "[Address]").unwrap();
        writeln!(output, "Address={}", addr.address).unwrap();
        if let Some(label) = &addr.label {
            writeln!(output, "Label={}", label).unwrap();
        }
        if addr.scope != keystone_core::AddressScope::Global {
            writeln!(output, "Scope={}", addr.scope).unwrap();
        }
        writeln!(output).unwrap();
    }

    // [Route] sections for static routes
    for route in &config.routes {
        writeln!(output, "[Route]").unwrap();
        if let Some(dest) = &route.destination {
            writeln!(output, "Destination={}", dest).unwrap();
        }
        writeln!(output, "Gateway={}", route.gateway).unwrap();
        if let Some(metric) = route.metric {
            writeln!(output, "Metric={}", metric).unwrap();
        }
        if let Some(table) = &route.table {
            writeln!(output, "Table={}", table).unwrap();
        }
        if route.route_type != keystone_core::RouteType::Unicast {
            writeln!(output, "Type={}", route.route_type).unwrap();
        }
        writeln!(output).unwrap();
    }

    // [DHCPv4] section if DHCP includes IPv4
    if config.dhcp_mode == DhcpMode::Yes || config.dhcp_mode == DhcpMode::Ipv4 {
        match &config.dhcpv4_client {
            Some(dhcp_cfg) => output.push_str(&generate_dhcpv4_section(dhcp_cfg)),
            None => output.push_str(DHCP_NO_RELEASE_V4),
        }
    }

    // [DHCPv6] section if DHCP includes IPv6
    if config.dhcp_mode == DhcpMode::Yes || config.dhcp_mode == DhcpMode::Ipv6 {
        match &config.dhcpv6_client {
            Some(dhcp_cfg) => output.push_str(&generate_dhcpv6_section(dhcp_cfg)),
            None => output.push_str(DHCP_NO_RELEASE_V6),
        }
    }

    // [IPv6AcceptRA] section if accepting RAs with custom settings
    if config.ipv6_accept_ra
        && let Some(ra_client_cfg) = &config.ipv6_accept_ra_config
    {
        output.push_str(&generate_ipv6_accept_ra_section(ra_client_cfg));
    }

    if let Some(pd_cfg) = &config.dhcp_prefix_delegation {
        output.push_str(&generate_dhcp_prefix_delegation_section(pd_cfg));
    }

    output
}

/// networkd releases leases whenever a client stops, including on reconfigure.
/// Some ISP BNGs tear the subscriber session down on release and then end up
/// with a stale session after an immediate re-DISCOVER, so never release.
const DHCP_NO_RELEASE_V4: &str = "[DHCPv4]\nSendRelease=no\n\n";
const DHCP_NO_RELEASE_V6: &str = "[DHCPv6]\nSendRelease=no\n\n";

fn generate_dhcpv4_section(cfg: &Dhcpv4ClientConfig) -> String {
    let mut output = String::new();
    writeln!(output, "[DHCPv4]").unwrap();
    writeln!(output, "SendRelease=no").unwrap();
    if let Some(identifier) = cfg.client_identifier {
        writeln!(output, "ClientIdentifier={identifier}").unwrap();
    }
    writeln!(output, "SendHostname={}", bool_to_yesno(cfg.send_hostname)).unwrap();
    if let Some(hostname) = &cfg.hostname {
        writeln!(output, "Hostname={}", hostname).unwrap();
    }
    writeln!(output, "UseDNS={}", bool_to_yesno(cfg.use_dns)).unwrap();
    writeln!(output, "UseNTP={}", bool_to_yesno(cfg.use_ntp)).unwrap();
    writeln!(output, "UseRoutes={}", bool_to_yesno(cfg.use_routes)).unwrap();
    writeln!(output, "UseGateway={}", bool_to_yesno(cfg.use_gateway)).unwrap();
    writeln!(output, "UseMTU={}", bool_to_yesno(cfg.use_mtu)).unwrap();
    if cfg.use_domains != "yes" {
        writeln!(output, "UseDomains={}", cfg.use_domains).unwrap();
    }
    if let Some(metric) = cfg.route_metric {
        writeln!(output, "RouteMetric={}", metric).unwrap();
    }
    writeln!(output).unwrap();
    output
}

fn generate_dhcpv6_section(cfg: &Dhcpv6ClientConfig) -> String {
    let mut output = String::new();
    writeln!(output, "[DHCPv6]").unwrap();
    writeln!(output, "SendRelease=no").unwrap();
    writeln!(output, "UseDNS={}", bool_to_yesno(cfg.use_dns)).unwrap();
    writeln!(output, "UseNTP={}", bool_to_yesno(cfg.use_ntp)).unwrap();
    if cfg.use_domains != "yes" {
        writeln!(output, "UseDomains={}", cfg.use_domains).unwrap();
    }
    writeln!(
        output,
        "UseDelegatedPrefix={}",
        bool_to_yesno(cfg.use_delegated_prefix)
    )
    .unwrap();
    if let Some(hint) = &cfg.prefix_delegation_hint {
        writeln!(output, "PrefixDelegationHint={}", hint).unwrap();
    }
    writeln!(output, "RapidCommit={}", bool_to_yesno(cfg.rapid_commit)).unwrap();
    if cfg.without_ra != "no" {
        writeln!(output, "WithoutRA={}", cfg.without_ra).unwrap();
    }
    writeln!(output).unwrap();
    output
}

fn generate_dhcp_prefix_delegation_section(
    cfg: &keystone_core::DhcpPrefixDelegationConfig,
) -> String {
    let mut output = String::new();
    writeln!(output, "[DHCPPrefixDelegation]").unwrap();
    if let Some(uplink) = &cfg.uplink_interface {
        writeln!(output, "UplinkInterface={}", uplink).unwrap();
    }
    if let Some(subnet_id) = cfg.subnet_id {
        writeln!(output, "SubnetId={}", subnet_id).unwrap();
    }
    if let Some(token) = &cfg.ipv6_token {
        writeln!(output, "Token=static:{}", token).unwrap();
    }
    writeln!(output, "Announce={}", bool_to_yesno(cfg.announce)).unwrap();
    writeln!(output).unwrap();
    output
}

fn generate_ipv6_accept_ra_section(cfg: &keystone_core::Ipv6AcceptRaConfig) -> String {
    let mut output = String::new();
    writeln!(output, "[IPv6AcceptRA]").unwrap();
    writeln!(output, "UseDNS={}", bool_to_yesno(cfg.use_dns)).unwrap();
    writeln!(output, "UseGateway={}", bool_to_yesno(cfg.use_gateway)).unwrap();
    writeln!(
        output,
        "UseRoutePrefix={}",
        bool_to_yesno(cfg.use_route_prefix)
    )
    .unwrap();
    writeln!(
        output,
        "UseAutonomousPrefix={}",
        bool_to_yesno(cfg.use_autonomous_prefix)
    )
    .unwrap();
    writeln!(output).unwrap();
    output
}

fn bool_to_yesno(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Generate global forwarding settings required for router operation.
fn requested_forwarding(configs: &[InterfaceConfig]) -> (bool, bool) {
    let ipv4 = configs.iter().any(|config| {
        config.enabled && matches!(config.ip_forward, IpForwardMode::Yes | IpForwardMode::Ipv4)
    });
    let ipv6 = configs.iter().any(|config| {
        config.enabled && matches!(config.ip_forward, IpForwardMode::Yes | IpForwardMode::Ipv6)
    });
    (ipv4, ipv6)
}

pub fn generate_router_sysctl_config(configs: &[InterfaceConfig]) -> String {
    let (ipv4, ipv6) = requested_forwarding(configs);
    format!(
        "# Generated by Keystone - do not edit manually\nnet.ipv4.ip_forward = {}\nnet.ipv6.conf.all.forwarding = {}\n",
        u8::from(ipv4),
        u8::from(ipv6)
    )
}

fn write_router_sysctl_config(configs: &[InterfaceConfig]) -> Result<()> {
    let path = Path::new(ROUTER_SYSCTL_CONFIG);
    std::fs::create_dir_all(path.parent().expect("static sysctl path has parent"))?;
    atomic_write(path, generate_router_sysctl_config(configs).as_bytes())
}

fn set_forwarding_sysctl(path: &str, enabled: bool) -> Result<()> {
    let desired = if enabled { "1" } else { "0" };
    // Changing ip_forward resets some kernel IPv4 sysctls; avoid redundant writes.
    if std::fs::read_to_string(path)?.trim() != desired {
        std::fs::write(path, desired).with_context(|| format!("Failed to update {path}"))?;
    }
    Ok(())
}

fn apply_runtime_forwarding(configs: &[InterfaceConfig]) -> Result<()> {
    let (ipv4, ipv6) = requested_forwarding(configs);
    set_forwarding_sysctl(IPV4_FORWARD_SYSCTL, ipv4).context("Failed to apply IPv4 forwarding")?;
    set_forwarding_sysctl(IPV6_FORWARD_SYSCTL, ipv6).context("Failed to apply IPv6 forwarding")
}

/// Generate global forwarding settings required for router operation.
pub fn generate_networkd_global_config(configs: &[InterfaceConfig]) -> Option<String> {
    let (ipv4_forwarding, ipv6_forwarding) = requested_forwarding(configs);

    if !ipv4_forwarding && !ipv6_forwarding {
        return None;
    }

    let mut output = String::new();
    writeln!(output, "# Generated by Keystone - do not edit manually").unwrap();
    writeln!(output, "[Network]").unwrap();
    if ipv4_forwarding {
        writeln!(output, "IPv4Forwarding=yes").unwrap();
    }
    if ipv6_forwarding {
        writeln!(output, "IPv6Forwarding=yes").unwrap();
    }
    Some(output)
}

/// Write or remove Keystone's global networkd router configuration.
pub fn write_networkd_global_config(configs: &[InterfaceConfig]) -> Result<()> {
    let directory = Path::new(NETWORKD_CONFIG_DIR);
    let path = directory.join(NETWORKD_ROUTER_CONFIG);

    if let Some(content) = generate_networkd_global_config(configs) {
        std::fs::create_dir_all(directory).with_context(|| {
            format!(
                "Failed to create networkd config directory: {:?}",
                directory
            )
        })?;
        atomic_write(&path, content.as_bytes())?;
        info!("Wrote global networkd router config to {:?}", path);
    } else if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove networkd router config: {:?}", path))?;
        info!("Removed global networkd router config: {:?}", path);
    }

    Ok(())
}

/// Get the filename for a managed interface
pub fn get_network_filename(interface_name: &str) -> String {
    format!("{}{}.network", KEYSTONE_PREFIX, interface_name)
}

/// Get the full path for a managed interface config file
pub fn get_network_filepath(interface_name: &str) -> std::path::PathBuf {
    Path::new(NETWORKD_DIR).join(get_network_filename(interface_name))
}

/// Write a network config file to disk
pub fn write_network_file(config: &InterfaceConfig) -> Result<()> {
    let content = generate_network_file(config);
    let path = get_network_filepath(&config.name);

    atomic_write(&path, content.as_bytes())?;

    info!("Wrote network config to {:?}", path);
    Ok(())
}

/// Remove a network config file from disk
pub fn remove_network_file(interface_name: &str) -> Result<()> {
    keystone_core::validation::interface_name(interface_name).map_err(anyhow::Error::msg)?;
    let path = get_network_filepath(interface_name);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove network file: {:?}", path))?;
        info!("Removed network config: {:?}", path);
    }
    Ok(())
}

/// Reload systemd-networkd to apply changes
pub fn reload_networkd() -> Result<()> {
    use std::process::Command;

    let output = Command::new("systemctl")
        .args(["reload", "systemd-networkd"])
        .output()
        .context("Failed to execute systemctl reload")?;

    if !output.status.success() {
        // Try restart if reload fails (reload may not be supported in all versions)
        let output = Command::new("systemctl")
            .args(["restart", "systemd-networkd"])
            .output()
            .context("Failed to execute systemctl restart")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to restart systemd-networkd: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    info!("Reloaded systemd-networkd");
    Ok(())
}

/// Check if networkd directory exists
pub fn ensure_networkd_dir() -> Result<()> {
    let path = Path::new(NETWORKD_DIR);
    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create networkd directory: {:?}", path))?;
    }
    Ok(())
}

// ============================================================================
// VLAN Netdev Generation
// ============================================================================

/// Generate a .netdev file content for a VLAN
pub fn generate_vlan_netdev_file(config: &VlanConfig) -> String {
    let mut output = String::new();

    // Header comment
    writeln!(output, "# Generated by Keystone - do not edit manually").unwrap();
    if let Some(desc) = &config.description {
        writeln!(output, "# {}", desc).unwrap();
    }
    writeln!(output).unwrap();

    // [NetDev] section
    writeln!(output, "[NetDev]").unwrap();
    writeln!(output, "Name={}", config.name).unwrap();
    writeln!(output, "Kind=vlan").unwrap();
    if let Some(desc) = &config.description {
        writeln!(output, "Description={}", desc).unwrap();
    }
    writeln!(output).unwrap();

    // [VLAN] section
    writeln!(output, "[VLAN]").unwrap();
    writeln!(output, "Id={}", config.vlan_id).unwrap();
    // Only write protocol if it's not the default 802.1q
    if config.protocol != keystone_core::VlanProtocol::Dot1Q {
        writeln!(output, "Protocol={}", config.protocol).unwrap();
    }
    writeln!(output).unwrap();

    output
}

/// Get the filename for a VLAN netdev
pub fn get_vlan_netdev_filename(vlan_name: &str) -> String {
    format!("{}{}.netdev", KEYSTONE_PREFIX, vlan_name)
}

/// Get the full path for a VLAN netdev config file
pub fn get_vlan_netdev_filepath(vlan_name: &str) -> std::path::PathBuf {
    Path::new(NETWORKD_DIR).join(get_vlan_netdev_filename(vlan_name))
}

/// Write a VLAN netdev config file to disk
pub fn write_vlan_netdev_file(config: &VlanConfig) -> Result<()> {
    let content = generate_vlan_netdev_file(config);
    let path = get_vlan_netdev_filepath(&config.name);

    atomic_write(&path, content.as_bytes())?;

    info!("Wrote VLAN netdev config to {:?}", path);
    Ok(())
}

/// Remove a VLAN netdev config file from disk
pub fn remove_vlan_netdev_file(vlan_name: &str) -> Result<()> {
    keystone_core::validation::interface_name(vlan_name).map_err(anyhow::Error::msg)?;
    let path = get_vlan_netdev_filepath(vlan_name);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove VLAN netdev file: {:?}", path))?;
        info!("Removed VLAN netdev config: {:?}", path);
    }
    Ok(())
}

// ============================================================================
// Bridge Configuration
// ============================================================================

/// Generate bridge .netdev file content
pub fn generate_bridge_netdev_file(config: &keystone_core::BridgeConfig) -> String {
    use std::fmt::Write;
    let mut output = String::new();

    // Header comment
    writeln!(output, "# Generated by Keystone - do not edit manually").unwrap();
    if let Some(desc) = &config.description {
        writeln!(output, "# {}", desc).unwrap();
    }
    writeln!(output).unwrap();

    // [NetDev] section
    writeln!(output, "[NetDev]").unwrap();
    writeln!(output, "Name={}", config.name).unwrap();
    writeln!(output, "Kind=bridge").unwrap();
    if let Some(desc) = &config.description {
        writeln!(output, "Description={}", desc).unwrap();
    }
    writeln!(output).unwrap();

    // [Bridge] section
    writeln!(output, "[Bridge]").unwrap();
    if config.stp {
        writeln!(output, "STP=yes").unwrap();
        writeln!(output, "ForwardDelaySec={}", config.stp_forward_delay).unwrap();
    } else {
        writeln!(output, "STP=no").unwrap();
    }
    writeln!(output).unwrap();

    output
}

/// Get the filename for a bridge netdev
pub fn get_bridge_netdev_filename(bridge_name: &str) -> String {
    format!("{}{}.netdev", KEYSTONE_PREFIX, bridge_name)
}

/// Get the full path for a bridge netdev config file
pub fn get_bridge_netdev_filepath(bridge_name: &str) -> std::path::PathBuf {
    Path::new(NETWORKD_DIR).join(get_bridge_netdev_filename(bridge_name))
}

/// Write a bridge netdev config file to disk
pub fn write_bridge_netdev_file(config: &keystone_core::BridgeConfig) -> Result<()> {
    let content = generate_bridge_netdev_file(config);
    let path = get_bridge_netdev_filepath(&config.name);

    atomic_write(&path, content.as_bytes())?;

    info!("Wrote bridge netdev config to {:?}", path);
    Ok(())
}

/// Remove a bridge netdev config file from disk
pub fn remove_bridge_netdev_file(bridge_name: &str) -> Result<()> {
    keystone_core::validation::interface_name(bridge_name).map_err(anyhow::Error::msg)?;
    let path = get_bridge_netdev_filepath(bridge_name);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove bridge netdev file: {:?}", path))?;
        info!("Removed bridge netdev config: {:?}", path);
    }
    Ok(())
}

/// Names of the VLANs whose parent is `parent`, in the order given.
fn vlan_names_for_parent<'a>(vlans: &'a [VlanConfig], parent: &str) -> Vec<&'a str> {
    vlans
        .iter()
        .filter(|vlan| vlan.parent_interface == parent)
        .map(|vlan| vlan.name.as_str())
        .collect()
}

/// Generate .network file for a bridge member interface
/// Bridge members need a simple .network file that attaches them to the bridge.
/// `vlans` are the VLANs whose parent is this member; they are attached here
/// because this file replaces the member's own interface file.
pub fn generate_bridge_member_network_file(
    interface_name: &str,
    bridge_name: &str,
    vlans: &[VlanConfig],
) -> String {
    use std::fmt::Write;
    let mut output = String::new();

    writeln!(output, "# Generated by Keystone - do not edit manually").unwrap();
    writeln!(
        output,
        "# Bridge member: {} -> {}",
        interface_name, bridge_name
    )
    .unwrap();
    writeln!(output).unwrap();

    writeln!(output, "[Match]").unwrap();
    writeln!(output, "Name={}", interface_name).unwrap();
    writeln!(output).unwrap();

    writeln!(output, "[Network]").unwrap();
    writeln!(output, "Bridge={}", bridge_name).unwrap();
    for vlan in vlan_names_for_parent(vlans, interface_name) {
        writeln!(output, "VLAN={}", vlan).unwrap();
    }
    writeln!(output).unwrap();

    output
}

/// Generate a minimal .network file that only attaches VLANs to a parent
/// interface that has no interface configuration of its own.
pub fn generate_vlan_parent_network_file(parent: &str, vlans: &[VlanConfig]) -> String {
    let mut output = String::new();
    writeln!(output, "# Generated by Keystone - do not edit manually").unwrap();
    writeln!(output, "# VLAN parent: {}", parent).unwrap();
    writeln!(output).unwrap();
    writeln!(output, "[Match]").unwrap();
    writeln!(output, "Name={}", parent).unwrap();
    writeln!(output).unwrap();
    writeln!(output, "[Network]").unwrap();
    writeln!(output, "LinkLocalAddressing=no").unwrap();
    writeln!(output, "IPv6AcceptRA=no").unwrap();
    for vlan in vlan_names_for_parent(vlans, parent) {
        writeln!(output, "VLAN={}", vlan).unwrap();
    }
    writeln!(output).unwrap();
    output
}

/// (filename, content) of the minimal .network files needed for VLAN parents
/// that have neither an enabled interface config nor a bridge membership.
pub fn vlan_parent_network_files(
    configs: &[InterfaceConfig],
    vlans: &[VlanConfig],
    bridges: &[BridgeConfig],
) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for vlan in vlans {
        let parent = vlan.parent_interface.as_str();
        let has_config = configs
            .iter()
            .any(|config| config.enabled && config.name == parent);
        let is_member = bridges
            .iter()
            .any(|bridge| bridge.members.iter().any(|member| member == parent));
        if has_config || is_member || !seen.insert(parent) {
            continue;
        }
        files.push((
            get_network_filename(parent),
            generate_vlan_parent_network_file(parent, vlans),
        ));
    }
    files
}

/// Check that interfaces, VLANs and bridges do not conflict: each interface
/// gets exactly one Keystone `.network` file, so a bridge member cannot also
/// have its own enabled interface configuration or belong to another bridge.
pub fn validate_topology(
    configs: &[InterfaceConfig],
    vlans: &[VlanConfig],
    bridges: &[BridgeConfig],
) -> Vec<String> {
    let mut errors = Vec::new();

    let mut member_of: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for bridge in bridges {
        if bridge.members.is_empty() {
            errors.push(format!("Bridge {} has no members", bridge.name));
        }
        let mut in_this_bridge = HashSet::new();
        for member in &bridge.members {
            if !in_this_bridge.insert(member.as_str()) {
                errors.push(format!(
                    "{} is listed more than once in bridge {}",
                    member, bridge.name
                ));
                continue;
            }
            if let Some(other) = member_of.insert(member.as_str(), bridge.name.as_str()) {
                errors.push(format!(
                    "{} is a member of both bridge {} and bridge {}",
                    member, other, bridge.name
                ));
            }
            if configs
                .iter()
                .any(|config| config.enabled && config.name == *member)
            {
                errors.push(format!(
                    "{} has its own interface configuration; disable it before adding it to bridge {}",
                    member, bridge.name
                ));
            }
        }
    }

    errors.extend(validate_vlans(vlans));
    errors
}

/// Check VLAN definitions for names and IDs that cannot work together.
pub fn validate_vlans(vlans: &[VlanConfig]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen: HashSet<(&str, u16)> = HashSet::new();
    for vlan in vlans {
        if vlan.name == vlan.parent_interface {
            errors.push(format!(
                "VLAN {} cannot have the same name as its parent interface",
                vlan.name
            ));
        }
        if !seen.insert((vlan.parent_interface.as_str(), vlan.vlan_id)) {
            errors.push(format!(
                "VLAN ID {} is used more than once on parent interface {}",
                vlan.vlan_id, vlan.parent_interface
            ));
        }
    }
    errors
}

/// Write bridge member .network files for all members
pub fn write_bridge_member_network_files(
    config: &keystone_core::BridgeConfig,
    vlans: &[VlanConfig],
) -> Result<Vec<String>> {
    let mut written = Vec::new();
    for member in &config.members {
        let content = generate_bridge_member_network_file(member, &config.name, vlans);
        let filename = format!("{}{}.network", KEYSTONE_PREFIX, member);
        let path = Path::new(NETWORKD_DIR).join(&filename);

        atomic_write(&path, content.as_bytes())?;

        info!("Wrote bridge member config for {} to {:?}", member, path);
        written.push(member.clone());
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::{
        ActivationPolicy, AddressScope, InterfaceRole, IpMasqueradeMode, LinkLocalMode,
        StaticAddress, VlanProtocol,
    };

    #[test]
    fn test_simple_dhcp_interface() {
        let config = InterfaceConfig {
            id: Some(1),
            name: "eth0".to_string(),
            role: InterfaceRole::WAN,
            enabled: true,
            description: Some("WAN Interface".to_string()),
            dhcp_mode: DhcpMode::Ipv4,
            addresses: vec![],
            routes: vec![],
            dns_servers: vec![],
            search_domains: vec![],
            gateway: None,
            link_local: LinkLocalMode::Ipv6,
            required_for_online: true,
            activation_policy: ActivationPolicy::Up,
            dhcpv4_client: Some(Dhcpv4ClientConfig::default()),
            dhcpv6_client: None,
            ipv6_accept_ra: true,
            ipv6_accept_ra_config: None,
            ipv6_send_ra: false,
            dhcp_prefix_delegation: None,
            mtu: None,
            ip_forward: IpForwardMode::No,
            ip_masquerade: IpMasqueradeMode::No,
            vlans: vec![],
        };

        let output = generate_network_file(&config);
        assert!(output.contains("[Match]"));
        assert!(output.contains("Name=eth0"));
        assert!(output.contains("DHCP=ipv4"));
        assert!(output.contains("[DHCPv4]"));
    }

    #[test]
    fn test_static_ip_interface() {
        let config = InterfaceConfig {
            id: Some(2),
            name: "eth1".to_string(),
            role: InterfaceRole::LAN,
            enabled: true,
            description: Some("LAN Interface".to_string()),
            dhcp_mode: DhcpMode::No,
            addresses: vec![StaticAddress {
                address: "192.168.1.1/24".to_string(),
                label: None,
                scope: AddressScope::Global,
            }],
            routes: vec![],
            dns_servers: vec!["8.8.8.8".to_string()],
            search_domains: vec!["example.com".to_string()],
            gateway: None,
            link_local: LinkLocalMode::Yes,
            required_for_online: true,
            activation_policy: ActivationPolicy::Up,
            dhcpv4_client: None,
            dhcpv6_client: None,
            ipv6_accept_ra: false,
            ipv6_accept_ra_config: None,
            ipv6_send_ra: false,
            dhcp_prefix_delegation: None,
            mtu: None,
            ip_forward: IpForwardMode::Yes,
            ip_masquerade: IpMasqueradeMode::No,
            vlans: vec![],
        };

        let output = generate_network_file(&config);
        assert!(output.contains("[Address]"));
        assert!(output.contains("Address=192.168.1.1/24"));
        assert!(output.contains("DNS=8.8.8.8"));
        assert!(output.contains("Domains=example.com"));
        assert!(output.contains("IPv4Forwarding=yes"));
        assert!(output.contains("IPv6Forwarding=yes"));
    }

    #[test]
    fn test_dual_stack_router_directives() {
        let wan = InterfaceConfig {
            name: "wan0".to_string(),
            role: InterfaceRole::WAN,
            dhcp_mode: DhcpMode::Yes,
            dhcpv6_client: Some(Dhcpv6ClientConfig::default()),
            ip_forward: IpForwardMode::Yes,
            ip_masquerade: IpMasqueradeMode::Ipv4,
            ..Default::default()
        };
        let wan_output = generate_network_file(&wan);
        assert!(!wan_output.contains("ClientIdentifier="));
        assert!(wan_output.contains("DHCP=yes"));
        assert!(wan_output.contains("UseDelegatedPrefix=yes"));
        assert!(wan_output.contains("IPv4Forwarding=yes"));
        assert!(wan_output.contains("IPv6Forwarding=yes"));
        assert!(!wan_output.contains("IPMasquerade="));

        let lan = InterfaceConfig {
            name: "lan0".to_string(),
            role: InterfaceRole::LAN,
            ipv6_accept_ra: false,
            ipv6_send_ra: true,
            dhcp_prefix_delegation: Some(keystone_core::DhcpPrefixDelegationConfig {
                uplink_interface: Some("wan0".to_string()),
                subnet_id: Some(1),
                ipv6_token: Some("::1".to_string()),
                announce: true,
            }),
            ip_forward: IpForwardMode::Yes,
            ..Default::default()
        };
        let lan_output = generate_network_file(&lan);
        assert!(lan_output.contains("IPv6SendRA=yes"));
        assert!(lan_output.contains("DHCPPrefixDelegation=yes"));
        assert!(lan_output.contains("[DHCPPrefixDelegation]"));
        assert!(lan_output.contains("UplinkInterface=wan0"));
        assert!(lan_output.contains("SubnetId=1"));
        assert!(lan_output.contains("Token=static:::1"));
        assert!(lan_output.contains("Announce=yes"));

        let configs = [wan, lan];
        let global = generate_networkd_global_config(&configs).unwrap();
        assert!(global.contains("IPv4Forwarding=yes"));
        assert!(global.contains("IPv6Forwarding=yes"));
        let sysctl = generate_router_sysctl_config(&configs);
        assert!(sysctl.contains("net.ipv4.ip_forward = 1"));
        assert!(sysctl.contains("net.ipv6.conf.all.forwarding = 1"));
    }

    #[test]
    fn dhcp_mac_identifier_is_explicit_and_optional() {
        let mut client = Dhcpv4ClientConfig::default();
        assert!(!generate_dhcpv4_section(&client).contains("ClientIdentifier="));
        client.client_identifier = Some(keystone_core::Dhcpv4ClientIdentifier::Mac);
        assert!(generate_dhcpv4_section(&client).contains("ClientIdentifier=mac"));
    }

    #[test]
    fn test_get_network_filename() {
        assert_eq!(get_network_filename("eth0"), "50-keystone-eth0.network");
        assert_eq!(get_network_filename("enp3s0"), "50-keystone-enp3s0.network");
    }

    #[test]
    fn test_vlan_netdev_generation() {
        let vlan = VlanConfig {
            id: Some(1),
            name: "vlan10".to_string(),
            parent_interface: "eth0".to_string(),
            vlan_id: 10,
            protocol: VlanProtocol::Dot1Q,
            description: Some("Management VLAN".to_string()),
            interface_config_id: None,
        };

        let output = generate_vlan_netdev_file(&vlan);
        assert!(output.contains("[NetDev]"));
        assert!(output.contains("Name=vlan10"));
        assert!(output.contains("Kind=vlan"));
        assert!(output.contains("[VLAN]"));
        assert!(output.contains("Id=10"));
        // Protocol should not be in output for default 802.1q
        assert!(!output.contains("Protocol="));
    }

    #[test]
    fn test_vlan_qinq_protocol() {
        let vlan = VlanConfig {
            id: Some(2),
            name: "eth0.100".to_string(),
            parent_interface: "eth0".to_string(),
            vlan_id: 100,
            protocol: VlanProtocol::Dot1Ad,
            description: None,
            interface_config_id: None,
        };

        let output = generate_vlan_netdev_file(&vlan);
        assert!(output.contains("Name=eth0.100"));
        assert!(output.contains("Id=100"));
        assert!(output.contains("Protocol=802.1ad"));
    }

    #[test]
    fn test_interface_with_vlans() {
        let config = InterfaceConfig {
            id: Some(5),
            name: "eth0".to_string(),
            role: InterfaceRole::LAN,
            enabled: true,
            description: None,
            dhcp_mode: DhcpMode::No,
            addresses: vec![StaticAddress {
                address: "192.168.1.1/24".to_string(),
                label: None,
                scope: AddressScope::Global,
            }],
            routes: vec![],
            dns_servers: vec![],
            search_domains: vec![],
            gateway: None,
            link_local: LinkLocalMode::Yes,
            required_for_online: true,
            activation_policy: ActivationPolicy::Up,
            dhcpv4_client: None,
            dhcpv6_client: None,
            ipv6_accept_ra: false,
            ipv6_accept_ra_config: None,
            ipv6_send_ra: false,
            dhcp_prefix_delegation: None,
            mtu: None,
            ip_forward: IpForwardMode::No,
            ip_masquerade: IpMasqueradeMode::No,
            vlans: vec!["vlan10".to_string(), "vlan20".to_string()],
        };

        let output = generate_network_file(&config);
        assert!(output.contains("VLAN=vlan10"));
        assert!(output.contains("VLAN=vlan20"));
    }

    #[test]
    fn test_get_vlan_netdev_filename() {
        assert_eq!(
            get_vlan_netdev_filename("vlan10"),
            "50-keystone-vlan10.netdev"
        );
        assert_eq!(
            get_vlan_netdev_filename("eth0.100"),
            "50-keystone-eth0.100.netdev"
        );
    }

    #[test]
    fn test_bridge_netdev_generation() {
        use keystone_core::BridgeConfig;

        let config = BridgeConfig {
            id: Some(1),
            name: "br0".to_string(),
            members: vec!["eth1".to_string(), "eth2".to_string()],
            stp: false,
            stp_forward_delay: 15,
            description: Some("LAN bridge".to_string()),
            interface_config_id: None,
        };

        let output = generate_bridge_netdev_file(&config);
        assert!(output.contains("# Generated by Keystone"));
        assert!(output.contains("# LAN bridge"));
        assert!(output.contains("[NetDev]"));
        assert!(output.contains("Name=br0"));
        assert!(output.contains("Kind=bridge"));
        assert!(output.contains("[Bridge]"));
        assert!(output.contains("STP=no"));
    }

    #[test]
    fn test_bridge_with_stp() {
        use keystone_core::BridgeConfig;

        let config = BridgeConfig {
            id: Some(1),
            name: "br-lan".to_string(),
            members: vec!["eth0".to_string()],
            stp: true,
            stp_forward_delay: 20,
            description: None,
            interface_config_id: None,
        };

        let output = generate_bridge_netdev_file(&config);
        assert!(output.contains("Name=br-lan"));
        assert!(output.contains("STP=yes"));
        assert!(output.contains("ForwardDelaySec=20"));
    }

    #[test]
    fn test_bridge_member_network_file() {
        let output = generate_bridge_member_network_file("eth1", "br0", &[]);
        assert!(!output.contains("VLAN="));
        assert!(output.contains("# Generated by Keystone"));
        assert!(output.contains("[Match]"));
        assert!(output.contains("Name=eth1"));
        assert!(output.contains("[Network]"));
        assert!(output.contains("Bridge=br0"));
    }

    #[test]
    fn test_get_bridge_netdev_filename() {
        assert_eq!(get_bridge_netdev_filename("br0"), "50-keystone-br0.netdev");
        assert_eq!(
            get_bridge_netdev_filename("bridge-lan"),
            "50-keystone-bridge-lan.netdev"
        );
    }

    #[test]
    fn user_dropin_directories_are_not_keystone_files() {
        let dir = std::env::temp_dir().join(format!("keystone-test-{}", Uuid::new_v4()));
        let dropins = dir.join("50-keystone-enp3s0.network.d");
        std::fs::create_dir_all(&dropins).unwrap();
        let file = dir.join("50-keystone-enp3s0.network");
        std::fs::write(&file, "x").unwrap();
        let other = dir.join("90-bootstrap-wan.network");
        std::fs::write(&other, "x").unwrap();

        assert!(is_keystone_networkd_file(&file));
        assert!(!is_keystone_networkd_file(&dropins));
        assert!(!is_keystone_networkd_file(&other));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dhcp_clients_never_send_release() {
        let configured = InterfaceConfig {
            name: "wan0".to_string(),
            dhcp_mode: DhcpMode::Yes,
            dhcpv4_client: Some(Dhcpv4ClientConfig::default()),
            dhcpv6_client: Some(Dhcpv6ClientConfig::default()),
            ..Default::default()
        };
        let bare = InterfaceConfig {
            dhcpv4_client: None,
            dhcpv6_client: None,
            ..configured.clone()
        };
        for config in [configured, bare] {
            let output = generate_network_file(&config);
            assert_eq!(output.matches("SendRelease=no").count(), 2, "{output}");
        }
        let static_lan = InterfaceConfig {
            dhcp_mode: DhcpMode::No,
            ..Default::default()
        };
        assert!(!generate_network_file(&static_lan).contains("SendRelease"));
    }

    fn test_vlan(name: &str, parent: &str, id: u16) -> VlanConfig {
        VlanConfig {
            id: None,
            name: name.to_string(),
            parent_interface: parent.to_string(),
            vlan_id: id,
            protocol: VlanProtocol::Dot1Q,
            description: None,
            interface_config_id: None,
        }
    }

    fn test_bridge(name: &str, members: &[&str]) -> BridgeConfig {
        BridgeConfig {
            id: None,
            name: name.to_string(),
            members: members.iter().map(|m| m.to_string()).collect(),
            stp: false,
            stp_forward_delay: 15,
            description: None,
            interface_config_id: None,
        }
    }

    #[test]
    fn bridge_member_with_enabled_interface_config_is_rejected() {
        let config = InterfaceConfig {
            name: "eth1".to_string(),
            enabled: true,
            ..Default::default()
        };
        let errors = validate_topology(
            std::slice::from_ref(&config),
            &[],
            &[test_bridge("br0", &["eth1"])],
        );
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("eth1 has its own interface configuration"));
        assert!(errors[0].contains("br0"));

        let disabled = InterfaceConfig {
            enabled: false,
            ..config
        };
        assert!(validate_topology(&[disabled], &[], &[test_bridge("br0", &["eth1"])]).is_empty());
    }

    #[test]
    fn interface_in_two_bridges_is_rejected() {
        let errors = validate_topology(
            &[],
            &[],
            &[test_bridge("br0", &["eth1"]), test_bridge("br1", &["eth1"])],
        );
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("both bridge br0 and bridge br1"));
    }

    #[test]
    fn bridge_without_members_is_rejected() {
        let errors = validate_topology(&[], &[], &[test_bridge("br0", &[])]);
        assert_eq!(errors, vec!["Bridge br0 has no members".to_string()]);
    }

    #[test]
    fn bridge_member_file_attaches_vlans_of_the_member() {
        let vlans = [
            test_vlan("vlan10", "eth1", 10),
            test_vlan("vlan20", "eth2", 20),
        ];
        let output = generate_bridge_member_network_file("eth1", "br0", &vlans);
        assert!(output.contains("Bridge=br0"));
        assert!(output.contains("VLAN=vlan10"));
        assert!(!output.contains("vlan20"));
    }

    #[test]
    fn vlan_parent_without_config_gets_minimal_network_file() {
        let vlans = [
            test_vlan("vlan10", "eth1", 10),
            test_vlan("vlan20", "eth1", 20),
        ];
        let files = vlan_parent_network_files(&[], &vlans, &[]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "50-keystone-eth1.network");
        let content = &files[0].1;
        assert!(content.contains("Name=eth1"));
        assert!(content.contains("LinkLocalAddressing=no"));
        assert!(content.contains("IPv6AcceptRA=no"));
        assert!(content.contains("VLAN=vlan10"));
        assert!(content.contains("VLAN=vlan20"));
    }

    #[test]
    fn vlan_parent_with_config_or_bridge_membership_gets_no_extra_file() {
        let vlans = [test_vlan("vlan10", "eth1", 10)];
        let config = InterfaceConfig {
            name: "eth1".to_string(),
            enabled: true,
            ..Default::default()
        };
        assert!(vlan_parent_network_files(std::slice::from_ref(&config), &vlans, &[]).is_empty());
        assert!(
            vlan_parent_network_files(&[], &vlans, &[test_bridge("br0", &["eth1"])]).is_empty()
        );
        let disabled = InterfaceConfig {
            enabled: false,
            ..config
        };
        assert_eq!(vlan_parent_network_files(&[disabled], &vlans, &[]).len(), 1);
    }

    #[test]
    fn vlan_name_and_id_conflicts_are_rejected() {
        let same_name = validate_vlans(&[test_vlan("eth1", "eth1", 10)]);
        assert!(same_name[0].contains("same name as its parent"));

        let dup_id = validate_vlans(&[
            test_vlan("vlan10", "eth1", 10),
            test_vlan("vlan10b", "eth1", 10),
        ]);
        assert!(dup_id[0].contains("VLAN ID 10 is used more than once on parent interface eth1"));

        assert!(
            validate_vlans(&[
                test_vlan("a", "eth1", 10),
                test_vlan("b", "eth2", 10),
                test_vlan("c", "eth1", 11),
            ])
            .is_empty()
        );
    }
}
