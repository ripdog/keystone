# systemd-networkd Implementation Checklist for Keystone

This document provides a comprehensive checklist of systemd-networkd configuration options that should be implemented in Keystone's interface configuration UI and storage schema.

**Reference**: `man systemd.network`, `man systemd.netdev`, `man systemd.link`

---

## Implementation Phases

### Phase 1: Core Interface Configuration (Essential)
Basic settings that every router admin needs.

### Phase 2: Advanced Networking (Important)
Settings for more complex network setups.

### Phase 3: Enterprise Features (Future)
Advanced features for complex deployments.

---

## Phase 1: Core Interface Configuration

### [Match] Section
*Used to match .network files to interfaces*

| Setting | Type | Description | Priority |
|---------|------|-------------|----------|
| `Name=` | string/glob | Interface name match (e.g., "eth0", "en*") | P1 - ESSENTIAL |
| `MACAddress=` | MAC | Match by MAC address | P2 |
| `Type=` | enum | Device type (ether, loopback, etc.) | P3 |
| `Kind=` | enum | Netdev kind (bridge, bond, vlan, etc.) | P3 |

### [Network] Section - Basic Settings

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `Description=` | string | Human-readable description | P1 | ✅ DONE |
| `DHCP=` | enum | DHCP mode: yes/no/ipv4/ipv6 | P1 | ✅ DONE |
| `Address=` | CIDR | Static IP address(es) | P1 | ✅ DONE |
| `Gateway=` | IP | Default gateway | P1 | ✅ DONE |
| `DNS=` | IP list | DNS servers | P1 | ✅ DONE |
| `Domains=` | string list | Search domains | P2 | ✅ DONE |
| `NTP=` | IP list | NTP servers | P3 | ⬜ TODO |
| `LinkLocalAddressing=` | enum | Link-local config (yes/no/ipv4/ipv6) | P2 | ✅ DONE |
| `IPv6AcceptRA=` | bool | Accept Router Advertisements | P1 | ✅ DONE |
| `IPForward=` | enum | IP forwarding (yes/no/ipv4/ipv6) | P1 | ✅ DONE |
| `IPMasquerade=` | enum | NAT/masquerade (yes/no/ipv4/ipv6/both) | P1 | ✅ DONE |

### [Network] Section - Interface State

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `RequiredForOnline=` | bool/enum | Wait for this interface in boot | P2 | ✅ DONE |
| `ActivationPolicy=` | enum | How to manage link state | P2 | ✅ DONE |
| `ConfigureWithoutCarrier=` | bool | Configure without cable | P3 | ⬜ TODO |

### [Address] Section
*Multiple sections allowed for multiple addresses*

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `Address=` | CIDR | IP address with prefix | P1 | ✅ DONE |
| `Peer=` | CIDR | Peer address (point-to-point) | P3 | ⬜ TODO |
| `Broadcast=` | IP/bool | Broadcast address | P3 | ⬜ TODO |
| `Label=` | string | Address label (15 chars max) | P3 | ⬜ TODO |
| `Scope=` | enum | Address scope (global/link/host) | P2 | 🔄 TYPES DONE |
| `PreferredLifetime=` | duration | Address lifetime | P3 | ⬜ TODO |

### [Route] Section
*Multiple sections allowed for multiple routes*

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `Gateway=` | IP | Route gateway | P1 | ✅ DONE |
| `Destination=` | CIDR | Route destination | P1 | ✅ DONE |
| `Source=` | CIDR | Source-based routing | P3 | ⬜ TODO |
| `Metric=` | u32 | Route metric/priority | P1 | ✅ DONE |
| `Table=` | string/u32 | Routing table | P2 | 🔄 TYPES DONE |
| `Scope=` | enum | Route scope | P3 | ⬜ TODO |
| `Type=` | enum | Route type (unicast/blackhole/etc.) | P2 | 🔄 TYPES DONE |
| `GatewayOnLink=` | bool | Gateway on link | P3 | ⬜ TODO |

---

## Phase 2: Advanced Networking

### [DHCPv4] Section

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `SendHostname=` | bool | Send hostname to DHCP server | P2 | ✅ DONE |
| `Hostname=` | string | Override hostname sent | P3 | ⬜ TODO |
| `UseDNS=` | bool | Use DHCP-provided DNS | P1 | ✅ DONE |
| `UseNTP=` | bool | Use DHCP-provided NTP | P2 | ✅ DONE |
| `UseRoutes=` | bool | Use DHCP-provided routes | P2 | ✅ DONE |
| `UseGateway=` | bool | Use DHCP-provided gateway | P2 | ✅ DONE |
| `UseMTU=` | bool | Use DHCP-provided MTU | P2 | ✅ DONE |
| `UseDomains=` | enum | Use DHCP domains (yes/no/route) | P2 | ⬜ TODO |
| `RouteMetric=` | u32 | Metric for DHCP routes | P2 | ✅ DONE |
| `RequestOptions=` | u8 list | Extra DHCP options to request | P3 | ⬜ TODO |
| `ClientIdentifier=` | enum | DHCP client ID (mac/duid) | P3 | ⬜ TODO |
| `VendorClassIdentifier=` | string | DHCP vendor class | P3 | ⬜ TODO |
| `IAID=` | u32 | DHCP IAID | P3 | ⬜ TODO |

### [DHCPv6] Section

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `UseDNS=` | bool | Use DHCPv6 DNS | P2 | ✅ DONE |
| `UseNTP=` | bool | Use DHCPv6 NTP | P2 | ✅ DONE |
| `UseDomains=` | enum | Use DHCPv6 domains | P2 | ✅ DONE |
| `WithoutRA=` | enum | DHCPv6 without RA | P3 | ✅ DONE |
| `PrefixDelegationHint=` | CIDR | Request specific prefix | P2 | ✅ DONE |
| `RapidCommit=` | bool | Use rapid commit | P3 | ✅ DONE |

### [IPv6AcceptRA] Section

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `UseDNS=` | bool | Use RA-provided DNS | P2 | ⬜ TODO |
| `UseGateway=` | bool | Use RA-provided gateway | P2 | ⬜ TODO |
| `UseRoutePrefix=` | bool | Use RA route prefixes | P2 | ⬜ TODO |
| `UseAutonomousPrefix=` | bool | Use SLAAC | P2 | ⬜ TODO |
| `Token=` | enum/addr | IPv6 address token | P3 | ⬜ TODO |

### [DHCPServer] Section
*For LAN interfaces running a DHCP server*

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `PoolOffset=` | u32 | Start of DHCP pool | P1 | ✅ DONE |
| `PoolSize=` | u32 | Size of DHCP pool | P1 | ✅ DONE |
| `DefaultLeaseTimeSec=` | duration | Default lease time | P1 | ✅ DONE |
| `MaxLeaseTimeSec=` | duration | Max lease time | P2 | ✅ DONE |
| `EmitDNS=` | bool | Provide DNS to clients | P1 | ✅ DONE |
| `DNS=` | IP list | DNS servers to provide | P1 | 🔄 TYPES DONE |
| `EmitNTP=` | bool | Provide NTP to clients | P2 | 🔄 TYPES DONE |
| `NTP=` | IP list | NTP servers to provide | P2 | 🔄 TYPES DONE |
| `EmitRouter=` | bool | Provide router to clients | P1 | ✅ DONE |
| `Router=` | IP | Router address to provide | P2 | 🔄 TYPES DONE |
| `EmitTimezone=` | bool | Provide timezone | P3 | ⬜ TODO |
| `Timezone=` | string | Timezone to provide | P3 | ⬜ TODO |
| `ServerAddress=` | CIDR | DHCP server address | P2 | ⬜ TODO |
| `UplinkInterface=` | string | Uplink for DNS relay | P3 | ⬜ TODO |

### [DHCPServerStaticLease] Section
*Multiple sections for static DHCP leases*

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `MACAddress=` | MAC | Client MAC address | P1 | ✅ DONE |
| `Address=` | IP | Reserved IP address | P1 | ✅ DONE |

### [Link] Section (from .network file)

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `MTUBytes=` | size | Maximum Transmission Unit | P1 | ⬜ TODO |
| `MACAddress=` | MAC | Override MAC address | P3 | ⬜ TODO |
| `ARP=` | bool | Enable ARP | P3 | ⬜ TODO |
| `Multicast=` | bool | Enable multicast | P3 | ⬜ TODO |
| `AllMulticast=` | bool | Receive all multicast | P3 | ⬜ TODO |
| `Promiscuous=` | bool | Promiscuous mode | P3 | ⬜ TODO |
| `Group=` | u32 | Interface group | P3 | ⬜ TODO |

---

## Phase 3: Enterprise Features

### VLAN Configuration (systemd.netdev)

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `VLAN=` | string | VLAN netdev to attach | P2 | ⬜ TODO |
| `Id=` | u16 | VLAN ID (1-4094) | P2 | ⬜ TODO |
| `Protocol=` | enum | 802.1q or 802.1ad | P3 | ⬜ TODO |
| `GVRP=` | bool | GVRP support | P3 | ⬜ TODO |
| `MVRP=` | bool | MVRP support | P3 | ⬜ TODO |
| `LooseBinding=` | bool | Loose binding mode | P3 | ⬜ TODO |
| `ReorderHeader=` | bool | Reorder header | P3 | ⬜ TODO |

### Bridge Configuration (systemd.netdev)

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `Bridge=` | string | Bridge to join | P2 | ⬜ TODO |
| `HelloTimeSec=` | duration | STP hello time | P3 | ⬜ TODO |
| `MaxAgeSec=` | duration | STP max age | P3 | ⬜ TODO |
| `ForwardDelaySec=` | duration | STP forward delay | P3 | ⬜ TODO |
| `AgeingTimeSec=` | duration | MAC aging time | P3 | ⬜ TODO |
| `Priority=` | u16 | Bridge priority | P3 | ⬜ TODO |
| `STP=` | bool | Enable STP | P2 | ⬜ TODO |
| `VLANFiltering=` | bool | Enable VLAN filtering | P3 | ⬜ TODO |

### Bridge Port Settings (in [Bridge] section of .network)

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `Cost=` | u32 | STP path cost | P3 | ⬜ TODO |
| `Priority=` | u16 | Port priority | P3 | ⬜ TODO |
| `HairPin=` | bool | Hairpin mode | P3 | ⬜ TODO |
| `FastLeave=` | bool | IGMP fast leave | P3 | ⬜ TODO |
| `Learning=` | bool | MAC learning | P3 | ⬜ TODO |
| `UnicastFlood=` | bool | Unicast flooding | P3 | ⬜ TODO |
| `MulticastFlood=` | bool | Multicast flooding | P3 | ⬜ TODO |
| `Isolated=` | bool | Port isolation | P3 | ⬜ TODO |

### Bond Configuration (systemd.netdev)

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `Bond=` | string | Bond to join | P2 | ⬜ TODO |
| `Mode=` | enum | Bond mode | P2 | ⬜ TODO |
| `TransmitHashPolicy=` | enum | Hash policy | P2 | ⬜ TODO |
| `LACPTransmitRate=` | enum | LACP rate | P3 | ⬜ TODO |
| `MIIMonitorSec=` | duration | MII monitor interval | P2 | ⬜ TODO |
| `UpDelaySec=` | duration | Up delay | P3 | ⬜ TODO |
| `DownDelaySec=` | duration | Down delay | P3 | ⬜ TODO |
| `PrimarySlave=` | string | Primary interface | P3 | ⬜ TODO |

### Routing Policy Rules ([RoutingPolicyRule] Section)

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `From=` | CIDR | Source match | P2 | ⬜ TODO |
| `To=` | CIDR | Destination match | P2 | ⬜ TODO |
| `FirewallMark=` | u32 | Firewall mark match | P3 | ⬜ TODO |
| `Table=` | string/u32 | Target table | P2 | ⬜ TODO |
| `Priority=` | u32 | Rule priority | P2 | ⬜ TODO |
| `IncomingInterface=` | string | Input interface match | P3 | ⬜ TODO |
| `OutgoingInterface=` | string | Output interface match | P3 | ⬜ TODO |
| `IPProtocol=` | enum/u8 | IP protocol match | P3 | ⬜ TODO |
| `SourcePort=` | port range | Source port match | P3 | ⬜ TODO |
| `DestinationPort=` | port range | Dest port match | P3 | ⬜ TODO |
| `Type=` | enum | Rule type | P3 | ⬜ TODO |

### IPv6 Router Advertisement (for LAN gateways)

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `IPv6SendRA=` | bool | Send RAs | P2 | ⬜ TODO |
| `RouterLifetimeSec=` | duration | Router lifetime | P3 | ⬜ TODO |
| `RouterPreference=` | enum | Router preference | P3 | ⬜ TODO |
| `Managed=` | bool | M flag (use DHCPv6) | P2 | ⬜ TODO |
| `OtherInformation=` | bool | O flag (DHCPv6 other) | P2 | ⬜ TODO |
| `EmitDNS=` | bool | Include DNS in RA | P2 | ⬜ TODO |
| `DNS=` | IP list | DNS servers in RA | P2 | ⬜ TODO |

### [IPv6Prefix] Section

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `Prefix=` | CIDR | Prefix to advertise | P2 | ⬜ TODO |
| `PreferredLifetimeSec=` | duration | Preferred lifetime | P3 | ⬜ TODO |
| `ValidLifetimeSec=` | duration | Valid lifetime | P3 | ⬜ TODO |
| `OnLink=` | bool | On-link flag | P3 | ⬜ TODO |
| `Assign=` | bool | Autonomous flag | P3 | ⬜ TODO |

### DNS/LLMNR/mDNS Settings

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `LLMNR=` | enum | LLMNR support | P3 | ⬜ TODO |
| `MulticastDNS=` | enum | mDNS support | P3 | ⬜ TODO |
| `DNSOverTLS=` | enum | DNS over TLS | P3 | ⬜ TODO |
| `DNSSEC=` | enum | DNSSEC validation | P3 | ⬜ TODO |
| `DNSDefaultRoute=` | bool | Default route for DNS | P3 | ⬜ TODO |

### QoS/Traffic Shaping (qdisc sections)

| Section | Description | Priority | Status |
|---------|-------------|----------|--------|
| `[CAKE]` | Common Applications Kept Enhanced | P3 | ⬜ TODO |
| `[FairQueueing]` | Fair queueing | P3 | ⬜ TODO |
| `[FairQueueingControlledDelay]` | fq_codel | P3 | ⬜ TODO |
| `[TokenBucketFilter]` | TBF rate limiting | P3 | ⬜ TODO |
| `[HierarchyTokenBucket]` | HTB QoS | P3 | ⬜ TODO |

### WireGuard (systemd.netdev)

| Setting | Type | Description | Priority | Status |
|---------|------|-------------|----------|--------|
| `PrivateKey=` | key | Private key | P3 | ⬜ TODO |
| `ListenPort=` | u16 | Listen port | P3 | ⬜ TODO |
| `FirewallMark=` | u32 | Firewall mark | P3 | ⬜ TODO |

---

## Database Schema Design

### New Tables Required

```sql
-- Extended interface configuration
CREATE TABLE interface_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,  -- WAN/LAN
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    
    -- Basic IP configuration
    dhcp_mode TEXT DEFAULT 'no',  -- yes/no/ipv4/ipv6
    link_local TEXT DEFAULT 'ipv6',  -- yes/no/ipv4/ipv6
    ipv6_accept_ra INTEGER DEFAULT 1,
    
    -- Forwarding & NAT
    ip_forward TEXT,  -- yes/no/ipv4/ipv6
    ip_masquerade TEXT,  -- yes/no/ipv4/ipv6/both
    
    -- Link settings
    mtu INTEGER,
    required_for_online INTEGER DEFAULT 1,
    activation_policy TEXT DEFAULT 'up',
    
    -- DNS settings
    llmnr TEXT,  -- yes/no/resolve
    multicast_dns TEXT,  -- yes/no/resolve
    
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Static addresses (multiple per interface)
CREATE TABLE interface_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    address TEXT NOT NULL,  -- CIDR notation
    peer TEXT,  -- for point-to-point
    broadcast TEXT,
    label TEXT,
    scope TEXT DEFAULT 'global',
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- Static routes (multiple per interface)
CREATE TABLE interface_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    destination TEXT,  -- CIDR, NULL for default
    gateway TEXT,
    source TEXT,
    metric INTEGER,
    table_name TEXT DEFAULT 'main',
    type TEXT DEFAULT 'unicast',
    scope TEXT,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- DNS servers (multiple per interface)
CREATE TABLE interface_dns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    server TEXT NOT NULL,
    priority INTEGER DEFAULT 0,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- Search domains
CREATE TABLE interface_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    is_routing_domain INTEGER DEFAULT 0,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- DHCPv4 client settings
CREATE TABLE dhcpv4_client_config (
    interface_config_id INTEGER PRIMARY KEY,
    send_hostname INTEGER DEFAULT 1,
    hostname TEXT,
    use_dns INTEGER DEFAULT 1,
    use_ntp INTEGER DEFAULT 1,
    use_routes INTEGER DEFAULT 1,
    use_gateway INTEGER DEFAULT 1,
    use_mtu INTEGER DEFAULT 1,
    use_domains TEXT DEFAULT 'yes',  -- yes/no/route
    route_metric INTEGER,
    client_identifier TEXT,  -- mac/duid
    vendor_class TEXT,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- DHCPv6 client settings
CREATE TABLE dhcpv6_client_config (
    interface_config_id INTEGER PRIMARY KEY,
    use_dns INTEGER DEFAULT 1,
    use_ntp INTEGER DEFAULT 1,
    use_domains TEXT DEFAULT 'yes',
    without_ra TEXT,
    prefix_delegation_hint TEXT,
    rapid_commit INTEGER DEFAULT 1,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- DHCP server settings (for LAN interfaces)
CREATE TABLE dhcp_server_config (
    interface_config_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    pool_offset INTEGER,
    pool_size INTEGER,
    default_lease_time INTEGER,  -- seconds
    max_lease_time INTEGER,  -- seconds
    emit_dns INTEGER DEFAULT 1,
    emit_ntp INTEGER DEFAULT 0,
    emit_router INTEGER DEFAULT 1,
    router_address TEXT,
    emit_timezone INTEGER DEFAULT 0,
    timezone TEXT,
    uplink_interface TEXT,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- DHCP server DNS servers
CREATE TABLE dhcp_server_dns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dhcp_server_id INTEGER NOT NULL,
    server TEXT NOT NULL,
    priority INTEGER DEFAULT 0,
    FOREIGN KEY (dhcp_server_id) REFERENCES dhcp_server_config(interface_config_id) ON DELETE CASCADE
);

-- DHCP static leases
CREATE TABLE dhcp_static_leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dhcp_server_id INTEGER NOT NULL,
    mac_address TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    FOREIGN KEY (dhcp_server_id) REFERENCES dhcp_server_config(interface_config_id) ON DELETE CASCADE
);

-- IPv6 RA settings (for LAN interfaces)
CREATE TABLE ipv6_ra_config (
    interface_config_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    router_lifetime INTEGER,
    router_preference TEXT,  -- low/medium/high
    managed INTEGER DEFAULT 0,  -- M flag
    other_information INTEGER DEFAULT 0,  -- O flag
    emit_dns INTEGER DEFAULT 1,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- IPv6 prefixes to advertise
CREATE TABLE ipv6_ra_prefixes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ipv6_ra_config_id INTEGER NOT NULL,
    prefix TEXT NOT NULL,
    preferred_lifetime INTEGER,
    valid_lifetime INTEGER,
    on_link INTEGER DEFAULT 1,
    autonomous INTEGER DEFAULT 1,
    FOREIGN KEY (ipv6_ra_config_id) REFERENCES ipv6_ra_config(interface_config_id) ON DELETE CASCADE
);

-- Routing policy rules
CREATE TABLE routing_policy_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    from_prefix TEXT,
    to_prefix TEXT,
    table_name TEXT NOT NULL,
    priority INTEGER,
    firewall_mark INTEGER,
    incoming_interface TEXT,
    outgoing_interface TEXT,
    ip_protocol TEXT,
    source_port TEXT,
    destination_port TEXT,
    type TEXT DEFAULT 'table',
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- VLAN configuration
CREATE TABLE vlan_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,  -- VLAN netdev name
    parent_interface TEXT NOT NULL,
    vlan_id INTEGER NOT NULL,
    protocol TEXT DEFAULT '802.1q',
    FOREIGN KEY (parent_interface) REFERENCES interface_config(interface_name) ON DELETE CASCADE
);

-- Bridge configuration  
CREATE TABLE bridge_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,  -- Bridge netdev name
    stp_enabled INTEGER DEFAULT 0,
    hello_time INTEGER,  -- seconds
    max_age INTEGER,  -- seconds
    forward_delay INTEGER,  -- seconds
    ageing_time INTEGER,  -- seconds
    priority INTEGER,
    vlan_filtering INTEGER DEFAULT 0
);

-- Bridge members
CREATE TABLE bridge_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bridge_id INTEGER NOT NULL,
    interface_name TEXT NOT NULL,
    cost INTEGER,
    priority INTEGER,
    hairpin INTEGER DEFAULT 0,
    FOREIGN KEY (bridge_id) REFERENCES bridge_config(id) ON DELETE CASCADE
);

-- Bond configuration
CREATE TABLE bond_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,  -- Bond netdev name
    mode TEXT NOT NULL,  -- balance-rr, active-backup, etc.
    transmit_hash_policy TEXT,
    lacp_rate TEXT,
    mii_monitor_interval INTEGER,  -- ms
    up_delay INTEGER,
    down_delay INTEGER,
    primary_member TEXT
);

-- Bond members
CREATE TABLE bond_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bond_id INTEGER NOT NULL,
    interface_name TEXT NOT NULL,
    FOREIGN KEY (bond_id) REFERENCES bond_config(id) ON DELETE CASCADE
);
```

---

## Core Type Definitions

### New Rust Types for `keystone-core`

```rust
// DHCP mode enum
pub enum DhcpMode {
    No,
    Yes,
    Ipv4,
    Ipv6,
}

// Link-local addressing mode
pub enum LinkLocalMode {
    No,
    Yes,
    Ipv4,
    Ipv6,
}

// IP forwarding mode
pub enum IpForwardMode {
    No,
    Yes,
    Ipv4,
    Ipv6,
}

// IP masquerade mode
pub enum IpMasqueradeMode {
    No,
    Yes,
    Ipv4,
    Ipv6,
    Both,
}

// Address scope
pub enum AddressScope {
    Global,
    Link,
    Host,
}

// Route type
pub enum RouteType {
    Unicast,
    Local,
    Broadcast,
    Anycast,
    Multicast,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
}

// Static address configuration
pub struct StaticAddress {
    pub address: String,  // CIDR notation
    pub peer: Option<String>,
    pub broadcast: Option<String>,
    pub label: Option<String>,
    pub scope: AddressScope,
}

// Static route configuration
pub struct StaticRoute {
    pub destination: Option<String>,  // CIDR, None for default
    pub gateway: Option<String>,
    pub metric: Option<u32>,
    pub table: Option<String>,
    pub route_type: RouteType,
    pub scope: Option<String>,
}

// DHCPv4 client configuration
pub struct Dhcpv4ClientConfig {
    pub send_hostname: bool,
    pub hostname: Option<String>,
    pub use_dns: bool,
    pub use_ntp: bool,
    pub use_routes: bool,
    pub use_gateway: bool,
    pub use_mtu: bool,
    pub use_domains: String,  // yes/no/route
    pub route_metric: Option<u32>,
    pub client_identifier: Option<String>,
}

// DHCPv6 client configuration
pub struct Dhcpv6ClientConfig {
    pub use_dns: bool,
    pub use_ntp: bool,
    pub use_domains: String,
    pub prefix_delegation_hint: Option<String>,
    pub rapid_commit: bool,
}

// DHCP server configuration
pub struct DhcpServerConfig {
    pub enabled: bool,
    pub pool_offset: Option<u32>,
    pub pool_size: Option<u32>,
    pub default_lease_time_secs: Option<u32>,
    pub max_lease_time_secs: Option<u32>,
    pub emit_dns: bool,
    pub dns_servers: Vec<String>,
    pub emit_ntp: bool,
    pub ntp_servers: Vec<String>,
    pub emit_router: bool,
    pub router_address: Option<String>,
    pub emit_timezone: bool,
    pub timezone: Option<String>,
    pub static_leases: Vec<DhcpStaticLease>,
}

// DHCP static lease
pub struct DhcpStaticLease {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
}

// IPv6 RA configuration
pub struct Ipv6RaConfig {
    pub enabled: bool,
    pub router_lifetime_secs: Option<u32>,
    pub router_preference: Option<String>,
    pub managed: bool,
    pub other_information: bool,
    pub emit_dns: bool,
    pub dns_servers: Vec<String>,
    pub prefixes: Vec<Ipv6RaPrefix>,
}

// IPv6 RA prefix
pub struct Ipv6RaPrefix {
    pub prefix: String,
    pub preferred_lifetime_secs: Option<u32>,
    pub valid_lifetime_secs: Option<u32>,
    pub on_link: bool,
    pub autonomous: bool,
}

// Complete interface configuration
pub struct InterfaceConfig {
    pub name: String,
    pub role: InterfaceRole,
    pub enabled: bool,
    pub description: Option<String>,
    
    // Basic IP configuration
    pub dhcp_mode: DhcpMode,
    pub addresses: Vec<StaticAddress>,
    pub routes: Vec<StaticRoute>,
    pub dns_servers: Vec<String>,
    pub search_domains: Vec<String>,
    
    // Link-local and RA
    pub link_local: LinkLocalMode,
    pub ipv6_accept_ra: bool,
    
    // Forwarding & NAT
    pub ip_forward: Option<IpForwardMode>,
    pub ip_masquerade: Option<IpMasqueradeMode>,
    
    // Link settings
    pub mtu: Option<u32>,
    
    // DHCP client settings
    pub dhcpv4_client: Option<Dhcpv4ClientConfig>,
    pub dhcpv6_client: Option<Dhcpv6ClientConfig>,
    
    // DHCP server settings (for LAN)
    pub dhcp_server: Option<DhcpServerConfig>,
    
    // IPv6 RA settings (for LAN)
    pub ipv6_ra: Option<Ipv6RaConfig>,
}
```

---

## UI Components Needed

### Phase 1 Components

1. **InterfaceBasicSettings**
   - Role selector (WAN/LAN)
   - Description field
   - Enable/disable toggle
   - DHCP mode selector
   - Static IP address list (add/edit/remove)
   - Gateway field
   - DNS servers list
   - MTU field

2. **InterfaceRoutingSettings**
   - Static routes table (add/edit/remove)
   - Default gateway configuration
   - Metric field

3. **InterfaceDhcpClientSettings** (expandable panel)
   - Send hostname toggle
   - Custom hostname field
   - Use DNS/NTP/Routes/Gateway/MTU toggles
   - Route metric field

### Phase 2 Components

4. **DhcpServerSettings** (for LAN interfaces)
   - Enable DHCP server toggle
   - Pool offset/size
   - Lease times
   - DNS servers to provide
   - NTP servers to provide
   - Static leases table

5. **Ipv6Settings** (expandable panel)
   - Accept RA toggle
   - Send RA toggle (LAN only)
   - RA prefix configuration
   - DHCPv6 settings

### Phase 3 Components

6. **VlanConfiguration**
   - VLAN ID
   - Parent interface
   - Protocol selection

7. **BridgeConfiguration**
   - Bridge creation/editing
   - Member interface selection
   - STP settings

8. **BondConfiguration**
   - Bond mode
   - Member interface selection
   - Monitoring settings

9. **RoutingPolicyRules**
   - Policy-based routing rules table
   - Source/destination matching
   - Table selection

---

## Implementation Order

### Sprint 1: Core Foundation
1. [ ] Create new database schema migration
2. [ ] Implement new core types in `keystone-core`
3. [ ] Create database CRUD operations in daemon
4. [ ] Basic API endpoints for interface config

### Sprint 2: Basic UI
5. [ ] InterfaceBasicSettings component
6. [ ] Static address management
7. [ ] Static route management
8. [ ] Save/apply functionality

### Sprint 3: DHCP
9. [ ] DHCP client settings UI
10. [ ] DHCP server settings UI
11. [ ] Static lease management
12. [ ] Config file generation

### Sprint 4: IPv6
13. [ ] IPv6 RA settings
14. [ ] DHCPv6 client settings
15. [ ] IPv6 prefix delegation

### Sprint 5: Advanced
16. [ ] VLAN configuration
17. [ ] Bridge configuration
18. [ ] Routing policy rules

### Sprint 6: Enterprise
19. [ ] Bond configuration
20. [ ] QoS/traffic shaping
21. [ ] WireGuard integration

---

## Notes

### Settings NOT to Implement (out of scope)
- SR-IOV (virtual function configuration) - very specialized
- CAN bus settings - not network routing related
- IPoIB (InfiniBand) - specialized hardware
- L2TP/IPSec tunnels - complex, use dedicated tools
- MACsec - specialized security
- Network emulation (netem) - testing tool
- Most QoS settings - complex, low priority

### Settings to Defer
- NetLabel (SELinux integration)
- NFTSet (nftables integration - handle in firewall module)
- LLDP (useful but not essential for basic routing)

### Key Decisions
1. Store configuration in SQLite, generate .network files on apply
2. Keep existing `managed_interfaces` table for backward compatibility initially
3. Phase implementation to deliver value incrementally
4. Focus on WAN/LAN router use case first
5. **Allow static IPs + DHCP simultaneously** (systemd-networkd supports this):
   - Valid use cases: fallback config, additional addresses, dual-stack
   - Show contextual warnings in UI when both are configured
   - Example: "DHCP is enabled. Static addresses will be used in addition to DHCP-assigned addresses."

---

*Last Updated: 2024-12-28*
*Author: AI Agent (Claude)*
