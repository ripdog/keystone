# Dnsmasq Implementation Plan for Keystone

This document outlines the plan to integrate dnsmasq as the DNS and DHCP server for Keystone, replacing the current systemd-networkd DHCP server functionality.

## Overview

**dnsmasq** is a lightweight, combined DNS forwarder and DHCP server that is well-suited for SOHO routers. It provides:

- **DNS forwarding/caching** with support for upstream chaining (critical for AdGuard Home integration)
- **DHCPv4 server** with static leases, options, and vendor-class matching
- **DHCPv6 server** with SLAAC support
- **Router Advertisement (RA)** for IPv6
- **TFTP server** for PXE boot (optional, future feature)

## Migration Strategy

### What Gets Removed

1. **From `core/src/lib.rs`:**
   - `DhcpServerConfig` struct (replaced by `DnsmasqDhcpRange`)
   - `DhcpStaticLease` (replaced by `DnsmasqStaticLease`)
   - `Ipv6RaConfig` and `Ipv6RaPrefix` (RA now handled by dnsmasq)
   - Remove `dhcp_server` field from `InterfaceConfig`
   - Remove `ipv6_ra` field from `InterfaceConfig`

2. **From `daemon/src/networkd.rs`:**
   - Remove `generate_dhcp_server_section()`
   - Remove `generate_ipv6_ra_section()`
   - Related code in `generate_network_file()` that calls these functions

3. **From Database:**
   - Tables: `dhcp_server_config`, `dhcp_server_dns`, `dhcp_server_ntp`, `dhcp_static_leases`
   - Migration to preserve data by converting to new dnsmasq tables

4. **From Web UI:**
   - Remove DHCP server configuration from interface edit page
   - Remove IPv6 RA configuration from interface edit page

### What Gets Added

New top-level dnsmasq configuration that is interface-aware but not interface-centric.

---

## Phase 1: Core Types (keystone-core)

### New Dnsmasq Configuration Types

```rust
// ============================================================================
// Dnsmasq Configuration Types
// ============================================================================

/// Global dnsmasq configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqConfig {
    /// Whether dnsmasq is enabled
    pub enabled: bool,
    
    // --- DNS Settings ---
    /// DNS port (53 by default, 0 to disable DNS)
    pub dns_port: u16,
    /// DNS cache size (0 to disable caching)
    pub cache_size: u32,
    /// Enable DNSSEC validation (requires trust-anchors)
    pub dnssec_enabled: bool,
    /// Never forward plain names (no dots)
    pub domain_needed: bool,
    /// Never forward addresses in non-routed address spaces
    pub bogus_priv: bool,
    /// Local domain name (e.g., "home.lan", "local")
    pub local_domain: Option<String>,
    /// Expand simple hostnames with the local domain
    pub expand_hosts: bool,
    
    // --- Upstream DNS ---
    /// DNS forwarding mode
    pub upstream_mode: DnsmasqUpstreamMode,
    /// Custom upstream DNS servers (when mode is Custom)
    pub upstream_servers: Vec<DnsmasqUpstreamServer>,
    
    // --- Interface Binding ---
    /// Interfaces to listen on (empty = all interfaces)
    pub listen_interfaces: Vec<String>,
    /// Interfaces to NOT listen on
    pub except_interfaces: Vec<String>,
    /// Interfaces where DHCP is disabled (DNS only)
    pub no_dhcp_interfaces: Vec<String>,
    /// Use bind-dynamic mode (recommended for routers)
    pub bind_dynamic: bool,
    
    // --- Logging ---
    /// Log DNS queries
    pub log_queries: bool,
    /// Log DHCP transactions
    pub log_dhcp: bool,
}

impl Default for DnsmasqConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dns_port: 53,
            cache_size: 1000,
            dnssec_enabled: false,
            domain_needed: true,
            bogus_priv: true,
            local_domain: Some("lan".to_string()),
            expand_hosts: true,
            upstream_mode: DnsmasqUpstreamMode::System,
            upstream_servers: Vec::new(),
            listen_interfaces: Vec::new(),  // Listen on all
            except_interfaces: Vec::new(),
            no_dhcp_interfaces: Vec::new(),
            bind_dynamic: true,
            log_queries: false,
            log_dhcp: false,
        }
    }
}

/// How dnsmasq resolves upstream DNS queries
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsmasqUpstreamMode {
    /// Use system resolv.conf
    #[default]
    System,
    /// Use custom upstream servers only (--no-resolv)
    Custom,
    /// Chain to local AdGuard Home (localhost:5353 or similar)
    LocalAdGuard,
}

/// Upstream DNS server configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqUpstreamServer {
    /// Server address (IP or hostname)
    pub address: String,
    /// Port (default 53)
    pub port: Option<u16>,
    /// Specific domain this server handles (None = all)
    /// e.g., "internal.company.com" for private DNS
    pub domain: Option<String>,
}

/// DHCP range/pool configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqDhcpRange {
    pub id: Option<i64>,
    /// Human-readable name for this pool
    pub name: String,
    /// Interface this pool serves
    pub interface: String,
    /// Pool start address (e.g., "192.168.1.100")
    pub start_address: String,
    /// Pool end address (e.g., "192.168.1.200")
    pub end_address: String,
    /// Subnet mask (e.g., "255.255.255.0")
    /// If not specified, derived from interface address
    pub netmask: Option<String>,
    /// Lease duration (e.g., "12h", "1d", "infinite")
    pub lease_time: String,
    /// Whether this range is enabled
    pub enabled: bool,
    
    // --- DHCPv6 / SLAAC options ---
    /// IPv6 mode for this range
    pub ipv6_mode: Option<DnsmasqIpv6Mode>,
    /// IPv6 prefix for this range (e.g., "2001:db8::/64")
    pub ipv6_prefix: Option<String>,
}

impl Default for DnsmasqDhcpRange {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            interface: String::new(),
            start_address: String::new(),
            end_address: String::new(),
            netmask: None,
            lease_time: "24h".to_string(),
            enabled: true,
            ipv6_mode: None,
            ipv6_prefix: None,
        }
    }
}

/// IPv6 DHCP/RA mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsmasqIpv6Mode {
    /// Router Advertisement only (SLAAC)
    RaOnly,
    /// RA with stateless DHCPv6 (addresses via SLAAC, other config via DHCP)
    RaStateless,
    /// RA + DHCPv6 + SLAAC
    Slaac,
    /// Full DHCPv6 (managed addresses, no SLAAC)
    Dhcpv6,
}

/// Static DHCP lease/reservation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqStaticLease {
    pub id: Option<i64>,
    /// MAC address (e.g., "00:11:22:33:44:55")
    /// Supports wildcards like "00:11:22:*:*:*"
    pub mac_address: String,
    /// Reserved IP address
    pub ip_address: String,
    /// Client hostname (optional)
    pub hostname: Option<String>,
    /// Lease time override (optional, e.g., "infinite")
    pub lease_time: Option<String>,
    /// Client ID (alternative to MAC, for DHCPv6)
    pub client_id: Option<String>,
    /// Tags to set when this host is matched
    pub set_tags: Vec<String>,
    /// Whether this reservation is enabled
    pub enabled: bool,
}

impl Default for DnsmasqStaticLease {
    fn default() -> Self {
        Self {
            id: None,
            mac_address: String::new(),
            ip_address: String::new(),
            hostname: None,
            lease_time: None,
            client_id: None,
            set_tags: Vec::new(),
            enabled: true,
        }
    }
}

/// DHCP options sent to clients
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqDhcpOption {
    pub id: Option<i64>,
    /// Human-readable description
    pub description: Option<String>,
    /// DHCP option number (e.g., 3 for router, 6 for DNS)
    /// Can also be option name like "router", "dns-server"
    pub option: String,
    /// Value(s) for the option
    pub value: String,
    /// Only apply to clients with these tags
    pub match_tags: Vec<String>,
    /// Whether this option is enabled
    pub enabled: bool,
    /// Is this an IPv6 option (option6:)
    pub ipv6: bool,
    /// Force send even if client didn't request it
    pub force: bool,
}

impl Default for DnsmasqDhcpOption {
    fn default() -> Self {
        Self {
            id: None,
            description: None,
            option: String::new(),
            value: String::new(),
            match_tags: Vec::new(),
            enabled: true,
            ipv6: false,
            force: false,
        }
    }
}

/// Custom DNS host record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqHostRecord {
    pub id: Option<i64>,
    /// Hostname(s) for this record
    pub hostnames: Vec<String>,
    /// IPv4 address (optional)
    pub ipv4_address: Option<String>,
    /// IPv6 address (optional)
    pub ipv6_address: Option<String>,
    /// TTL in seconds (optional)
    pub ttl: Option<u32>,
    /// Whether this record is enabled
    pub enabled: bool,
}

/// Custom CNAME record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqCnameRecord {
    pub id: Option<i64>,
    /// Alias name (the CNAME)
    pub alias: String,
    /// Target hostname
    pub target: String,
    /// TTL in seconds (optional)
    pub ttl: Option<u32>,
    /// Whether this record is enabled
    pub enabled: bool,
}

/// Address override (block or redirect domain)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqAddressOverride {
    pub id: Option<i64>,
    /// Domain pattern (e.g., "ads.example.com", "*.malware.com")
    pub domain: String,
    /// Override action
    pub action: DnsmasqAddressAction,
    /// Custom IP address (when action is Redirect)
    pub redirect_address: Option<String>,
    /// Whether this override is enabled
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsmasqAddressAction {
    /// Return NXDOMAIN (block the domain)
    Block,
    /// Redirect to specific IP
    Redirect,
    /// Return 0.0.0.0 / :: (NULL address)
    Null,
}
```

### API Request/Response Types

```rust
// Complete dnsmasq state for UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsmasqStateResponse {
    pub config: DnsmasqConfig,
    pub dhcp_ranges: Vec<DnsmasqDhcpRange>,
    pub static_leases: Vec<DnsmasqStaticLease>,
    pub dhcp_options: Vec<DnsmasqDhcpOption>,
    pub host_records: Vec<DnsmasqHostRecord>,
    pub cname_records: Vec<DnsmasqCnameRecord>,
    pub address_overrides: Vec<DnsmasqAddressOverride>,
}

// Save requests for each entity type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveDnsmasqConfigRequest {
    pub config: DnsmasqConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveDhcpRangeRequest {
    pub range: DnsmasqDhcpRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveStaticLeaseRequest {
    pub lease: DnsmasqStaticLease,
}

// ... similar for other entity types

// Current DHCP leases (read from lease file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub expires_at: u64,  // Unix timestamp
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLeasesResponse {
    pub leases: Vec<DhcpLease>,
}
```

---

## Phase 2: Database Schema

### New Migration: `20241230000001_dnsmasq_config.sql`

```sql
-- Dnsmasq global configuration (singleton)
CREATE TABLE IF NOT EXISTS dnsmasq_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 1,
    dns_port INTEGER NOT NULL DEFAULT 53,
    cache_size INTEGER NOT NULL DEFAULT 1000,
    dnssec_enabled INTEGER NOT NULL DEFAULT 0,
    domain_needed INTEGER NOT NULL DEFAULT 1,
    bogus_priv INTEGER NOT NULL DEFAULT 1,
    local_domain TEXT,
    expand_hosts INTEGER NOT NULL DEFAULT 1,
    upstream_mode TEXT NOT NULL DEFAULT 'system',
    bind_dynamic INTEGER NOT NULL DEFAULT 1,
    log_queries INTEGER NOT NULL DEFAULT 0,
    log_dhcp INTEGER NOT NULL DEFAULT 0
);

-- Initialize with defaults
INSERT OR IGNORE INTO dnsmasq_config (id) VALUES (1);

-- Dnsmasq listen interfaces (many-to-one)
CREATE TABLE IF NOT EXISTS dnsmasq_listen_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE
);

-- Dnsmasq except interfaces
CREATE TABLE IF NOT EXISTS dnsmasq_except_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE
);

-- Dnsmasq no-dhcp interfaces (DNS only)
CREATE TABLE IF NOT EXISTS dnsmasq_no_dhcp_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE
);

-- Upstream DNS servers
CREATE TABLE IF NOT EXISTS dnsmasq_upstream_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    port INTEGER,
    domain TEXT,
    priority INTEGER NOT NULL DEFAULT 0
);

-- DHCP ranges
CREATE TABLE IF NOT EXISTS dnsmasq_dhcp_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    interface TEXT NOT NULL,
    start_address TEXT NOT NULL,
    end_address TEXT NOT NULL,
    netmask TEXT,
    lease_time TEXT NOT NULL DEFAULT '24h',
    enabled INTEGER NOT NULL DEFAULT 1,
    ipv6_mode TEXT,
    ipv6_prefix TEXT
);

-- Static leases
CREATE TABLE IF NOT EXISTS dnsmasq_static_leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    lease_time TEXT,
    client_id TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- Static lease tags (many-to-many)
CREATE TABLE IF NOT EXISTS dnsmasq_static_lease_tags (
    lease_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (lease_id, tag),
    FOREIGN KEY (lease_id) REFERENCES dnsmasq_static_leases(id) ON DELETE CASCADE
);

-- DHCP options
CREATE TABLE IF NOT EXISTS dnsmasq_dhcp_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT,
    option TEXT NOT NULL,
    value TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    ipv6 INTEGER NOT NULL DEFAULT 0,
    force_send INTEGER NOT NULL DEFAULT 0
);

-- DHCP option tag matches (many-to-many)
CREATE TABLE IF NOT EXISTS dnsmasq_dhcp_option_tags (
    option_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (option_id, tag),
    FOREIGN KEY (option_id) REFERENCES dnsmasq_dhcp_options(id) ON DELETE CASCADE
);

-- Custom DNS host records
CREATE TABLE IF NOT EXISTS dnsmasq_host_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ipv4_address TEXT,
    ipv6_address TEXT,
    ttl INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- Host record hostnames (one-to-many)
CREATE TABLE IF NOT EXISTS dnsmasq_host_record_names (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    FOREIGN KEY (record_id) REFERENCES dnsmasq_host_records(id) ON DELETE CASCADE
);

-- CNAME records
CREATE TABLE IF NOT EXISTS dnsmasq_cname_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alias TEXT NOT NULL,
    target TEXT NOT NULL,
    ttl INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- Address overrides (block/redirect domains)
CREATE TABLE IF NOT EXISTS dnsmasq_address_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    action TEXT NOT NULL,  -- 'block', 'redirect', 'null'
    redirect_address TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_dhcp_ranges_interface ON dnsmasq_dhcp_ranges(interface);
CREATE INDEX IF NOT EXISTS idx_static_leases_mac ON dnsmasq_static_leases(mac_address);
CREATE INDEX IF NOT EXISTS idx_host_record_names_record ON dnsmasq_host_record_names(record_id);
```

### Data Migration

Add a migration script that:
1. Reads existing DHCP server config from `dhcp_server_config` table
2. Creates corresponding `dnsmasq_dhcp_ranges` entries
3. Migrates `dhcp_static_leases` to `dnsmasq_static_leases`
4. Preserves DNS server preferences as `dnsmasq_dhcp_options` (option 6)
5. Drops old tables after successful migration

---

## Phase 3: Daemon Implementation

### New Module: `daemon/src/dnsmasq.rs`

```
daemon/src/dnsmasq/
├── mod.rs           # Module exports
├── config.rs        # Config generation logic
├── apply.rs         # Apply config and manage service
├── routes.rs        # API route handlers
└── leases.rs        # Parse and serve active leases
```

#### Config Generation (`config.rs`)

Generates `/etc/dnsmasq.d/50-keystone.conf`:

```ini
# Generated by Keystone - do not edit manually

# Global settings
domain-needed
bogus-priv
local=/lan/
expand-hosts
domain=lan

# Upstream DNS
no-resolv
server=127.0.0.1#5353  # AdGuard Home example

# Interface binding
bind-dynamic
interface=br-lan
interface=eth1
no-dhcp-interface=eth0  # WAN - DNS only

# DNS cache
cache-size=1000

# DHCP pools
dhcp-range=set:lan,192.168.1.100,192.168.1.200,255.255.255.0,24h
dhcp-range=set:guest,192.168.10.100,192.168.10.200,255.255.255.0,1h

# DHCPv6/SLAAC
dhcp-range=::,constructor:br-lan,ra-stateless

# Static leases
dhcp-host=00:11:22:33:44:55,192.168.1.10,server1,infinite
dhcp-host=00:11:22:33:44:56,192.168.1.11,server2

# DHCP options
dhcp-option=option:router,192.168.1.1
dhcp-option=option:dns-server,192.168.1.1
dhcp-option=option:ntp-server,192.168.1.1
dhcp-option=option:domain-search,lan,home.arpa

# Tagged options (for specific networks)
dhcp-option=tag:guest,option:dns-server,1.1.1.1,8.8.8.8

# Custom DNS records
host-record=router.lan,192.168.1.1
cname=gateway.lan,router.lan

# Block domains
address=/ads.example.com/
address=/malware.com/

# Lease file
dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases

# Logging (if enabled)
# log-queries
# log-dhcp
```

#### Service Management (`apply.rs`)

```rust
/// Apply dnsmasq configuration
pub async fn apply_dnsmasq_config(db: &SqlitePool) -> Result<()> {
    // 1. Load config from database
    let config = load_dnsmasq_config(db).await?;
    
    // 2. Generate config file content
    let content = generate_dnsmasq_config(&config)?;
    
    // 3. Write to /etc/dnsmasq.d/50-keystone.conf
    ensure_dnsmasq_dir()?;
    std::fs::write(DNSMASQ_CONFIG_PATH, &content)?;
    
    // 4. Validate config
    validate_dnsmasq_config()?;
    
    // 5. Reload dnsmasq
    reload_dnsmasq()?;
    
    Ok(())
}

fn validate_dnsmasq_config() -> Result<()> {
    let output = Command::new("dnsmasq")
        .arg("--test")
        .output()?;
    
    if !output.status.success() {
        anyhow::bail!("dnsmasq config validation failed: {}", 
            String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

fn reload_dnsmasq() -> Result<()> {
    let output = Command::new("systemctl")
        .args(["reload", "dnsmasq"])
        .output()?;
    
    if !output.status.success() {
        // Try restart if reload fails
        let output = Command::new("systemctl")
            .args(["restart", "dnsmasq"])
            .output()?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to reload dnsmasq: {}", 
                String::from_utf8_lossy(&output.stderr));
        }
    }
    Ok(())
}
```

#### Lease Parsing (`leases.rs`)

Parse `/var/lib/dnsmasq/dnsmasq.leases`:

```rust
/// Parse dnsmasq lease file
pub fn parse_leases() -> Result<Vec<DhcpLease>> {
    let content = std::fs::read_to_string("/var/lib/dnsmasq/dnsmasq.leases")?;
    let mut leases = Vec::new();
    
    for line in content.lines() {
        // Format: expire_time mac_addr ip_addr hostname client_id
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            leases.push(DhcpLease {
                expires_at: parts[0].parse().unwrap_or(0),
                mac_address: parts[1].to_string(),
                ip_address: parts[2].to_string(),
                hostname: if parts[3] == "*" { None } else { Some(parts[3].to_string()) },
                client_id: parts.get(4).map(|s| s.to_string()),
            });
        }
    }
    
    Ok(leases)
}
```

### API Routes (`routes.rs`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dnsmasq` | Get complete dnsmasq state |
| PUT | `/api/dnsmasq/config` | Update global config |
| GET | `/api/dnsmasq/ranges` | List DHCP ranges |
| POST | `/api/dnsmasq/ranges` | Create/update DHCP range |
| DELETE | `/api/dnsmasq/ranges/:id` | Delete DHCP range |
| GET | `/api/dnsmasq/leases` | List static leases |
| POST | `/api/dnsmasq/leases` | Create/update static lease |
| DELETE | `/api/dnsmasq/leases/:id` | Delete static lease |
| GET | `/api/dnsmasq/options` | List DHCP options |
| POST | `/api/dnsmasq/options` | Create/update DHCP option |
| DELETE | `/api/dnsmasq/options/:id` | Delete DHCP option |
| GET | `/api/dnsmasq/hosts` | List host records |
| POST | `/api/dnsmasq/hosts` | Create/update host record |
| DELETE | `/api/dnsmasq/hosts/:id` | Delete host record |
| GET | `/api/dnsmasq/cnames` | List CNAME records |
| POST | `/api/dnsmasq/cnames` | Create/update CNAME |
| DELETE | `/api/dnsmasq/cnames/:id` | Delete CNAME |
| GET | `/api/dnsmasq/overrides` | List address overrides |
| POST | `/api/dnsmasq/overrides` | Create/update override |
| DELETE | `/api/dnsmasq/overrides/:id` | Delete override |
| GET | `/api/dnsmasq/active-leases` | List current active DHCP leases |
| POST | `/api/dnsmasq/apply` | Apply config and reload dnsmasq |
| GET | `/api/dnsmasq/preview` | Preview generated config file |

---

## Phase 4: Web UI

### New Pages

1. **DNS & DHCP** (`pages/dnsmasq.rs`)
   - Tabbed interface:
     - **Overview**: Status, active leases, quick stats
     - **DNS Settings**: Upstream servers, cache, local domain
     - **DHCP Ranges**: Per-interface DHCP pools
     - **Static Leases**: MAC-to-IP reservations
     - **DHCP Options**: Custom options for clients
     - **DNS Records**: Host records, CNAMEs
     - **Block Lists**: Address overrides (placeholder for later)

2. **Active Leases View**
   - Real-time table of current DHCP clients
   - One-click "Make Static" button to convert lease to reservation
   - Sortable by hostname, IP, MAC, expiry

### UI Components

- `DnsConfigForm`: Global DNS settings
- `DhcpRangeEditor`: Create/edit DHCP pools
- `StaticLeaseEditor`: Create/edit static reservations
- `DhcpOptionEditor`: Create/edit DHCP options
- `ActiveLeasesTable`: Real-time lease display

---

## Phase 5: CLI Support (keystonectl)

```bash
# Dnsmasq status
keystonectl dnsmasq status

# View active leases
keystonectl dnsmasq leases

# Quick static lease creation
keystonectl dnsmasq lease add --mac 00:11:22:33:44:55 --ip 192.168.1.100 --hostname server1

# Apply config
keystonectl dnsmasq apply

# Preview generated config
keystonectl dnsmasq preview
```

---

## Phase 6: AdGuard Home Integration (Future)

When upstream mode is `LocalAdGuard`:

1. Set `server=127.0.0.1#5353` (or configurable port)
2. Optionally disable dnsmasq caching (AdGuard has its own)
3. Documentation on configuring AdGuard Home to listen on 5353

```rust
pub struct AdGuardIntegration {
    /// AdGuard Home listening port
    pub port: u16,
    /// Whether to disable dnsmasq cache when using AdGuard
    pub disable_cache: bool,
}
```

---

## Implementation Priority

### Essential (Phase 1-2) - Core Functionality
1. Core types in `keystone-core`
2. Database schema and migrations
3. Config generation
4. Service management (apply/reload)
5. Basic API endpoints

### High Priority (Phase 3) - Usability  
1. Web UI for DHCP ranges
2. Web UI for static leases
3. Active leases display
4. Lease-to-static conversion

### Medium Priority (Phase 4) - Power User Features
1. DHCP options configuration
2. Custom DNS records (host-record, cname)
3. CLI support
4. Config preview

### Lower Priority (Phase 5) - Advanced Features
1. Address overrides (block/redirect)
2. IPv6/SLAAC configuration UI
3. AdGuard Home integration
4. DNSSEC configuration
5. Vendor class matching
6. PXE/TFTP (future)

---

## Testing Checklist

- [ ] dnsmasq config generation produces valid syntax
- [ ] `dnsmasq --test` passes for generated config
- [ ] DHCP clients receive addresses from configured pools
- [ ] Static leases work correctly
- [ ] DNS resolution works (local and upstream)
- [ ] Service reload doesn't drop existing leases
- [ ] IPv6 SLAAC works when configured
- [ ] Web UI correctly displays and edits all settings
- [ ] Migration from old DHCP server config preserves data
- [ ] Active leases are correctly parsed and displayed

---

## Files to Modify/Create

### New Files
- `core/src/dnsmasq.rs` - New types (or add to lib.rs)
- `daemon/migrations/20241230000001_dnsmasq_config.sql`
- `daemon/src/dnsmasq/mod.rs`
- `daemon/src/dnsmasq/config.rs`
- `daemon/src/dnsmasq/apply.rs`
- `daemon/src/dnsmasq/routes.rs`
- `daemon/src/dnsmasq/leases.rs`
- `web-ui/src/pages/dnsmasq.rs`
- `ctl/src/commands/dnsmasq.rs`

### Modified Files
- `core/src/lib.rs` - Remove old DHCP types, add new dnsmasq types
- `daemon/src/main.rs` - Add dnsmasq routes
- `daemon/src/networkd.rs` - Remove DHCP server generation
- `web-ui/src/pages/mod.rs` - Add dnsmasq page
- `web-ui/src/pages/interface_edit.rs` - Remove DHCP server section
- `web-ui/src/app.rs` - Add navigation
- `ctl/src/main.rs` - Add dnsmasq commands

### Files to Eventually Remove/Migrate
- `daemon/migrations/20241228000007_dhcp_server_config.sql` (migrate data first)
- `daemon/migrations/20241228000008_ipv6_ra_config.sql` (RA now via dnsmasq)
