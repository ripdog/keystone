-- Dnsmasq DNS/DHCP server configuration schema
-- Replaces the old systemd-networkd DHCP server functionality

-- Dnsmasq global configuration (singleton)
CREATE TABLE IF NOT EXISTS dnsmasq_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 1,
    dns_port INTEGER NOT NULL DEFAULT 53,
    cache_size INTEGER NOT NULL DEFAULT 1000,
    dnssec_enabled INTEGER NOT NULL DEFAULT 0,
    domain_needed INTEGER NOT NULL DEFAULT 1,
    bogus_priv INTEGER NOT NULL DEFAULT 1,
    local_domain TEXT DEFAULT 'lan',
    expand_hosts INTEGER NOT NULL DEFAULT 1,
    -- Upstream mode: 'system', 'custom', 'localadguard'
    upstream_mode TEXT NOT NULL DEFAULT 'system',
    bind_dynamic INTEGER NOT NULL DEFAULT 1,
    log_queries INTEGER NOT NULL DEFAULT 0,
    log_dhcp INTEGER NOT NULL DEFAULT 0
);

-- Initialize with defaults
INSERT OR IGNORE INTO dnsmasq_config (id, enabled, local_domain) VALUES (1, 1, 'lan');

-- Dnsmasq listen interfaces (which interfaces to bind to)
CREATE TABLE IF NOT EXISTS dnsmasq_listen_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE
);

-- Dnsmasq except interfaces (which interfaces to exclude)
CREATE TABLE IF NOT EXISTS dnsmasq_except_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE
);

-- Dnsmasq no-dhcp interfaces (DNS only, no DHCP on these interfaces)
CREATE TABLE IF NOT EXISTS dnsmasq_no_dhcp_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE
);

-- Upstream DNS servers (for 'custom' mode)
CREATE TABLE IF NOT EXISTS dnsmasq_upstream_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    port INTEGER,
    -- Optional: only use this server for specific domain
    domain TEXT,
    -- Priority for ordering (lower = higher priority)
    priority INTEGER NOT NULL DEFAULT 0
);

-- DHCP ranges/pools
CREATE TABLE IF NOT EXISTS dnsmasq_dhcp_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    interface TEXT NOT NULL,
    start_address TEXT NOT NULL,
    end_address TEXT NOT NULL,
    netmask TEXT,
    lease_time TEXT NOT NULL DEFAULT '24h',
    enabled INTEGER NOT NULL DEFAULT 1,
    -- IPv6 mode: 'ra-only', 'ra-stateless', 'slaac', 'dhcpv6'
    ipv6_mode TEXT,
    ipv6_prefix TEXT
);

-- Static DHCP leases/reservations
CREATE TABLE IF NOT EXISTS dnsmasq_static_leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    lease_time TEXT,
    client_id TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- Tags for static leases (many-to-many relationship)
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
    -- Option number or name (e.g., '3' or 'router', '6' or 'dns-server')
    option TEXT NOT NULL,
    value TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- Is this an IPv6 option (option6:)
    ipv6 INTEGER NOT NULL DEFAULT 0,
    -- Force send even if client didn't request it
    force_send INTEGER NOT NULL DEFAULT 0
);

-- Tags for DHCP options (many-to-many - options apply to clients with matching tags)
CREATE TABLE IF NOT EXISTS dnsmasq_dhcp_option_tags (
    option_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (option_id, tag),
    FOREIGN KEY (option_id) REFERENCES dnsmasq_dhcp_options(id) ON DELETE CASCADE
);

-- Custom DNS host records (A/AAAA)
CREATE TABLE IF NOT EXISTS dnsmasq_host_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ipv4_address TEXT,
    ipv6_address TEXT,
    ttl INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- Hostnames for host records (one host record can have multiple hostnames)
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
    -- Action: 'block' (NXDOMAIN), 'redirect', 'null' (0.0.0.0)
    action TEXT NOT NULL DEFAULT 'block',
    -- Redirect address (when action is 'redirect')
    redirect_address TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- Indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_dhcp_ranges_interface ON dnsmasq_dhcp_ranges(interface);
CREATE INDEX IF NOT EXISTS idx_dhcp_ranges_enabled ON dnsmasq_dhcp_ranges(enabled);
CREATE INDEX IF NOT EXISTS idx_static_leases_mac ON dnsmasq_static_leases(mac_address);
CREATE INDEX IF NOT EXISTS idx_static_leases_ip ON dnsmasq_static_leases(ip_address);
CREATE INDEX IF NOT EXISTS idx_static_leases_enabled ON dnsmasq_static_leases(enabled);
CREATE INDEX IF NOT EXISTS idx_host_record_names_record ON dnsmasq_host_record_names(record_id);
CREATE INDEX IF NOT EXISTS idx_host_record_names_hostname ON dnsmasq_host_record_names(hostname);
CREATE INDEX IF NOT EXISTS idx_cname_records_alias ON dnsmasq_cname_records(alias);
CREATE INDEX IF NOT EXISTS idx_address_overrides_domain ON dnsmasq_address_overrides(domain);
CREATE INDEX IF NOT EXISTS idx_upstream_servers_priority ON dnsmasq_upstream_servers(priority);
