-- Add IPv6 Router Advertisement configuration tables
-- For LAN interfaces that need to act as IPv6 gateways

-- Main IPv6 RA configuration
CREATE TABLE IF NOT EXISTS ipv6_ra_config (
    interface_config_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    router_lifetime_secs INTEGER,
    router_preference TEXT,  -- low/medium/high
    managed INTEGER NOT NULL DEFAULT 0,  -- M flag (use DHCPv6 for addresses)
    other_information INTEGER NOT NULL DEFAULT 0,  -- O flag (use DHCPv6 for other config)
    emit_dns INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (interface_config_id) REFERENCES interface_configs(id) ON DELETE CASCADE
);

-- DNS servers to advertise in RA (RDNSS)
CREATE TABLE IF NOT EXISTS ipv6_ra_dns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ipv6_ra_config_id INTEGER NOT NULL,
    server TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (ipv6_ra_config_id) REFERENCES ipv6_ra_config(interface_config_id) ON DELETE CASCADE
);

-- DNS search domains to advertise in RA (DNSSL)
CREATE TABLE IF NOT EXISTS ipv6_ra_search_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ipv6_ra_config_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (ipv6_ra_config_id) REFERENCES ipv6_ra_config(interface_config_id) ON DELETE CASCADE
);

-- IPv6 prefixes to advertise
CREATE TABLE IF NOT EXISTS ipv6_ra_prefixes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ipv6_ra_config_id INTEGER NOT NULL,
    prefix TEXT NOT NULL,  -- CIDR notation, e.g., "2001:db8::/64"
    preferred_lifetime_secs INTEGER,  -- NULL = infinite
    valid_lifetime_secs INTEGER,  -- NULL = infinite
    on_link INTEGER NOT NULL DEFAULT 1,
    autonomous INTEGER NOT NULL DEFAULT 1,  -- Use for SLAAC
    FOREIGN KEY (ipv6_ra_config_id) REFERENCES ipv6_ra_config(interface_config_id) ON DELETE CASCADE
);
