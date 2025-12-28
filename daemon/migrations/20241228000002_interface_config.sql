-- Extended interface configuration schema
-- Replaces the simple managed_interfaces table with full networkd configuration support

-- Main interface configuration table
CREATE TABLE IF NOT EXISTS interface_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,  -- WAN/LAN
    enabled INTEGER NOT NULL DEFAULT 1,
    
    -- DHCP mode: no, yes, ipv4, ipv6
    dhcp_mode TEXT NOT NULL DEFAULT 'no',
    
    -- Default gateway (convenience, also stored in routes)
    gateway TEXT,
    
    -- IPv6 settings
    ipv6_accept_ra INTEGER NOT NULL DEFAULT 1,
    
    -- Forwarding & NAT modes: no, yes, ipv4, ipv6 (or 'both' for masquerade)
    ip_forward TEXT NOT NULL DEFAULT 'no',
    ip_masquerade TEXT NOT NULL DEFAULT 'no',
    
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Static IP addresses (multiple per interface)
CREATE TABLE IF NOT EXISTS interface_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    address TEXT NOT NULL,  -- CIDR notation e.g., "192.168.1.1/24"
    label TEXT,  -- Optional label (max 15 chars)
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- Static routes (multiple per interface)
CREATE TABLE IF NOT EXISTS interface_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    destination TEXT,  -- CIDR notation, NULL for default route
    gateway TEXT NOT NULL,
    metric INTEGER,  -- Route priority
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- DNS servers (multiple per interface)
CREATE TABLE IF NOT EXISTS interface_dns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    server TEXT NOT NULL,  -- IP address
    priority INTEGER NOT NULL DEFAULT 0,  -- Lower = higher priority
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- Create indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_interface_addresses_config ON interface_addresses(interface_config_id);
CREATE INDEX IF NOT EXISTS idx_interface_routes_config ON interface_routes(interface_config_id);
CREATE INDEX IF NOT EXISTS idx_interface_dns_config ON interface_dns(interface_config_id);

-- Migrate data from old managed_interfaces table if it exists
INSERT INTO interface_config (interface_name, role, enabled, dhcp_mode, gateway, created_at, updated_at)
SELECT 
    name,
    role,
    enabled,
    CASE WHEN static_ip IS NULL THEN 'ipv4' ELSE 'no' END,
    NULL,
    strftime('%s', 'now'),
    strftime('%s', 'now')
FROM managed_interfaces
WHERE NOT EXISTS (SELECT 1 FROM interface_config WHERE interface_name = managed_interfaces.name);

-- Migrate static IPs to addresses table
INSERT INTO interface_addresses (interface_config_id, address, label)
SELECT 
    ic.id,
    mi.static_ip,
    NULL
FROM managed_interfaces mi
JOIN interface_config ic ON ic.interface_name = mi.name
WHERE mi.static_ip IS NOT NULL
AND NOT EXISTS (
    SELECT 1 FROM interface_addresses ia 
    WHERE ia.interface_config_id = ic.id AND ia.address = mi.static_ip
);
