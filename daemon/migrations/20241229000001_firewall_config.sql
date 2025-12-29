-- Zone-based firewall configuration schema
-- Implements a zone-based firewall model similar to pfSense/OpenWrt

-- Firewall zones group interfaces with common policies
CREATE TABLE IF NOT EXISTS firewall_zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    -- Default policy for incoming traffic to the router: accept, drop
    default_input_policy TEXT NOT NULL DEFAULT 'drop',
    -- Default policy for forwarded traffic from this zone: accept, drop
    default_forward_policy TEXT NOT NULL DEFAULT 'drop',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Zone-to-interface mapping (many-to-many)
CREATE TABLE IF NOT EXISTS firewall_zone_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id INTEGER NOT NULL,
    interface_name TEXT NOT NULL,
    FOREIGN KEY (zone_id) REFERENCES firewall_zones(id) ON DELETE CASCADE,
    UNIQUE(zone_id, interface_name)
);

-- Zone-to-zone forwarding policies
CREATE TABLE IF NOT EXISTS firewall_zone_forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_zone_id INTEGER NOT NULL,
    dest_zone_id INTEGER NOT NULL,
    -- Policy: accept, drop, reject
    policy TEXT NOT NULL DEFAULT 'drop',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (source_zone_id) REFERENCES firewall_zones(id) ON DELETE CASCADE,
    FOREIGN KEY (dest_zone_id) REFERENCES firewall_zones(id) ON DELETE CASCADE,
    UNIQUE(source_zone_id, dest_zone_id)
);

-- Port forwarding (DNAT) rules
CREATE TABLE IF NOT EXISTS firewall_port_forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- Protocol: any, tcp, udp, tcp+udp
    protocol TEXT NOT NULL DEFAULT 'tcp',
    -- Source zone ID (NULL = any incoming interface)
    source_zone_id INTEGER,
    -- External port range
    external_port_start INTEGER NOT NULL,
    external_port_end INTEGER,
    -- Source IP restriction (CIDR, NULL = any)
    source_ip TEXT,
    -- Internal destination
    dest_ip TEXT NOT NULL,
    dest_port INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (source_zone_id) REFERENCES firewall_zones(id) ON DELETE SET NULL
);

-- Input rules (traffic TO the router)
CREATE TABLE IF NOT EXISTS firewall_input_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- Position for ordering (lower = evaluated first)
    position INTEGER NOT NULL DEFAULT 0,
    -- Source zone ID (NULL = any)
    zone_id INTEGER,
    -- Protocol: any, tcp, udp, tcp+udp, icmp, icmpv6
    protocol TEXT,
    -- Port range (NULL = any)
    port_start INTEGER,
    port_end INTEGER,
    -- Source IP restriction (CIDR, NULL = any)
    source_ip TEXT,
    -- Action: accept, drop, reject
    action TEXT NOT NULL DEFAULT 'accept',
    -- Logging
    log_enabled INTEGER NOT NULL DEFAULT 0,
    log_prefix TEXT,
    -- Rate limiting (e.g., "10/minute")
    rate_limit TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (zone_id) REFERENCES firewall_zones(id) ON DELETE SET NULL
);

-- Forward rules (traffic THROUGH the router)
CREATE TABLE IF NOT EXISTS firewall_forward_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- Position for ordering
    position INTEGER NOT NULL DEFAULT 0,
    -- Source zone ID (NULL = any)
    source_zone_id INTEGER,
    -- Destination zone ID (NULL = any)
    dest_zone_id INTEGER,
    -- Protocol: any, tcp, udp, tcp+udp, icmp, icmpv6
    protocol TEXT,
    -- Destination port range
    dest_port_start INTEGER,
    dest_port_end INTEGER,
    -- Source IP (CIDR, NULL = any)
    source_ip TEXT,
    -- Destination IP (CIDR, NULL = any)
    dest_ip TEXT,
    -- Action: accept, drop, reject
    action TEXT NOT NULL DEFAULT 'accept',
    -- Logging
    log_enabled INTEGER NOT NULL DEFAULT 0,
    log_prefix TEXT,
    -- Rate limiting
    rate_limit TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (source_zone_id) REFERENCES firewall_zones(id) ON DELETE SET NULL,
    FOREIGN KEY (dest_zone_id) REFERENCES firewall_zones(id) ON DELETE SET NULL
);

-- Rollback state for safe apply with confirmation
CREATE TABLE IF NOT EXISTS firewall_rollback_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Only one row allowed
    -- JSON blob of previous FirewallConfig
    previous_config TEXT NOT NULL,
    -- Timestamp when rollback will occur if not confirmed
    rollback_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

-- Indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_zone_interfaces_zone ON firewall_zone_interfaces(zone_id);
CREATE INDEX IF NOT EXISTS idx_zone_interfaces_name ON firewall_zone_interfaces(interface_name);
CREATE INDEX IF NOT EXISTS idx_zone_forwards_source ON firewall_zone_forwards(source_zone_id);
CREATE INDEX IF NOT EXISTS idx_zone_forwards_dest ON firewall_zone_forwards(dest_zone_id);
CREATE INDEX IF NOT EXISTS idx_port_forwards_zone ON firewall_port_forwards(source_zone_id);
CREATE INDEX IF NOT EXISTS idx_input_rules_zone ON firewall_input_rules(zone_id);
CREATE INDEX IF NOT EXISTS idx_input_rules_position ON firewall_input_rules(position);
CREATE INDEX IF NOT EXISTS idx_forward_rules_source ON firewall_forward_rules(source_zone_id);
CREATE INDEX IF NOT EXISTS idx_forward_rules_dest ON firewall_forward_rules(dest_zone_id);
CREATE INDEX IF NOT EXISTS idx_forward_rules_position ON firewall_forward_rules(position);

-- Create default zones: WAN (external) and LAN (internal)
INSERT INTO firewall_zones (name, description, default_input_policy, default_forward_policy, created_at, updated_at)
VALUES 
    ('wan', 'External/Internet-facing zone', 'drop', 'drop', strftime('%s', 'now'), strftime('%s', 'now')),
    ('lan', 'Internal/trusted network zone', 'accept', 'accept', strftime('%s', 'now'), strftime('%s', 'now'));

-- Enable forwarding from LAN to WAN by default (allows LAN clients to reach internet)
INSERT INTO firewall_zone_forwards (source_zone_id, dest_zone_id, policy, enabled, created_at, updated_at)
SELECT 
    (SELECT id FROM firewall_zones WHERE name = 'lan'),
    (SELECT id FROM firewall_zones WHERE name = 'wan'),
    'accept',
    1,
    strftime('%s', 'now'),
    strftime('%s', 'now');

-- Create default input rules for essential services
-- Allow ICMP ping from LAN
INSERT INTO firewall_input_rules (name, description, enabled, position, zone_id, protocol, action, created_at, updated_at)
SELECT 
    'Allow ICMP from LAN',
    'Allow ping and ICMP from LAN zone',
    1,
    100,
    (SELECT id FROM firewall_zones WHERE name = 'lan'),
    'icmp',
    'accept',
    strftime('%s', 'now'),
    strftime('%s', 'now');

-- Allow DHCPv4 server from LAN (ports 67-68)
INSERT INTO firewall_input_rules (name, description, enabled, position, zone_id, protocol, port_start, port_end, action, created_at, updated_at)
SELECT 
    'Allow DHCP from LAN',
    'Allow DHCPv4 requests from LAN zone',
    1,
    110,
    (SELECT id FROM firewall_zones WHERE name = 'lan'),
    'udp',
    67,
    68,
    'accept',
    strftime('%s', 'now'),
    strftime('%s', 'now');

-- Allow DNS from LAN (port 53)
INSERT INTO firewall_input_rules (name, description, enabled, position, zone_id, protocol, port_start, action, created_at, updated_at)
SELECT 
    'Allow DNS from LAN',
    'Allow DNS queries from LAN zone',
    1,
    120,
    (SELECT id FROM firewall_zones WHERE name = 'lan'),
    'tcp+udp',
    53,
    'accept',
    strftime('%s', 'now'),
    strftime('%s', 'now');

-- Allow SSH from LAN (port 22) - for management
INSERT INTO firewall_input_rules (name, description, enabled, position, zone_id, protocol, port_start, action, created_at, updated_at)
SELECT 
    'Allow SSH from LAN',
    'Allow SSH management from LAN zone',
    1,
    130,
    (SELECT id FROM firewall_zones WHERE name = 'lan'),
    'tcp',
    22,
    'accept',
    strftime('%s', 'now'),
    strftime('%s', 'now');

-- Allow Web UI from LAN (port 8080)
INSERT INTO firewall_input_rules (name, description, enabled, position, zone_id, protocol, port_start, action, created_at, updated_at)
SELECT 
    'Allow Web UI from LAN',
    'Allow Keystone Web UI access from LAN zone',
    1,
    140,
    (SELECT id FROM firewall_zones WHERE name = 'lan'),
    'tcp',
    8080,
    'accept',
    strftime('%s', 'now'),
    strftime('%s', 'now');
