-- UPnP IGD and NAT-PMP / PCP port mapping (miniupnpd). The settings are a
-- single row; the interface and subnet lists are child tables. All of these
-- are configuration: they are captured into and restored from snapshots.
CREATE TABLE IF NOT EXISTS upnp_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    -- Validated against WAN-role interfaces when saved.
    wan_interface TEXT NOT NULL DEFAULT '',
    enable_igd INTEGER NOT NULL DEFAULT 1 CHECK (enable_igd IN (0, 1)),
    enable_natpmp_pcp INTEGER NOT NULL DEFAULT 1 CHECK (enable_natpmp_pcp IN (0, 1)),
    secure_mode INTEGER NOT NULL DEFAULT 1 CHECK (secure_mode IN (0, 1)),
    external_port_min INTEGER NOT NULL DEFAULT 1024 CHECK (external_port_min BETWEEN 0 AND 65535),
    external_port_max INTEGER NOT NULL DEFAULT 65535 CHECK (external_port_max BETWEEN 0 AND 65535),
    internal_port_min INTEGER NOT NULL DEFAULT 1024 CHECK (internal_port_min BETWEEN 0 AND 65535),
    internal_port_max INTEGER NOT NULL DEFAULT 65535 CHECK (internal_port_max BETWEEN 0 AND 65535),
    max_lease_secs INTEGER NOT NULL DEFAULT 86400 CHECK (max_lease_secs BETWEEN 0 AND 86400),
    friendly_name TEXT NOT NULL DEFAULT 'Keystone router',
    notify_interval_secs INTEGER NOT NULL DEFAULT 900 CHECK (notify_interval_secs BETWEEN 0 AND 86400),
    system_uptime INTEGER NOT NULL DEFAULT 1 CHECK (system_uptime IN (0, 1)),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

INSERT OR IGNORE INTO upnp_config (id) VALUES (1);

-- LAN-role interfaces whose clients may request mappings.
CREATE TABLE IF NOT EXISTS upnp_lan_interfaces (
    interface TEXT PRIMARY KEY
);

-- Client subnets (a.b.c.d/nn) allowed to create mappings. Empty means the
-- subnets of the selected LAN interfaces.
CREATE TABLE IF NOT EXISTS upnp_allowed_subnets (
    subnet TEXT PRIMARY KEY
);

-- The UPnP configuration last applied. Runtime state, not configuration: the
-- reconciler uses it to recreate the nftables table after a reboot.
CREATE TABLE IF NOT EXISTS upnp_applied (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL,
    applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
