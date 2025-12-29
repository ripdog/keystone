-- VLAN configuration table
-- VLANs create virtual interfaces on top of physical interfaces

CREATE TABLE IF NOT EXISTS vlan_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- VLAN interface name (e.g., "vlan10", "eth0.10")
    name TEXT NOT NULL UNIQUE,
    -- Parent interface name (e.g., "eth0", "enp3s0")  
    parent_interface TEXT NOT NULL,
    -- VLAN ID (1-4094)
    vlan_id INTEGER NOT NULL CHECK (vlan_id >= 1 AND vlan_id <= 4094),
    -- Protocol: "802.1q" (standard) or "802.1ad" (QinQ)
    protocol TEXT NOT NULL DEFAULT '802.1q',
    -- Optional description
    description TEXT,
    -- Foreign key to interface_config for the VLAN's network settings
    -- This is optional - the VLAN netdev can exist without network config
    interface_config_id INTEGER,
    -- Timestamps
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    -- Constraints
    UNIQUE(parent_interface, vlan_id),
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE SET NULL
);

-- Index for fast lookups by parent interface
CREATE INDEX IF NOT EXISTS idx_vlan_parent ON vlan_config(parent_interface);
