-- Bridge configuration table
-- Bridges create virtual switches that combine multiple interfaces

CREATE TABLE IF NOT EXISTS bridge_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Bridge interface name (e.g., "br0", "bridge-lan")
    name TEXT NOT NULL UNIQUE,
    -- Member interfaces (JSON array of strings, e.g., ["eth1", "eth2"])
    members TEXT NOT NULL DEFAULT '[]',
    -- Enable Spanning Tree Protocol
    stp INTEGER NOT NULL DEFAULT 0,
    -- STP forward delay in seconds (2-30, default 15)
    stp_forward_delay INTEGER NOT NULL DEFAULT 15 CHECK (stp_forward_delay >= 2 AND stp_forward_delay <= 30),
    -- Optional description
    description TEXT,
    -- Foreign key to interface_config for the bridge's network settings
    -- This is optional - the bridge netdev can exist without network config
    interface_config_id INTEGER,
    -- Timestamps
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    -- Constraints
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE SET NULL
);

-- Index for fast lookups by name
CREATE INDEX IF NOT EXISTS idx_bridge_name ON bridge_config(name);
