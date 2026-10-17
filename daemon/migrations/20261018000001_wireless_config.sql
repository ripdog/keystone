-- Wi-Fi access point (hostapd). The settings are a single row. It is
-- configuration: it is captured into and restored from snapshots.
CREATE TABLE IF NOT EXISTS wireless_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    -- The wireless interface hosting the access point. Not a Keystone
    -- interface: it has no networkd configuration of its own.
    interface TEXT NOT NULL DEFAULT '',
    -- A bridge_config name. Validated when saved.
    bridge TEXT NOT NULL DEFAULT '',
    ssid TEXT NOT NULL DEFAULT '',
    hidden_ssid INTEGER NOT NULL DEFAULT 0 CHECK (hidden_ssid IN (0, 1)),
    country_code TEXT NOT NULL DEFAULT '',
    channel INTEGER NOT NULL DEFAULT 6 CHECK (channel BETWEEN 1 AND 11),
    passphrase TEXT NOT NULL DEFAULT '',
    client_isolation INTEGER NOT NULL DEFAULT 0 CHECK (client_isolation IN (0, 1)),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

INSERT OR IGNORE INTO wireless_config (id) VALUES (1);

-- The access point configuration last applied. Runtime state, not
-- configuration: apply uses it to stop and clean up an access point whose
-- interface was changed or removed.
CREATE TABLE IF NOT EXISTS wireless_applied (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL,
    applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
