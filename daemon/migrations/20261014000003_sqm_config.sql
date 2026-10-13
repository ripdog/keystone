-- Traffic shaping (SQM / CAKE) on the WAN link. A single row of configuration;
-- it is captured into and restored from configuration snapshots.
CREATE TABLE IF NOT EXISTS sqm_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    -- WAN interface whose traffic is shaped. Validated against interface_config.
    interface TEXT NOT NULL DEFAULT '',
    -- Shaper rates in kbit/s; 0 leaves that direction unshaped.
    download_kbit INTEGER NOT NULL DEFAULT 0 CHECK (download_kbit >= 0),
    upload_kbit INTEGER NOT NULL DEFAULT 0 CHECK (upload_kbit >= 0),
    link_preset TEXT NOT NULL DEFAULT 'ethernet'
        CHECK (link_preset IN ('none', 'ethernet', 'docsis', 'pppoe-ptm', 'bridged-ptm', 'pppoe-vcmux')),
    -- Custom overhead and minimum packet unit; NULL keeps the preset's values.
    overhead INTEGER CHECK (overhead IS NULL OR overhead BETWEEN -64 AND 256),
    mpu INTEGER CHECK (mpu IS NULL OR mpu BETWEEN 0 AND 256),
    diffserv TEXT NOT NULL DEFAULT 'diffserv4'
        CHECK (diffserv IN ('besteffort', 'diffserv3', 'diffserv4', 'diffserv8')),
    isolation TEXT NOT NULL DEFAULT 'dual'
        CHECK (isolation IN ('dual', 'triflow', 'flows', 'hosts')),
    nat INTEGER NOT NULL DEFAULT 1 CHECK (nat IN (0, 1)),
    ack_filter INTEGER NOT NULL DEFAULT 0 CHECK (ack_filter IN (0, 1)),
    wash INTEGER NOT NULL DEFAULT 0 CHECK (wash IN (0, 1)),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

INSERT OR IGNORE INTO sqm_config (id) VALUES (1);

-- The configuration last applied to the system, as JSON. This is runtime state
-- rather than configuration: the reconciler re-applies it after a reboot or a
-- WAN link flap, and it is never captured into or restored from a snapshot.
CREATE TABLE IF NOT EXISTS sqm_applied (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL,
    applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
