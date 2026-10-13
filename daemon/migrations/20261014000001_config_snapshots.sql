-- Point-in-time copies of the router configuration, taken on every apply.
-- Snapshot files live beside the database in snapshots/; this table is only
-- their metadata index. It is never captured into or restored from a snapshot.
CREATE TABLE IF NOT EXISTS config_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('applied', 'pre_restore', 'imported', 'manual')),
    status TEXT NOT NULL CHECK (status IN ('active', 'pending_confirmation', 'rolled_back')),
    actor TEXT,
    note TEXT,
    file_name TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    -- Apply session that must be confirmed for a pending_confirmation snapshot.
    session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_config_snapshots_session ON config_snapshots(session_id);
