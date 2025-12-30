-- Global application settings table
-- This is a singleton table (only one row with id=1)
CREATE TABLE IF NOT EXISTS global_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    config_changes_disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Insert default row
INSERT OR IGNORE INTO global_settings (id, config_changes_disabled) VALUES (1, 0);
