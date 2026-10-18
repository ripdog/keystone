-- Verbosity of the daemon's logs, changeable at runtime from the web UI.
ALTER TABLE global_settings ADD COLUMN log_level TEXT NOT NULL DEFAULT 'info'
    CHECK (log_level IN ('error', 'warn', 'info', 'debug', 'trace'));
