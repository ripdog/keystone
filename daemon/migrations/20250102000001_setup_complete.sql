-- Add setup_complete flag to global_settings
-- When false, the web UI will redirect all routes to /status for initial setup
ALTER TABLE global_settings ADD COLUMN setup_complete INTEGER NOT NULL DEFAULT 0;
