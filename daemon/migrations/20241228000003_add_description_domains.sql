-- Add description field to interface_config table
ALTER TABLE interface_config ADD COLUMN description TEXT;

-- Create table for search domains (multiple per interface)
CREATE TABLE IF NOT EXISTS interface_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_config_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    is_routing_domain INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_interface_domains_config ON interface_domains(interface_config_id);
