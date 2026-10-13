-- Named address and port groups. Each group is a named set that rules
-- reference by name; generation turns them into nftables named sets.
-- Names are unique across both kinds and are enforced by the application.
CREATE TABLE IF NOT EXISTS firewall_address_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Entries are single addresses or CIDR networks (IPv4 or IPv6), kept in the
-- order they were entered.
CREATE TABLE IF NOT EXISTS firewall_address_group_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    entry TEXT NOT NULL,
    FOREIGN KEY (group_id) REFERENCES firewall_address_groups(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS firewall_port_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Entries are single ports or inclusive "start-end" ranges.
CREATE TABLE IF NOT EXISTS firewall_port_group_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    entry TEXT NOT NULL,
    FOREIGN KEY (group_id) REFERENCES firewall_port_groups(id) ON DELETE CASCADE
);

-- Group references. Deleting a group is refused while a rule uses it (see
-- the DB layer), so SET NULL only matters for rows restored out of order.
ALTER TABLE firewall_input_rules ADD COLUMN source_group_id INTEGER REFERENCES firewall_address_groups(id) ON DELETE SET NULL;
ALTER TABLE firewall_input_rules ADD COLUMN dest_port_group_id INTEGER REFERENCES firewall_port_groups(id) ON DELETE SET NULL;
ALTER TABLE firewall_forward_rules ADD COLUMN source_group_id INTEGER REFERENCES firewall_address_groups(id) ON DELETE SET NULL;
ALTER TABLE firewall_forward_rules ADD COLUMN dest_group_id INTEGER REFERENCES firewall_address_groups(id) ON DELETE SET NULL;
ALTER TABLE firewall_forward_rules ADD COLUMN dest_port_group_id INTEGER REFERENCES firewall_port_groups(id) ON DELETE SET NULL;
ALTER TABLE firewall_port_forwards ADD COLUMN source_group_id INTEGER REFERENCES firewall_address_groups(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_address_group_entries_group ON firewall_address_group_entries(group_id);
CREATE INDEX IF NOT EXISTS idx_port_group_entries_group ON firewall_port_group_entries(group_id);
