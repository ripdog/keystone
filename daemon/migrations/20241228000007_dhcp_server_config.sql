-- DHCP server configuration table (for LAN interfaces)
CREATE TABLE IF NOT EXISTS dhcp_server_config (
    interface_config_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    pool_offset INTEGER,
    pool_size INTEGER,
    default_lease_time_secs INTEGER,
    max_lease_time_secs INTEGER,
    emit_dns INTEGER NOT NULL DEFAULT 1,
    emit_ntp INTEGER NOT NULL DEFAULT 0,
    emit_router INTEGER NOT NULL DEFAULT 1,
    router_address TEXT,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);

-- DHCP server DNS servers to provide to clients
CREATE TABLE IF NOT EXISTS dhcp_server_dns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dhcp_server_id INTEGER NOT NULL,
    server TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (dhcp_server_id) REFERENCES dhcp_server_config(interface_config_id) ON DELETE CASCADE
);

-- DHCP server NTP servers to provide to clients
CREATE TABLE IF NOT EXISTS dhcp_server_ntp (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dhcp_server_id INTEGER NOT NULL,
    server TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (dhcp_server_id) REFERENCES dhcp_server_config(interface_config_id) ON DELETE CASCADE
);

-- DHCP static leases (MAC to IP reservations)
CREATE TABLE IF NOT EXISTS dhcp_static_leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dhcp_server_id INTEGER NOT NULL,
    mac_address TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    FOREIGN KEY (dhcp_server_id) REFERENCES dhcp_server_config(interface_config_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_dhcp_server_dns_server ON dhcp_server_dns(dhcp_server_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_server_ntp_server ON dhcp_server_ntp(dhcp_server_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_static_leases_server ON dhcp_static_leases(dhcp_server_id);
