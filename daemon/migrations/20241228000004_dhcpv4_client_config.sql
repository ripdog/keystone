-- DHCPv4 client configuration table
CREATE TABLE IF NOT EXISTS dhcpv4_client_config (
    interface_config_id INTEGER PRIMARY KEY,
    send_hostname INTEGER NOT NULL DEFAULT 1,
    hostname TEXT,
    use_dns INTEGER NOT NULL DEFAULT 1,
    use_ntp INTEGER NOT NULL DEFAULT 1,
    use_routes INTEGER NOT NULL DEFAULT 1,
    use_gateway INTEGER NOT NULL DEFAULT 1,
    use_mtu INTEGER NOT NULL DEFAULT 1,
    use_domains TEXT NOT NULL DEFAULT 'yes',  -- yes/no/route
    route_metric INTEGER,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);
