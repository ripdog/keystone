-- DHCPv6 client configuration table
CREATE TABLE IF NOT EXISTS dhcpv6_client_config (
    interface_config_id INTEGER PRIMARY KEY,
    use_dns INTEGER NOT NULL DEFAULT 1,
    use_ntp INTEGER NOT NULL DEFAULT 1,
    use_domains TEXT NOT NULL DEFAULT 'yes',  -- yes/no/route
    prefix_delegation_hint TEXT,  -- CIDR notation for PD hint
    rapid_commit INTEGER NOT NULL DEFAULT 1,
    without_ra TEXT NOT NULL DEFAULT 'no',  -- no/solicit/information-request
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);
