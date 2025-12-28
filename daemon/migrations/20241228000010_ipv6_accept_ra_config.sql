-- Add IPv6 Accept RA client configuration table
-- Controls what information to accept from Router Advertisements

CREATE TABLE IF NOT EXISTS ipv6_accept_ra_config (
    interface_config_id INTEGER PRIMARY KEY,
    use_dns INTEGER NOT NULL DEFAULT 1,
    use_gateway INTEGER NOT NULL DEFAULT 1,
    use_route_prefix INTEGER NOT NULL DEFAULT 1,
    use_autonomous_prefix INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (interface_config_id) REFERENCES interface_config(id) ON DELETE CASCADE
);
