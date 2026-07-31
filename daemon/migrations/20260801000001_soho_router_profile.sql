-- Explicit SOHO router semantics and DHCPv6 prefix delegation support.

ALTER TABLE interface_config ADD COLUMN ipv6_send_ra INTEGER NOT NULL DEFAULT 0;
ALTER TABLE interface_config ADD COLUMN dhcp_prefix_delegation_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE interface_config ADD COLUMN dhcp_prefix_delegation_uplink TEXT;
ALTER TABLE interface_config ADD COLUMN dhcp_prefix_delegation_subnet_id INTEGER;
ALTER TABLE interface_config ADD COLUMN dhcp_prefix_delegation_announce INTEGER NOT NULL DEFAULT 1;

ALTER TABLE dhcpv6_client_config ADD COLUMN use_delegated_prefix INTEGER NOT NULL DEFAULT 1;

ALTER TABLE firewall_zones ADD COLUMN is_wan INTEGER NOT NULL DEFAULT 0;
ALTER TABLE firewall_zones ADD COLUMN masquerade_ipv4 INTEGER NOT NULL DEFAULT 0;

-- Track the last confirmed ruleset independently from editable configuration.
CREATE TABLE IF NOT EXISTS firewall_active_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- A missing prior ruleset means Keystone owned no nftables tables before apply.
ALTER TABLE firewall_rollback_state ADD COLUMN previous_present INTEGER NOT NULL DEFAULT 1;

UPDATE firewall_zones
SET is_wan = 1,
    masquerade_ipv4 = 1
WHERE lower(name) = 'wan';
