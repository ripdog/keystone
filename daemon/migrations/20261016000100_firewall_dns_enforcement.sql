-- Enforcing the router's DNS server for LAN clients. Both settings apply to
-- traffic arriving on non-WAN zone interfaces and addressed to outside hosts:
-- plain DNS (port 53) is redirected to the router, and DNS-over-TLS / QUIC
-- (port 853) is rejected. Members of the exempt address group are left alone.
ALTER TABLE firewall_global_settings ADD COLUMN force_local_dns INTEGER NOT NULL DEFAULT 0 CHECK (force_local_dns IN (0, 1));
ALTER TABLE firewall_global_settings ADD COLUMN block_dns_over_tls INTEGER NOT NULL DEFAULT 0 CHECK (block_dns_over_tls IN (0, 1));
-- Deleting the group is refused while it is referenced (see the DB layer), so
-- SET NULL only matters for rows restored out of order.
ALTER TABLE firewall_global_settings ADD COLUMN dns_exempt_group_id INTEGER REFERENCES firewall_address_groups(id) ON DELETE SET NULL;
