-- Rules and port forwards that target a host by its IPv6 interface-identifier
-- suffix (e.g. ::1234) instead of a full address, so they survive the ISP
-- renumbering a delegated prefix. NULL means the rule does not use a suffix.
ALTER TABLE firewall_forward_rules ADD COLUMN dest_ipv6_suffix TEXT;
ALTER TABLE firewall_port_forwards ADD COLUMN dest_ipv6_suffix TEXT;
