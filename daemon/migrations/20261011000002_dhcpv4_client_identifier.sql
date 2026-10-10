-- Retain DHCPv4 option 61 identity; some IPoE providers authorise traffic by client ID.
-- NULL keeps the systemd-networkd default for existing interface configurations.
ALTER TABLE dhcpv4_client_config ADD COLUMN client_identifier TEXT
    CHECK (client_identifier IN ('duid', 'mac') OR client_identifier IS NULL);
