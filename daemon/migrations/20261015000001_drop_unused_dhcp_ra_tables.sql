-- Drop the DHCP server and IPv6 router advertisement tables. No generator, API
-- or validation step reads or writes them; they were left over from an earlier
-- design. Children are dropped before their parents. Indexes go with their tables.
DROP TABLE IF EXISTS dhcp_server_dns;
DROP TABLE IF EXISTS dhcp_server_ntp;
DROP TABLE IF EXISTS dhcp_static_leases;
DROP TABLE IF EXISTS dhcp_server_config;
DROP TABLE IF EXISTS ipv6_ra_dns;
DROP TABLE IF EXISTS ipv6_ra_search_domains;
DROP TABLE IF EXISTS ipv6_ra_prefixes;
DROP TABLE IF EXISTS ipv6_ra_config;
