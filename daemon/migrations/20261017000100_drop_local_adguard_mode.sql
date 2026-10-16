-- The 'localadguard' upstream mode is removed: it only chained to 127.0.0.1#5353,
-- which Custom mode expresses with an upstream server. Convert saved settings
-- so dnsmasq keeps forwarding to the same place. Servers listed while the old
-- mode was active were ignored by it, so they are replaced, not kept.
DELETE FROM dnsmasq_upstream_servers
 WHERE EXISTS (SELECT 1 FROM dnsmasq_config WHERE upstream_mode = 'localadguard');
INSERT INTO dnsmasq_upstream_servers (address, port, domain, priority)
SELECT '127.0.0.1', 5353, NULL, 0
 WHERE EXISTS (SELECT 1 FROM dnsmasq_config WHERE upstream_mode = 'localadguard');
UPDATE dnsmasq_config SET upstream_mode = 'custom' WHERE upstream_mode = 'localadguard';
