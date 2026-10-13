-- Forwarding between zones is governed only by zone-to-zone policies
-- (firewall_zone_forwards) and the forward chain's final drop. The per-zone
-- default forward policy was stored but never generated into nftables, so the
-- column is removed. The column has no index, constraint or foreign key, so
-- SQLite can drop it in place.
ALTER TABLE firewall_zones DROP COLUMN default_forward_policy;
