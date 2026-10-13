-- Components a snapshot was taken as applied for, as a comma list. A snapshot
-- with no components (manual, imported, pre-restore) never counts as an
-- applied baseline. Rows that predate this column were whole-configuration
-- baselines, so they default to every component.
ALTER TABLE config_snapshots
    ADD COLUMN components TEXT NOT NULL DEFAULT 'networkd,firewall,dnsmasq,caddy';
