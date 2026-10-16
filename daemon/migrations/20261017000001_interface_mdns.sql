-- Per-interface multicast DNS (`<hostname>.local`). Answered by avahi-daemon,
-- which Keystone restricts to the interfaces that set this flag.
ALTER TABLE interface_config ADD COLUMN mdns BOOLEAN NOT NULL DEFAULT 0;
