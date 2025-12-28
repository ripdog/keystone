-- Add MTU (Maximum Transmission Unit) column to interface_config
-- Common values: 1500 (default), 1492 (PPPoE), 9000 (jumbo frames)

ALTER TABLE interface_config ADD COLUMN mtu INTEGER;
