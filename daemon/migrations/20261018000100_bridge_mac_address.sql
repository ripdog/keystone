-- Optional MAC address for a bridge. A bridge that takes over a LAN port's
-- addresses keeps that port's MAC, so clients' ARP caches stay valid when the
-- address moves to the bridge. NULL lets the kernel/networkd choose.
ALTER TABLE bridge_config ADD COLUMN mac_address TEXT;
