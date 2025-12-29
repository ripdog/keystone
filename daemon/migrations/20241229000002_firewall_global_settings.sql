-- Global firewall settings
-- These are singleton settings that apply to the entire firewall

CREATE TABLE IF NOT EXISTS firewall_global_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Only one row allowed
    
    -- ICMP settings
    -- Allow responding to ping requests (echo-request -> echo-reply)
    -- Dangerous ICMP types are always blocked: timestamp, redirect, address-mask
    ping_wan_enabled INTEGER NOT NULL DEFAULT 0,  -- Respond to ping from WAN
    ping_lan_enabled INTEGER NOT NULL DEFAULT 1,  -- Respond to ping from LAN (usually wanted)
    
    -- Hairpin NAT (NAT reflection)
    -- Allows LAN clients to access port-forwarded services using the external IP
    hairpin_nat_enabled INTEGER NOT NULL DEFAULT 1,
    
    updated_at INTEGER NOT NULL
);

-- Insert default settings
INSERT INTO firewall_global_settings (id, ping_wan_enabled, ping_lan_enabled, hairpin_nat_enabled, updated_at)
VALUES (1, 0, 1, 1, strftime('%s', 'now'));
