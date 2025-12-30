-- Caddy reverse proxy configuration
-- Singleton table for global Caddy settings

CREATE TABLE IF NOT EXISTS caddy_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- Whether Caddy is enabled
    enabled INTEGER NOT NULL DEFAULT 0,
    -- Domain name or IP address for the server block (e.g., "router.lan" or "192.168.1.1")
    server_address TEXT NOT NULL DEFAULT '',
    -- LAN interface to bind to (e.g., "eth1", "br-lan")
    -- Caddy will only listen on this interface's IP address
    bind_interface TEXT NOT NULL DEFAULT '',
    -- HTTPS mode: "disabled", "self_signed", "acme_custom"
    https_mode TEXT NOT NULL DEFAULT 'disabled',
    -- Custom ACME/TLS configuration block (raw Caddyfile directives)
    -- This is inserted into the site block for custom certificate handling
    -- Example: "tls { dns cloudflare {env.CF_API_TOKEN} }"
    custom_tls_config TEXT NOT NULL DEFAULT '',
    -- Port for HTTPS (default 443)
    https_port INTEGER NOT NULL DEFAULT 443,
    -- Port for HTTP (default 80, only used for redirect if HTTPS enabled)
    http_port INTEGER NOT NULL DEFAULT 80,
    -- Last validation status (success/error message from caddy validate)
    last_validation_status TEXT,
    last_validation_time INTEGER,
    -- Timestamps
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Initialize with defaults
INSERT OR IGNORE INTO caddy_config (id, enabled) VALUES (1, 0);
