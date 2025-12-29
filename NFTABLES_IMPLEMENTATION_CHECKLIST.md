# nftables Firewall Implementation Checklist for Keystone

This document provides a comprehensive implementation plan for nftables firewall support in Keystone, using the `nftables` Rust crate (v0.6.x) for safe abstraction over the nftables JSON API.

**Reference**: `man nft`, `nftables` crate docs, libnftables-json(5)

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Address family | `inet` (dual-stack) | Single ruleset for IPv4/IPv6, modern best practice |
| Firewall model | Zone-based (like pfSense/OpenWrt) | Intuitive for home users, groups interfaces logically |
| Rule evaluation | Priority groups | Built-in rules first, then user rules, then zone defaults |
| Table ownership | Dedicated `keystone` table | Never touches other tables, safe flush/reload |
| Apply strategy | Atomic replacement | Flush and recreate entire table atomically |
| Rollback timer | 60 seconds | Prevents lockouts from bad rules |
| MSS clamping | Automatic on WAN (route MTU based) | Prevents MTU black holes for PPPoE/VPN |

---

## Rule Evaluation Order (Priority Groups)

### Input Chain (base policy: `drop`)

| Priority | Description | User Editable |
|----------|-------------|---------------|
| 1 | `ct state established,related accept` | No |
| 2 | `ct state invalid drop` | No |
| 3 | `iif lo accept` (loopback) | No |
| 4 | **User Input Rules** (position-ordered) | Yes |
| 5 | Zone default policies (fallback) | Via zone config |

### Forward Chain (base policy: `drop`)

| Priority | Description | User Editable |
|----------|-------------|---------------|
| 1 | `ct state established,related accept` | No |
| 2 | `ct state invalid drop` | No |
| 3 | **User Forward Rules** (position-ordered) | Yes |
| 4 | Zone-to-Zone Policies (lan→wan, etc.) | Via zone forwards |
| 5 | Zone default policies (fallback) | Via zone config |

### Output Chain (base policy: `accept`)

| Priority | Description | User Editable |
|----------|-------------|---------------|
| 1 | `accept` (permissive by default) | No (for now) |

### NAT Chains

- **Prerouting (dstnat)**: Port forwards (DNAT)
- **Postrouting (srcnat)**: Masquerade for WAN interfaces + MSS clamping

---

## Implementation Phases

### Phase 1: Foundation

| Task | File | Status |
|------|------|--------|
| Add `nftables` crate dependency | `daemon/Cargo.toml` | ⬜ TODO |
| Add firewall types to core | `core/src/lib.rs` | ⬜ TODO |
| Remove legacy `FirewallRule` type | `core/src/lib.rs` | ⬜ TODO |
| Create firewall database migration | `daemon/migrations/20241229000001_firewall_config.sql` | ⬜ TODO |
| Create firewall module structure | `daemon/src/firewall/mod.rs` | ⬜ TODO |
| Implement zone CRUD | `daemon/src/firewall/db.rs` | ⬜ TODO |
| Implement zone-forward CRUD | `daemon/src/firewall/db.rs` | ⬜ TODO |
| Implement port-forward CRUD | `daemon/src/firewall/db.rs` | ⬜ TODO |
| Implement input-rule CRUD | `daemon/src/firewall/db.rs` | ⬜ TODO |
| Implement forward-rule CRUD | `daemon/src/firewall/db.rs` | ⬜ TODO |
| Implement rule reordering | `daemon/src/firewall/db.rs` | ⬜ TODO |

### Phase 2: Ruleset Generation

| Task | File | Status |
|------|------|--------|
| Create nftables generation module | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate filter table structure | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate input chain (built-in rules) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate input chain (user rules) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate input chain (zone defaults) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate forward chain (built-in rules) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate forward chain (user rules) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate forward chain (zone-to-zone) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate output chain | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate NAT table structure | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate prerouting chain (port forwards) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate postrouting chain (masquerade) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate MSS clamping rules (WAN only) | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Implement rate limiting in rules | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Implement logging in rules | `daemon/src/firewall/generate.rs` | ⬜ TODO |
| Generate ruleset preview (text format) | `daemon/src/firewall/generate.rs` | ⬜ TODO |

### Phase 3: Apply/Confirm/Rollback Logic

| Task | File | Status |
|------|------|--------|
| Create apply module | `daemon/src/firewall/apply.rs` | ⬜ TODO |
| Implement save current ruleset for rollback | `daemon/src/firewall/apply.rs` | ⬜ TODO |
| Implement atomic ruleset application | `daemon/src/firewall/apply.rs` | ⬜ TODO |
| Implement 60-second rollback timer | `daemon/src/firewall/apply.rs` | ⬜ TODO |
| Implement confirm endpoint logic | `daemon/src/firewall/apply.rs` | ⬜ TODO |
| Implement manual rollback | `daemon/src/firewall/apply.rs` | ⬜ TODO |
| Implement status check (pending confirmation) | `daemon/src/firewall/apply.rs` | ⬜ TODO |
| Handle timer expiration (auto-rollback) | `daemon/src/firewall/apply.rs` | ⬜ TODO |

### Phase 4: API Routes

| Task | File | Status |
|------|------|--------|
| Create routes module | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `GET /firewall/zones` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/zones` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `DELETE /firewall/zones/:id` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `GET /firewall/zone-forwards` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/zone-forwards` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `DELETE /firewall/zone-forwards/:id` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `GET /firewall/port-forwards` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/port-forwards` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `DELETE /firewall/port-forwards/:id` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `GET /firewall/input-rules` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/input-rules` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `DELETE /firewall/input-rules/:id` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/input-rules/reorder` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `GET /firewall/forward-rules` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/forward-rules` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `DELETE /firewall/forward-rules/:id` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/forward-rules/reorder` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `GET /firewall/preview` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/apply` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/confirm` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `POST /firewall/rollback` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| `GET /firewall/status` | `daemon/src/firewall/routes.rs` | ⬜ TODO |
| Register firewall routes in main | `daemon/src/main.rs` | ⬜ TODO |
| Add zone deletion protection | `daemon/src/firewall/routes.rs` | ⬜ TODO |

### Phase 5: Web UI

| Task | File | Status |
|------|------|--------|
| Add firewall API functions | `web-ui/src/api.rs` | ⬜ TODO |
| Rewrite firewall page with tabs | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement Zones tab | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement zone edit modal | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement Port Forwards tab | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement port forward edit modal | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement Rules tab (input + forward) | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement rule edit modal | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement rule drag-and-drop reordering | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement zone-to-zone forward matrix | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement preview button/modal | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement apply button with countdown | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Implement confirm/rollback UI | `web-ui/src/pages/firewall.rs` | ⬜ TODO |
| Update page exports | `web-ui/src/pages/mod.rs` | ⬜ TODO |

### Phase 6: CLI (keystonectl)

| Task | File | Status |
|------|------|--------|
| Add `firewall` subcommand | `ctl/src/main.rs` | ⬜ TODO |
| `firewall zones list` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall zones create` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall zones delete` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall port-forwards list` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall port-forwards create` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall port-forwards delete` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall rules list` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall preview` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall apply` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall confirm` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall rollback` | `ctl/src/main.rs` | ⬜ TODO |
| `firewall status` | `ctl/src/main.rs` | ⬜ TODO |

---

## Database Schema

### Migration: `20241229000001_firewall_config.sql`

```sql
-- ============================================================================
-- Firewall Zones
-- ============================================================================

CREATE TABLE firewall_zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    default_input_policy TEXT NOT NULL DEFAULT 'drop',    -- 'accept' or 'drop'
    default_forward_policy TEXT NOT NULL DEFAULT 'drop',
    created_at INTEGER NOT NULL
);

-- Zone-to-interface mapping
CREATE TABLE firewall_zone_interfaces (
    zone_id INTEGER NOT NULL REFERENCES firewall_zones(id) ON DELETE CASCADE,
    interface_name TEXT NOT NULL,
    PRIMARY KEY (zone_id, interface_name)
);

-- Index for reverse lookup (interface → zone)
CREATE INDEX idx_zone_interfaces_name ON firewall_zone_interfaces(interface_name);

-- ============================================================================
-- Zone-to-Zone Forwarding Policies
-- ============================================================================

CREATE TABLE firewall_zone_forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_zone_id INTEGER NOT NULL REFERENCES firewall_zones(id) ON DELETE CASCADE,
    dest_zone_id INTEGER NOT NULL REFERENCES firewall_zones(id) ON DELETE CASCADE,
    policy TEXT NOT NULL DEFAULT 'drop',   -- 'accept', 'drop', 'reject'
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(source_zone_id, dest_zone_id)
);

-- ============================================================================
-- Port Forwards (DNAT)
-- ============================================================================

CREATE TABLE firewall_port_forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- Match criteria
    protocol TEXT NOT NULL,                -- 'tcp', 'udp', 'tcp+udp'
    source_zone_id INTEGER REFERENCES firewall_zones(id) ON DELETE SET NULL,
    external_port_start INTEGER NOT NULL,
    external_port_end INTEGER,             -- NULL = single port
    source_ip TEXT,                        -- CIDR restriction, NULL = any
    -- Destination
    dest_ip TEXT NOT NULL,
    dest_port INTEGER,                     -- NULL = same as external
    -- Metadata
    created_at INTEGER NOT NULL
);

-- ============================================================================
-- Input Rules (access to router itself)
-- ============================================================================

CREATE TABLE firewall_input_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL,             -- ordering within input rules
    -- Match criteria
    zone_id INTEGER REFERENCES firewall_zones(id) ON DELETE SET NULL,
    protocol TEXT,                         -- 'tcp', 'udp', 'icmp', 'icmpv6', NULL = any
    port_start INTEGER,
    port_end INTEGER,                      -- NULL = single port
    source_ip TEXT,                        -- CIDR, NULL = any
    -- Action
    action TEXT NOT NULL,                  -- 'accept', 'drop', 'reject'
    -- Optional features
    log_enabled INTEGER NOT NULL DEFAULT 0,
    log_prefix TEXT,
    rate_limit TEXT,                       -- e.g., '10/minute', NULL = no limit
    -- Metadata
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_input_rules_position ON firewall_input_rules(position);

-- ============================================================================
-- Forward Rules (traffic between zones, beyond zone policies)
-- ============================================================================

CREATE TABLE firewall_forward_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL,
    -- Match criteria
    source_zone_id INTEGER REFERENCES firewall_zones(id) ON DELETE SET NULL,
    dest_zone_id INTEGER REFERENCES firewall_zones(id) ON DELETE SET NULL,
    protocol TEXT,
    dest_port_start INTEGER,
    dest_port_end INTEGER,
    source_ip TEXT,
    dest_ip TEXT,
    -- Action
    action TEXT NOT NULL,
    -- Optional features
    log_enabled INTEGER NOT NULL DEFAULT 0,
    log_prefix TEXT,
    rate_limit TEXT,
    -- Metadata
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_forward_rules_position ON firewall_forward_rules(position);

-- ============================================================================
-- Rollback State (for apply/confirm/rollback flow)
-- ============================================================================

CREATE TABLE firewall_rollback_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton
    previous_ruleset_json TEXT NOT NULL,    -- serialized FirewallConfig
    pending_until INTEGER,                  -- Unix timestamp, NULL = no pending
    session_id TEXT                         -- for confirmation matching
);

-- Initialize with empty state
INSERT INTO firewall_rollback_state (id, previous_ruleset_json, pending_until, session_id)
VALUES (1, '{}', NULL, NULL);

-- ============================================================================
-- Default Zones
-- ============================================================================

INSERT INTO firewall_zones (name, description, default_input_policy, default_forward_policy, created_at)
VALUES 
    ('wan', 'Internet-facing interfaces', 'drop', 'drop', strftime('%s', 'now')),
    ('lan', 'Internal network interfaces', 'accept', 'accept', strftime('%s', 'now'));

-- Default: allow LAN → WAN forwarding
INSERT INTO firewall_zone_forwards (source_zone_id, dest_zone_id, policy, enabled)
SELECT 
    (SELECT id FROM firewall_zones WHERE name = 'lan'),
    (SELECT id FROM firewall_zones WHERE name = 'wan'),
    'accept', 1;
```

---

## Core Types Summary

### Types to Add (`keystone-core/src/lib.rs`)

| Type | Description | Status |
|------|-------------|--------|
| `FirewallPolicy` | Zone default policy (Accept/Drop) | ⬜ TODO |
| `FirewallAction` | Rule action (Accept/Drop/Reject) | ⬜ TODO |
| `RuleProtocol` | Protocol matcher (Any/Tcp/Udp/TcpUdp/Icmp/Icmpv6) | ⬜ TODO |
| `FirewallZone` | Zone with interfaces and default policies | ⬜ TODO |
| `ZoneForwardPolicy` | Zone-to-zone forwarding policy | ⬜ TODO |
| `PortForward` | DNAT port forward rule | ⬜ TODO |
| `InputRule` | Rule for traffic to the router | ⬜ TODO |
| `ForwardRule` | Rule for traffic through the router | ⬜ TODO |
| `FirewallConfig` | Container for all firewall config | ⬜ TODO |

### Request/Response Types

| Type | Description | Status |
|------|-------------|--------|
| `SaveFirewallZoneRequest/Response` | Zone CRUD | ⬜ TODO |
| `DeleteFirewallZoneRequest/Response` | Zone deletion | ⬜ TODO |
| `FirewallZonesResponse` | List zones | ⬜ TODO |
| `SaveZoneForwardRequest/Response` | Zone forward CRUD | ⬜ TODO |
| `ZoneForwardsResponse` | List zone forwards | ⬜ TODO |
| `SavePortForwardRequest/Response` | Port forward CRUD | ⬜ TODO |
| `PortForwardsResponse` | List port forwards | ⬜ TODO |
| `SaveInputRuleRequest/Response` | Input rule CRUD | ⬜ TODO |
| `InputRulesResponse` | List input rules | ⬜ TODO |
| `SaveForwardRuleRequest/Response` | Forward rule CRUD | ⬜ TODO |
| `ForwardRulesResponse` | List forward rules | ⬜ TODO |
| `ReorderRulesRequest/Response` | Rule reordering | ⬜ TODO |
| `FirewallPreviewResponse` | Ruleset preview text | ⬜ TODO |
| `FirewallApplyRequest/Response` | Apply with timer | ⬜ TODO |
| `FirewallConfirmRequest/Response` | Confirm pending | ⬜ TODO |
| `FirewallRollbackResponse` | Manual rollback | ⬜ TODO |
| `FirewallStatusResponse` | Pending status check | ⬜ TODO |

### Types to Remove

| Type | Reason | Status |
|------|--------|--------|
| `Protocol` (old enum) | Replaced by `RuleProtocol` | ⬜ TODO |
| `FirewallRule` (old struct) | Replaced by new rule types | ⬜ TODO |
| `firewall_rules` in `SystemState` | No longer used | ⬜ TODO |

---

## API Endpoints

| Method | Endpoint | Description | Status |
|--------|----------|-------------|--------|
| GET | `/firewall/zones` | List all zones | ⬜ TODO |
| POST | `/firewall/zones` | Create/update zone | ⬜ TODO |
| DELETE | `/firewall/zones/:id` | Delete zone (protected) | ⬜ TODO |
| GET | `/firewall/zone-forwards` | List zone-to-zone policies | ⬜ TODO |
| POST | `/firewall/zone-forwards` | Create/update policy | ⬜ TODO |
| DELETE | `/firewall/zone-forwards/:id` | Delete policy | ⬜ TODO |
| GET | `/firewall/port-forwards` | List port forwards | ⬜ TODO |
| POST | `/firewall/port-forwards` | Create/update port forward | ⬜ TODO |
| DELETE | `/firewall/port-forwards/:id` | Delete port forward | ⬜ TODO |
| GET | `/firewall/input-rules` | List input rules | ⬜ TODO |
| POST | `/firewall/input-rules` | Create/update input rule | ⬜ TODO |
| DELETE | `/firewall/input-rules/:id` | Delete input rule | ⬜ TODO |
| POST | `/firewall/input-rules/reorder` | Reorder input rules | ⬜ TODO |
| GET | `/firewall/forward-rules` | List forward rules | ⬜ TODO |
| POST | `/firewall/forward-rules` | Create/update forward rule | ⬜ TODO |
| DELETE | `/firewall/forward-rules/:id` | Delete forward rule | ⬜ TODO |
| POST | `/firewall/forward-rules/reorder` | Reorder forward rules | ⬜ TODO |
| GET | `/firewall/preview` | Preview nftables ruleset | ⬜ TODO |
| POST | `/firewall/apply` | Apply with 60s rollback timer | ⬜ TODO |
| POST | `/firewall/confirm` | Confirm pending changes | ⬜ TODO |
| POST | `/firewall/rollback` | Manual rollback | ⬜ TODO |
| GET | `/firewall/status` | Check pending confirmation status | ⬜ TODO |

---

## Example Generated Ruleset

```nft
#!/usr/sbin/nft -f

# Keystone Firewall - Auto-generated
# Generated: 2025-01-15T10:30:00Z

table inet keystone {
    # ========================================
    # Input Chain (traffic TO the router)
    # ========================================
    chain input {
        type filter hook input priority filter; policy drop;
        
        # Priority 1: Established/Related connections
        ct state established,related accept
        
        # Priority 2: Invalid packets
        ct state invalid drop
        
        # Priority 3: Loopback
        iif lo accept
        
        # Priority 4: User Input Rules
        iifname { "eth1", "eth2" } tcp dport 22 accept comment "Allow SSH from LAN"
        iifname { "eth1", "eth2" } udp dport 53 accept comment "Allow DNS from LAN"
        iifname { "eth1", "eth2" } tcp dport 53 accept comment "Allow DNS from LAN"
        
        # Priority 5: Zone defaults
        iifname { "eth1", "eth2" } accept  # lan zone: default accept
        # wan zone (eth0): default drop (implicit from chain policy)
    }
    
    # ========================================
    # Forward Chain (traffic THROUGH the router)
    # ========================================
    chain forward {
        type filter hook forward priority filter; policy drop;
        
        # Priority 1: Established/Related
        ct state established,related accept
        
        # Priority 2: Invalid
        ct state invalid drop
        
        # Priority 3: User Forward Rules
        # (none configured)
        
        # Priority 4: Zone-to-Zone Policies
        iifname { "eth1", "eth2" } oifname "eth0" accept  # lan → wan
        
        # Priority 5: Zone defaults (implicit drop)
    }
    
    # ========================================
    # Output Chain (traffic FROM the router)
    # ========================================
    chain output {
        type filter hook output priority filter; policy accept;
    }
}

table inet keystone_nat {
    # ========================================
    # DNAT (Port Forwards)
    # ========================================
    chain prerouting {
        type nat hook prerouting priority dstnat;
        
        # Port forwards
        iifname "eth0" tcp dport 8080 dnat to 192.168.1.100:80 comment "Web server"
        iifname "eth0" tcp dport 25565 dnat to 192.168.1.50 comment "Minecraft"
    }
    
    # ========================================
    # SNAT (Masquerade + MSS Clamping)
    # ========================================
    chain postrouting {
        type nat hook postrouting priority srcnat;
        
        # MSS clamping for WAN (automatic, route-based)
        oifname "eth0" tcp flags syn tcp option maxseg size set rt mtu
        
        # Masquerade for WAN
        oifname "eth0" masquerade
    }
}
```

---

## Safety Features

| Feature | Description | Status |
|---------|-------------|--------|
| 60-second rollback timer | Auto-restore if not confirmed | ⬜ TODO |
| Atomic table replacement | Flush and recreate, no partial states | ⬜ TODO |
| Dedicated table ownership | Never touches non-Keystone tables | ⬜ TODO |
| Zone deletion protection | Cannot delete zones with interfaces or rule references | ⬜ TODO |
| MSS clamping on WAN | Automatic based on route MTU | ⬜ TODO |
| Stateful by default | Always allow established/related | ⬜ TODO |

---

## Testing Checklist

### Unit Tests

| Test | Status |
|------|--------|
| Core type serialization | ⬜ TODO |
| Protocol/Action/Policy parsing | ⬜ TODO |
| Ruleset generation (basic) | ⬜ TODO |
| Ruleset generation (port ranges) | ⬜ TODO |
| Ruleset generation (rate limits) | ⬜ TODO |

### Integration Tests (Vagrant)

| Test | Status |
|------|--------|
| Apply ruleset, verify with `nft list ruleset` | ⬜ TODO |
| Zone isolation (LAN cannot reach WAN without forward policy) | ⬜ TODO |
| Port forward connectivity | ⬜ TODO |
| Rollback timer expiration | ⬜ TODO |
| Confirm within timeout | ⬜ TODO |
| Manual rollback | ⬜ TODO |
| MSS clamping on WAN | ⬜ TODO |

### Manual Testing

| Test | Status |
|------|--------|
| Web UI: Zone CRUD | ⬜ TODO |
| Web UI: Port forward CRUD | ⬜ TODO |
| Web UI: Rule CRUD and reordering | ⬜ TODO |
| Web UI: Preview modal | ⬜ TODO |
| Web UI: Apply with countdown | ⬜ TODO |
| Web UI: Confirm/Rollback buttons | ⬜ TODO |
| keystonectl: All firewall commands | ⬜ TODO |

---

## Dependencies

```toml
# daemon/Cargo.toml
[dependencies]
nftables = "0.6"
```

---

## Future Enhancements (Post-MVP)

| Feature | Priority | Notes |
|---------|----------|-------|
| Custom chains | Low | For complex rule organization |
| Named sets (IP blocklists) | Medium | Efficient matching against lists |
| Conntrack helpers (FTP, SIP) | Low | ALG support |
| Traffic marking (QoS) | Low | Integration with tc |
| Time-based rules | Low | Parental controls |
| Quotas | Low | Bandwidth limits |
| Source NAT (multi-WAN) | Low | Specific source IP for NAT |
| Hairpin NAT | Medium | Access port-forwards from inside |
| Flow offloading | Low | Hardware acceleration |
| IPv6-specific rules | Medium | Beyond dual-stack inet |

---

**Last Updated**: 2025-12-29
**Status**: Planning Complete, Implementation Not Started
