-- DNS filtering (ad-blocking) and encrypted upstream DNS, served by Blocky.
-- The settings are a single row; the upstream, bootstrap, group and client
-- lists are child tables ordered by a position column. All of these are
-- configuration: they are captured into and restored from snapshots.
CREATE TABLE IF NOT EXISTS blocky_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    upstream_strategy TEXT NOT NULL DEFAULT 'parallel_best'
        CHECK (upstream_strategy IN ('parallel_best', 'strict', 'random')),
    block_type TEXT NOT NULL DEFAULT 'zero_ip' CHECK (block_type IN ('zero_ip', 'nx_domain')),
    refresh_hours INTEGER NOT NULL DEFAULT 24 CHECK (refresh_hours BETWEEN 1 AND 168),
    prefetching INTEGER NOT NULL DEFAULT 1 CHECK (prefetching IN (0, 1)),
    min_cache_minutes INTEGER NOT NULL DEFAULT 5 CHECK (min_cache_minutes BETWEEN 0 AND 60),
    query_log_enabled INTEGER NOT NULL DEFAULT 1 CHECK (query_log_enabled IN (0, 1)),
    query_log_retention_days INTEGER NOT NULL DEFAULT 7
        CHECK (query_log_retention_days BETWEEN 1 AND 90),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

INSERT OR IGNORE INTO blocky_config (id) VALUES (1);

-- Encrypted or plain upstream resolvers, in the order they are listed.
CREATE TABLE IF NOT EXISTS blocky_upstreams (
    position INTEGER PRIMARY KEY,
    upstream TEXT NOT NULL
);

-- Plain resolvers used to look up upstream host names and list URLs.
CREATE TABLE IF NOT EXISTS blocky_bootstrap (
    position INTEGER PRIMARY KEY,
    address TEXT NOT NULL
);

-- Filtering groups. Names are unique and validated when saved.
CREATE TABLE IF NOT EXISTS blocky_groups (
    position INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

-- Sources of a group. kind is deny or allow. custom 0 rows are list URLs;
-- custom 1 rows are hand-written domain entries, one inline source per group
-- and kind. The group name is not a foreign key: snapshot restore replaces
-- all of these tables together.
CREATE TABLE IF NOT EXISTS blocky_group_sources (
    group_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('deny', 'allow')),
    custom INTEGER NOT NULL DEFAULT 0 CHECK (custom IN (0, 1)),
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (group_name, kind, custom, position)
);

-- Which groups apply to which client selector. selector_position orders the
-- selectors and group_position orders the groups within one selector.
CREATE TABLE IF NOT EXISTS blocky_client_groups (
    selector_position INTEGER NOT NULL,
    selector TEXT NOT NULL,
    group_position INTEGER NOT NULL,
    group_name TEXT NOT NULL,
    PRIMARY KEY (selector_position, group_position)
);

-- Defaults, matching BlockyConfig::default in keystone-core. This migration
-- runs once, against empty tables, so plain inserts are enough.
INSERT INTO blocky_upstreams (position, upstream) VALUES
    (0, 'https://dns.quad9.net/dns-query'),
    (1, 'tcp-tls:dns.quad9.net');

INSERT INTO blocky_bootstrap (position, address) VALUES
    (0, '9.9.9.9'),
    (1, '149.112.112.112');

INSERT INTO blocky_groups (position, name) VALUES (0, 'ads');

INSERT INTO blocky_group_sources (group_name, kind, custom, position, value) VALUES
    ('ads', 'deny', 0, 0, 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt');

INSERT INTO blocky_client_groups (selector_position, selector, group_position, group_name) VALUES
    (0, 'default', 0, 'ads');
