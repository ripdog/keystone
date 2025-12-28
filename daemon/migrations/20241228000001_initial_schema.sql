-- Initial database schema for Keystone

-- Managed network interfaces
CREATE TABLE IF NOT EXISTS managed_interfaces (
    name TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    static_ip TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- User accounts
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- JWT signing key (singleton table)
CREATE TABLE IF NOT EXISTS jwt_key (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    key_bytes BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
