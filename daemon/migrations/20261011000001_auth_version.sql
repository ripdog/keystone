-- Existing login tokens must be invalidated when an account is edited.
ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0;
