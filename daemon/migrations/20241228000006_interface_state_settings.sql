-- Add interface state settings columns to interface_config table
-- These control link-local addressing, online wait, and activation policy

ALTER TABLE interface_config ADD COLUMN link_local TEXT NOT NULL DEFAULT 'yes';
ALTER TABLE interface_config ADD COLUMN required_for_online INTEGER NOT NULL DEFAULT 1;
ALTER TABLE interface_config ADD COLUMN activation_policy TEXT NOT NULL DEFAULT 'up';
