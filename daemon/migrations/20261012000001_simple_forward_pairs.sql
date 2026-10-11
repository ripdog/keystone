-- Identifies the v4/v6 allow rules belonging to the same logical port forward.
-- Comments are stored in the existing description columns, not in this key.
ALTER TABLE firewall_forward_rules ADD COLUMN simple_forward_group TEXT;
