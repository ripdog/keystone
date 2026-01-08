-- Add wizard_step column to track setup wizard progress
-- wizard_step values:
--   0 = Not started (show wizard)
--   1 = Password changed
--   2 = System checks passed
--   3 = Interfaces assigned to zones
--   4 = Wizard complete (same as setup_complete=true)

ALTER TABLE global_settings ADD COLUMN wizard_step INTEGER NOT NULL DEFAULT 0;
