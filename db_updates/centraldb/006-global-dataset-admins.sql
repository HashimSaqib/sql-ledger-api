-- Add a configurable list of users who are automatically granted admin access
-- on every newly created dataset. Managed via PUT /management/settings.
ALTER TABLE backend_settings
    ADD COLUMN IF NOT EXISTS global_dataset_admins JSONB NOT NULL DEFAULT '[]';
