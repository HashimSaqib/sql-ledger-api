-- Backend management settings table (singleton row, id always = 1)
-- public_signup and allow_db_creation replace the .env flags of the same name.
-- db_creation_rules holds the extensible allow-list for dataset creation when
-- allow_db_creation is false: { "allowed_emails": [], "allowed_domains": [] }
-- Extra future settings can be added to the JSONB `extra` column without a migration.
CREATE TABLE IF NOT EXISTS backend_settings (
    id                INTEGER PRIMARY KEY DEFAULT 1,
    public_signup     BOOLEAN NOT NULL DEFAULT true,
    allow_db_creation BOOLEAN NOT NULL DEFAULT true,
    db_creation_rules JSONB   NOT NULL DEFAULT '{"allowed_emails": [], "allowed_domains": []}',
    extra             JSONB   NOT NULL DEFAULT '{}',
    updated_at        TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT single_row CHECK (id = 1)
);

-- Seed the one row from current env defaults (backend will overwrite on first save)
INSERT INTO backend_settings (id, public_signup, allow_db_creation)
VALUES (1, true, true)
ON CONFLICT (id) DO NOTHING;
