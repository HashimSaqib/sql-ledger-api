-- Add station_type column: extensible way to mark stations as 'default', 'receipt', etc.
-- Only one active station per type is allowed via a partial unique index.
ALTER TABLE stations ADD COLUMN IF NOT EXISTS station_type VARCHAR(50);

-- Migrate existing is_default data
UPDATE stations SET station_type = 'default' WHERE is_default = true AND station_type IS NULL;

-- Enforce one active station per type
CREATE UNIQUE INDEX IF NOT EXISTS idx_stations_unique_type
    ON stations(station_type) WHERE station_type IS NOT NULL AND is_active = true;

-- Seed a Default station if none exists yet
INSERT INTO stations (name, description, station_type, is_default, workflow_order, is_active)
SELECT 'Default', 'Default station', 'default', true, 1, true
WHERE NOT EXISTS (SELECT 1 FROM stations WHERE station_type = 'default' AND is_active = true);

-- Seed a Receipt station if none exists yet
INSERT INTO stations (name, description, station_type, is_default, workflow_order, is_active)
SELECT 'Receipt', 'Receipt station', 'receipt', false, 2, true
WHERE NOT EXISTS (SELECT 1 FROM stations WHERE station_type = 'receipt' AND is_active = true);

INSERT INTO db_updates (version, last_update) VALUES ('024', 'Station Types');
