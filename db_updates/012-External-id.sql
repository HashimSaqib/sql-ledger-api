ALTER TABLE parts ADD COLUMN external_info JSONB;
ALTER TABLE ar ADD COLUMN external_info JSONB;
ALTER TABLE ap ADD COLUMN external_info JSONB;
ALTER TABLE project ADD COLUMN external_info JSONB;