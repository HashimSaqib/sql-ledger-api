ALTER TABLE role ADD COLUMN extra_info JSONB;   
INSERT INTO db_updates (version, last_update) VALUES ('003', 'Role Extra Info');