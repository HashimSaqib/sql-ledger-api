--- introduction of central API keys
CREATE TABLE api_key (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES profile(id) ON DELETE CASCADE,
    apikey TEXT NOT NULL UNIQUE,
    label TEXT,                      
    scopes JSONB DEFAULT '[]',       
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires TIMESTAMP,           
    last_used TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE api_key_access (
    id SERIAL PRIMARY KEY,
    apikey_id INTEGER NOT NULL REFERENCES api_key(id) ON DELETE CASCADE,
    dataset_id INTEGER NOT NULL REFERENCES dataset(id) ON DELETE CASCADE,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scopes JSONB DEFAULT '[]'
);
CREATE UNIQUE INDEX idx_api_key_dataset ON api_key_access(apikey_id, dataset_id);
CREATE INDEX idx_dataset_id ON api_key_access(dataset_id);
CREATE INDEX idx_api_key_profile_id ON api_key(profile_id);