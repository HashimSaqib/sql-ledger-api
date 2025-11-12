
CREATE TABLE totp_secrets (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES profile(id) ON DELETE CASCADE,
    secret VARCHAR(32) NOT NULL,
    enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP,
    backup_codes TEXT, 
    UNIQUE(profile_id)
);

CREATE INDEX idx_totp_profile ON totp_secrets(profile_id);

CREATE TABLE temp_2fa_session (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES profile(id) ON DELETE CASCADE,
    temp_sessionkey VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '5 minutes'),
    client VARCHAR(255), 
    UNIQUE(profile_id, temp_sessionkey)
);

CREATE INDEX idx_temp_2fa_expires ON temp_2fa_session(expires_at);