CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    module VARCHAR(50) NOT NULL,          -- ar, ap, gl
    name TEXT NOT NULL,                   -- system-generated file name
    extension VARCHAR(10),           -- File extension (.pdf, .jpg)
    location VARCHAR(20) NOT NULL,        -- E.g., 'local', 'google_drive', 'dropbox'
    path TEXT NOT NULL,           -- Relative path or external storage key/ID
    link TEXT,                          -- direct URL to access the file, if applicable
    upload_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    reference_id INTEGER
);

CREATE TABLE connections (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL,          -- 'google_drive', 'dropbox'
    access_token TEXT NOT NULL,         -- Short-lived access token (encrypted)
    refresh_token TEXT,                 -- Long-lived refresh token (encrypted)
    token_expires TIMESTAMPTZ,          -- Expiration time for the access token
    status VARCHAR(20),  -- active, error
    error TEXT,                         -- any error messages
    drive_id VARCHAR(255),              -- Google Drive ID
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
