-- Add columns to existing tables
ALTER TABLE ar 
ADD linetax BOOLEAN NOT NULL DEFAULT FALSE,
ADD COLUMN created TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE ap 
ADD linetax BOOLEAN NOT NULL DEFAULT FALSE,
ADD COLUMN created TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE gl 
ADD COLUMN created TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE oe 
ADD COLUMN created TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE acc_trans ADD tax_chart_id INTEGER;
ALTER TABLE acc_trans ADD linetaxamount NUMERIC NOT NULL DEFAULT 0;
ALTER TABLE chart ADD parent_id INTEGER;
ALTER TABLE tax ADD id SERIAL PRIMARY KEY;
 
CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    module VARCHAR(50) NOT NULL,          -- ar, ap, gl
    name TEXT NOT NULL,                   -- system-generated file name
    extension VARCHAR(10),           -- File extension (.pdf, .jpg)
    location VARCHAR(20) NOT NULL,        -- E.g., 'local', 'google_drive', 'dropbox'
    path TEXT NOT NULL,           -- Relative path or external storage key/ID
    link TEXT,                          -- direct URL to access the file, if applicable
    upload_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
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
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    drive_id VARCHAR(255)              -- Google Drive ID
);

CREATE TABLE job_status (
   id SERIAL PRIMARY KEY,
   job_id TEXT NOT NULL,
   trans_id TEXT NOT NULL,
   status TEXT NOT NULL, -- 'success' or 'error'
   type TEXT,
   email TEXT,
   name TEXT,
   reference TEXT,
   error_message TEXT,
   created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE invoicetax (
    trans_id integer NOT NULL,
    invoice_id integer NOT NULL,
    chart_id integer NOT NULL,
    taxamount double precision NOT NULL,
    amount double precision NOT NULL
);

-- Create indexes
CREATE INDEX idx_invoicetax_trans_id ON invoicetax (trans_id);
CREATE INDEX idx_files_module ON files(module);
CREATE INDEX idx_files_location ON files(location);
CREATE INDEX idx_files_reference_id ON files(reference_id);

-- Create trigger function for updating 'updated' column
CREATE OR REPLACE FUNCTION update_updated_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for automatic timestamp updates
CREATE TRIGGER gl_update_updated_trigger
    BEFORE UPDATE ON gl
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_column();

CREATE TRIGGER ar_update_updated_trigger
    BEFORE UPDATE ON ar
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_column();

CREATE TRIGGER ap_update_updated_trigger
    BEFORE UPDATE ON ap
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_column();

CREATE TRIGGER oe_update_updated_trigger
    BEFORE UPDATE ON oe
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_column();