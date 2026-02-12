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

CREATE TABLE db_updates (
    id SERIAL PRIMARY KEY,
    version VARCHAR(3) NOT NULL,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_update TEXT NOT NULL
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

ALTER TABLE bank ADD COLUMN qriban TEXT, ADD COLUMN strdbkginf TEXT, ADD COLUMN invdescriptionqr TEXT;
INSERT INTO db_updates (version, last_update) VALUES ('001', 'Bank QR');

CREATE TABLE ai_processing (
    id SERIAL PRIMARY KEY,
    file_id INTEGER NOT NULL,
    job_id BIGINT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'start',
    type VARCHAR(50) NOT NULL DEFAULT 'customer_invoice',
    started TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed TIMESTAMP WITHOUT TIME ZONE,
    reference_id INTEGER,
    error_message TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    additional_info JSONB,
    original_response JSONB,
    error_type TEXT
);

CREATE TABLE ai_prompts (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    prompt TEXT NOT NULL,
    model VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO ai_prompts (name, prompt) VALUES ('ap_transaction', '');
INSERT INTO ai_prompts (name, prompt) VALUES ('sales_invoice', '');

INSERT INTO db_updates (version, last_update) VALUES ('002', 'AI Tables');

ALTER TABLE gl ADD COLUMN offset_account_id INTEGER;
INSERT INTO db_updates (version, last_update) VALUES ('003', 'Offset Account');


-- Work Station & Workflow Tables
CREATE TABLE stations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT false, 
    workflow_order INTEGER, 
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE station_users (
    id SERIAL PRIMARY KEY,
    station_id INTEGER NOT NULL,
    profile_id INTEGER NOT NULL, -- References central DB profile.id
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER NOT NULL, -- profile_id who assigned this user
    FOREIGN KEY (station_id) REFERENCES stations(id) ON DELETE CASCADE,
    UNIQUE (station_id, profile_id)
);

CREATE TABLE station_approval_rules (
    id SERIAL PRIMARY KEY,
    station_id INTEGER NOT NULL,
    rule_type VARCHAR(50) NOT NULL, -- 'amount', 'department', 'vendor', 'project'.
    condition_field VARCHAR(100), -- field name to check 'total_amount', 'department_id', 'vendor_id', 'project_id')
    operator VARCHAR(10) NOT NULL, -- 'gt', 'lt', 'eq', 'gte', 'lte', 'in', 'not_in'
    condition_value JSONB NOT NULL, -- value storage
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (station_id) REFERENCES stations(id) ON DELETE CASCADE
);

CREATE TABLE invoice_station (
    id SERIAL PRIMARY KEY,
    invoice_id INTEGER NOT NULL,
    station_id INTEGER NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (station_id) REFERENCES stations(id) ON DELETE CASCADE
);

CREATE table invoice_station_history (
    id SERIAL PRIMARY KEY,
    invoice_id INTEGER NOT NULL,
    from_station_id INTEGER,
    to_station_id INTEGER NOT NULL,
    user_id INTEGER,
    is_system BOOLEAN DEFAULT FALSE,
    transfer_timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    transfer_notes TEXT,
    FOREIGN KEY (from_station_id) REFERENCES stations(id) ON DELETE CASCADE,
    FOREIGN KEY (to_station_id) REFERENCES stations(id) ON DELETE CASCADE
);

ALTER table department ADD COLUMN detail TEXT;
ALTER table project ADD COLUMN detail TEXT;

INSERT INTO db_updates (version, last_update) VALUES ('006', 'Department and Project Detail');

CREATE TABLE bank_transactions (
    transaction_id VARCHAR(255) PRIMARY KEY,
    bank_id INTEGER NOT NULL,
    account_servicer_ref VARCHAR(100) NOT NULL,
    end_to_end_id TEXT,
    amount DECIMAL(18, 2) NOT NULL,
    currency CHAR(3) NOT NULL,
    type_indicator CHAR(4) NOT NULL,
    booking_date DATE NOT NULL,
    value_date DATE,
    counterparty_name VARCHAR(255),
    counterparty_iban VARCHAR(34),
    counterparty_id VARCHAR(100),
    remittance_unstructured TEXT,
    remittance_structured VARCHAR(100),
    additional_info JSONB,
    bank_transaction_code_domain CHAR(4),
    bank_transaction_code_family CHAR(4),
    category_subfamily CHAR(4),
    bank_ref VARCHAR(100),
    module VARCHAR(50),
    reference_id INTEGER,
    source VARCHAR(50),
    source_id VARCHAR(255),
    bank_transaction_code VARCHAR(10),
    rule_id INTEGER,
    pending BOOLEAN DEFAULT TRUE
);


CREATE TABLE bank_transaction_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    rule_json JSONB NOT NULL,
    template_json JSONB NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    bank_id INTEGER,
    template_type VARCHAR(100)
);

CREATE TABLE payments (
    id SERIAL PRIMARY KEY,
    module VARCHAR(255) NOT NULL,
    payment_status VARCHAR(255) NOT NULL,
    created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    end_to_end_id VARCHAR(255),
    transaction_id INTEGER
);

INSERT INTO db_updates (version, last_update) VALUES ('007', 'Bank Transactions');

CREATE TABLE bank_account (
    id SERIAL PRIMARY KEY,
    trans_id INTEGER NOT NULL,  
    name CHARACTER VARYING(64),
    iban CHARACTER VARYING(34),
    bic CHARACTER VARYING(11),
    address_id INTEGER,
    dcn TEXT,
    rvc TEXT,
    membernumber TEXT,
    clearingnumber TEXT,
    qriban TEXT,
    strdbkginf TEXT,
    invdescriptionqr TEXT,
    is_primary BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE ar ADD COLUMN vc_bank_id INTEGER;
ALTER TABLE ap ADD COLUMN vc_bank_id INTEGER;
ALTER TABLE ap ADD column executiondate DATE;
ALTER TABLE ar ADD column executiondate DATE;
ALTER TABLE address ADD COLUMN street VARCHAR(255);
ALTER TABLE address ADD COLUMN post_office VARCHAR(255);

INSERT INTO db_updates (version, last_update) VALUES ('008', 'Bank Account');

CREATE TABLE onboarding (
    id SERIAL PRIMARY KEY,
    fldname VARCHAR(255) NOT NULL,
    fldvalue BOOLEAN
);

INSERT INTO onboarding (fldname, fldvalue) VALUES ('coa', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('departments', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('projects', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('bank_accounts', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('defaults', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('services', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('stations', false);
INSERT INTO db_updates (version, last_update) VALUES ('009', 'Onboarding');

ALTER TABLE bank_transactions ADD COLUMN processing_info JSONB;
INSERT INTO db_updates (version, last_update) VALUES ('010', 'Bank Transaction Processing Info');


CREATE TABLE connection_keys (
    id SERIAL PRIMARY KEY,
    fldname VARCHAR(255) NOT NULL,
    fldvalue JSONB,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE bank ADD COLUMN external_id VARCHAR(255);


CREATE TABLE transaction_distribution (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(255) NOT NULL,
    trans_id INTEGER NOT NULL,
    amount double precision NOT NULL,
    based_on VARCHAR(50),
    module VARCHAR(50) NOT NULL
);
INSERT INTO db_updates (version, last_update) VALUES ('011', 'Transaction Distribution');


ALTER TABLE parts ADD COLUMN external_info JSONB;
ALTER TABLE ar ADD COLUMN external_info JSONB;
ALTER TABLE ap ADD COLUMN external_info JSONB;
ALTER TABLE project ADD COLUMN external_info JSONB;

INSERT INTO db_updates (version, last_update) VALUES ('012', 'External ID');

-- Notification System Tables
CREATE TABLE notification_subscriptions (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL,  -- from centraldb
    notification_type VARCHAR(100) NOT NULL, -- 'workflow_pending', 'payments_uploaded', etc.
    frequency VARCHAR(50) NOT NULL, -- 'daily', 'weekly', 'monthly', 'custom'
    custom_schedule JSONB, -- for complex schedules: {"days": [1,3,5]}
    delivery_time TIME NOT NULL, -- when to send (e.g., '09:00:00')
    is_active BOOLEAN DEFAULT true,
    last_sent_at TIMESTAMP WITHOUT TIME ZONE,
    email_to VARCHAR(255), -- override recipient email (NULL = use profile email)
    email_cc JSONB, -- JSON array of CC email addresses
    email_bcc JSONB, -- JSON array of BCC email addresses
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_notification_subscriptions_profile_type ON notification_subscriptions(profile_id, notification_type);
CREATE INDEX idx_notification_subscriptions_active ON notification_subscriptions(is_active, last_sent_at);

CREATE TABLE notification_history (
    id SERIAL PRIMARY KEY,
    subscription_id INTEGER REFERENCES notification_subscriptions(id) ON DELETE CASCADE,
    profile_id INTEGER NOT NULL,
    notification_type VARCHAR(100) NOT NULL,
    sent_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL, -- 'sent', 'failed', 'skipped'
    record_count INTEGER,
    error_message TEXT
);

CREATE INDEX idx_notification_history_profile ON notification_history(profile_id, sent_at);
CREATE INDEX idx_notification_history_subscription ON notification_history(subscription_id);

INSERT INTO db_updates (version, last_update) VALUES ('013', 'Notification System');

CREATE TABLE widget_config (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, config JSONB NOT NULL);
INSERT INTO db_updates (version, last_update) VALUES ('014', 'Widgets');

ALTER TABLE gl ADD COLUMN taxincluded BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE gl ADD COLUMN offset_tax_id INTEGER;

INSERT INTO db_updates (version, last_update) VALUES ('015', 'GL Line Tax');