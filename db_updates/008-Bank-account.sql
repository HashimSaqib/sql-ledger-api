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
ALTER TABLE address ADD COLUMN street VARCHAR(255);