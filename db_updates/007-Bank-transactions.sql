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

