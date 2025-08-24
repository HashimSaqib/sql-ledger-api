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
    

