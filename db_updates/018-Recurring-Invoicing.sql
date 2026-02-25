-- Recurring Invoicing Module
-- Stores invoice template (JSON) + schedule; cron creates AR invoices and optionally emails.
-- Schedule uses same format as notification subscriptions: frequency, delivery_time, custom_schedule.
-- Does NOT use SQL-Ledger's built-in recurring table (that one is tied to existing ar/ap id).

CREATE TABLE recurring_invoice (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER,
    name VARCHAR(255),
    vc VARCHAR(20) NOT NULL DEFAULT 'customer',
    invoice_payload JSONB NOT NULL,
    frequency VARCHAR(20) NOT NULL,           -- 'daily', 'weekly', 'monthly', 'custom'
    delivery_time TIME NOT NULL DEFAULT '09:00:00',
    custom_schedule JSONB,                   -- e.g. {"days": [2, 4]} for weekly (1-7) or monthly (1-31 or -1)
    start_date DATE NOT NULL,
    end_date DATE,
    last_run_at TIMESTAMP WITHOUT TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    send_email BOOLEAN DEFAULT false,
    message TEXT,                           -- email body; {variable} replaced from build_invoice form
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_recurring_invoice_active ON recurring_invoice(is_active);

CREATE TABLE recurring_invoice_run (
    id SERIAL PRIMARY KEY,
    recurring_invoice_id INTEGER NOT NULL REFERENCES recurring_invoice(id) ON DELETE CASCADE,
    ran_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_invoice_id INTEGER,
    status VARCHAR(20) NOT NULL,
    error_message TEXT
);

CREATE INDEX idx_recurring_invoice_run_schedule ON recurring_invoice_run(recurring_invoice_id, ran_at);

INSERT INTO db_updates (version, last_update) VALUES ('018', 'Recurring Invoicing');
