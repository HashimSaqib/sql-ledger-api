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