-- Create the profile table
-- Referenced by: dataset, dataset_access, invite, profile_role, session
CREATE TABLE profile (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITHOUT TIME ZONE
);

-- Create the dataset table
-- References: profile
-- Referenced by: dataset_access, invite, role
CREATE TABLE dataset (
    id SERIAL PRIMARY KEY,
    db_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    owner_id INTEGER,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES profile(id)
);

-- Create the role table
-- References: dataset
-- Referenced by: dataset_access, invite, profile_role
CREATE TABLE role (
    id SERIAL PRIMARY KEY,
    dataset_id INTEGER NOT NULL,
    name VARCHAR(100) NOT NULL,
    acs JSONB,
    rn SMALLINT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (dataset_id) REFERENCES dataset(id) ON DELETE CASCADE
);

-- Create the dataset_access table
-- References: profile, dataset, role
CREATE TABLE dataset_access (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER,
    dataset_id INTEGER,
    role_id INTEGER,
    access_level VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    invited_by INTEGER,
    UNIQUE (profile_id, dataset_id),
    FOREIGN KEY (profile_id) REFERENCES profile(id),
    FOREIGN KEY (dataset_id) REFERENCES dataset(id),
    FOREIGN KEY (invited_by) REFERENCES profile(id),
    FOREIGN KEY (role_id) REFERENCES role(id) ON DELETE CASCADE
);

-- Create the profile_role table
-- References: profile, role
CREATE TABLE profile_role (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (profile_id) REFERENCES profile(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES role(id) ON DELETE CASCADE
);

-- Create the otp table
-- No dependencies
CREATE TABLE otp (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(6) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '5 minutes')
);

-- Create the session table
-- References: profile
CREATE TABLE session (
    id SERIAL PRIMARY KEY,
    profile_id INTEGER, -- Kept nullable as per original structure, add NOT NULL if required
    sessionkey TEXT NOT NULL,
    created TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (profile_id) REFERENCES profile(id) ON DELETE CASCADE -- Added FK constraint
);

-- Create the invite table
-- References: profile, dataset, role
CREATE TABLE invite (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    dataset_id INTEGER NOT NULL,
    access_level VARCHAR(50) NOT NULL DEFAULT 'user',
    role_id INTEGER,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    invite_code VARCHAR(50),
    FOREIGN KEY (sender_id) REFERENCES profile(id) ON DELETE CASCADE,
    FOREIGN KEY (dataset_id) REFERENCES dataset(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES role(id) ON DELETE SET NULL
);
