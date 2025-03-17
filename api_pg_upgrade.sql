-- Upgrade script for the database schema

-- Table: public.acsapirole
CREATE TABLE IF NOT EXISTS public.acsapirole (
    id SERIAL PRIMARY KEY,
    description TEXT,
    acs JSONB,
    rn SMALLINT
);

-- Table: public.login
CREATE TABLE IF NOT EXISTS public.login (
    id SERIAL PRIMARY KEY,
    employeeid INTEGER,
    password TEXT NOT NULL,
    created TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    lastlogin TIMESTAMP WITHOUT TIME ZONE,
    admin BOOLEAN DEFAULT FALSE,
    acsrole_id INTEGER,
    CONSTRAINT login_acsrole_fk FOREIGN KEY (acsrole_id) REFERENCES public.acsapirole(id)
);

-- Table: public.session
CREATE TABLE IF NOT EXISTS public.session (
    id SERIAL PRIMARY KEY,
    employeeid INTEGER,
    sessionkey TEXT NOT NULL,
    created TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table: public.files
CREATE TABLE IF NOT EXISTS public.files (
    id SERIAL PRIMARY KEY,
    filename TEXT,
    timestamp TIMESTAMP WITH TIME ZONE,
    processed BOOLEAN DEFAULT FALSE,
    reference TEXT,
    module VARCHAR(2),
    link TEXT
);

-- Indexes
CREATE UNIQUE INDEX IF NOT EXISTS login_pkey ON public.login (id);
CREATE UNIQUE INDEX IF NOT EXISTS session_pkey ON public.session (id);
CREATE UNIQUE INDEX IF NOT EXISTS files_pkey ON public.files (id);
CREATE UNIQUE INDEX IF NOT EXISTS acsapirole_pkey ON public.acsapirole (id);
