-- Upgrade script for the database schema

-- Table: public.login
CREATE TABLE IF NOT EXISTS public.login (
    id serial PRIMARY KEY,
    employeeid integer,
    password text NOT NULL,
    created timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    lastlogin timestamp without time zone,
    admin boolean DEFAULT false
);

-- Table: public.session
CREATE TABLE IF NOT EXISTS public.session (
    id serial PRIMARY KEY,
    employeeid integer,
    sessionkey text NOT NULL,
    created timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

-- Table: public.files
CREATE TABLE IF NOT EXISTS public.files (
    id serial PRIMARY KEY,
    filename text,
    timestamp timestamp with time zone,
    processed boolean DEFAULT false,
    reference text,
    module character varying(2),
    link text
);

-- Indexes
CREATE UNIQUE INDEX IF NOT EXISTS login_pkey ON public.login (id);
CREATE UNIQUE INDEX IF NOT EXISTS session_pkey ON public.session (id);
CREATE UNIQUE INDEX IF NOT EXISTS files_pkey ON public.files (id);
