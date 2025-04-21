#!/bin/bash

# PostgreSQL superuser credentials
PGUSER="postgres"
PGHOST="localhost"
PGPORT="5432"

# Role to grant privileges to
TARGET_USER="neoledger"

# List all non-template databases
DBS=$(psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -Atc \
  "SELECT datname FROM pg_database WHERE datistemplate = false AND datname NOT IN ('postgres');")

for DB in $DBS; do
  echo "Granting sequence access on database: $DB"

  psql -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -d "$DB" -c "
    DO \$\$
    DECLARE
      seq text;
    BEGIN
      FOR seq IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'S' AND n.nspname = 'public'
      LOOP
        EXECUTE format('GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.%I TO \"$TARGET_USER\";', seq);
      END LOOP;
    END
    \$\$;
  "
done

echo "✅ Done granting sequence access for user '$TARGET_USER'."
