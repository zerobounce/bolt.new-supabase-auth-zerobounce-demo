#!/bin/sh
# Load the guard functions from zb_migration.sql and run tests/assertions.sql.
# Does not create the http extension and does not call http_post.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sql=$(mktemp)
trap 'rm -f "$sql"' EXIT
cat >> "$sql" << 'EOF'
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE OR REPLACE FUNCTION extensions.urlencode(t text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT replace(replace(replace(coalesce(t, ''), '%', '%25'), ' ', '%20'), '''', '%27');
$$;
EOF
awk '/^-- zb-guard-start$/{p=1; next} /^-- zb-guard-end$/{p=0} p' "$root/zb_migration.sql" >> "$sql"
cat "$root/tests/assertions.sql" >> "$sql"
psql -v ON_ERROR_STOP=1 -f "$sql"
