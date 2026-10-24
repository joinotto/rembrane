#!/bin/sh
set -eu

: "${REMBRANE_POSTGRES_URL:?REMBRANE_POSTGRES_URL is required}"

psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA IF EXISTS rembrane CASCADE;
DROP TABLE IF EXISTS memory_share_proposals, memories, workspaces CASCADE;
DROP ROLE IF EXISTS rembrane_runtime_test;

CREATE TABLE workspaces (id text PRIMARY KEY);
CREATE TABLE memories (
    workspace_id text NOT NULL REFERENCES workspaces(id),
    id text NOT NULL,
    PRIMARY KEY (workspace_id, id)
);
CREATE TABLE memory_share_proposals (
    source_workspace_id text NOT NULL REFERENCES workspaces(id),
    target_workspace_id text NOT NULL REFERENCES workspaces(id),
    id text NOT NULL,
    PRIMARY KEY (source_workspace_id, id)
);
CREATE ROLE rembrane_runtime_test NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO rembrane_runtime_test;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
    TO rembrane_runtime_test;

INSERT INTO workspaces VALUES ('workspace_01'), ('workspace_02');
INSERT INTO memories VALUES
    ('workspace_01', 'memory_01'),
    ('workspace_02', 'memory_02');
INSERT INTO memory_share_proposals VALUES
    ('workspace_01', 'workspace_02', 'proposal_01'),
    ('workspace_02', 'workspace_01', 'proposal_02');
SQL

psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 \
    -f migrations/postgres/0001_tenant_rls.sql

result=$(
    psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 -qAt <<'SQL'
BEGIN;
SET LOCAL ROLE rembrane_runtime_test;
SET LOCAL rembrane.workspace_id = 'workspace_01';
SELECT
    (SELECT count(*) FROM workspaces),
    (SELECT count(*) FROM memories),
    (SELECT count(*) FROM memory_share_proposals);
ROLLBACK;
SQL
)
test "$result" = "1|1|1"

if psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<'SQL'
BEGIN;
SET LOCAL ROLE rembrane_runtime_test;
SET LOCAL rembrane.workspace_id = 'workspace_01';
INSERT INTO memories VALUES ('workspace_02', 'forbidden');
ROLLBACK;
SQL
then
    echo "PostgreSQL RLS accepted a cross-tenant insert" >&2
    exit 1
fi

unscoped=$(
    psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 -qAt <<'SQL'
BEGIN;
SET LOCAL ROLE rembrane_runtime_test;
SELECT count(*) FROM memories;
ROLLBACK;
SQL
)
test "$unscoped" = "0"

echo "PostgreSQL two-tenant RLS test passed"
