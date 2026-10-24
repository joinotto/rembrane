#!/bin/sh
set -eu

: "${REMBRANE_POSTGRES_URL:?REMBRANE_POSTGRES_URL is required}"

psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA IF EXISTS rembrane CASCADE;
DROP TABLE IF EXISTS
    memory_share_proposals,
    projection_outbox,
    disclosed_memories,
    disclosure_receipts,
    activity_checkpoints,
    memory_evidence,
    memories,
    workspace_events,
    memberships,
    workspaces,
    principals
CASCADE;
DROP ROLE IF EXISTS rembrane_runtime_test;
SQL

psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 \
    -f migrations/postgres/0001_canonical_schema.sql

psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE rembrane_runtime_test NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO rembrane_runtime_test;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
    TO rembrane_runtime_test;

INSERT INTO principals (id) VALUES
    ('principal_01'),
    ('principal_02'),
    ('principal_shared');
INSERT INTO workspaces (id, kind) VALUES
    ('workspace_01', 'personal'),
    ('workspace_02', 'personal'),
    ('workspace_shared', 'shared');
INSERT INTO memberships (
    workspace_id, principal_id, role, status
) VALUES
    ('workspace_01', 'principal_01', 'owner', 'active'),
    ('workspace_02', 'principal_02', 'owner', 'active'),
    ('workspace_shared', 'principal_shared', 'owner', 'active');
INSERT INTO memories (
    workspace_id, id, subject_id, scope_type, kind, status,
    content_ciphertext, encryption_key_id, encryption_algorithm,
    encryption_nonce, version
) VALUES
    (
        'workspace_01', 'memory_01', 'principal_01', 'global',
        'preference', 'confirmed', '\x01', 'key_01',
        'xchacha20poly1305-ietf', decode(repeat('01', 24), 'hex'), 1
    ),
    (
        'workspace_02', 'memory_02', 'principal_02', 'global',
        'preference', 'confirmed', '\x02', 'key_02',
        'xchacha20poly1305-ietf', decode(repeat('02', 24), 'hex'), 1
    );
INSERT INTO memory_share_proposals (
    source_workspace_id, id, source_memory_id, source_memory_version,
    source_subject_id, target_workspace_id, target_scope_type, proposed_by,
    status
) VALUES
    (
        'workspace_01', 'proposal_01', 'memory_01', 1, 'principal_01',
        'workspace_shared', 'global', 'principal_01', 'pending'
    ),
    (
        'workspace_02', 'proposal_02', 'memory_02', 1, 'principal_02',
        'workspace_shared', 'global', 'principal_02', 'pending'
    );
SQL

psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 \
    -f migrations/postgres/0002_tenant_rls.sql

result=$(
    psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 -qAt <<'SQL'
BEGIN;
SET LOCAL ROLE rembrane_runtime_test;
SET LOCAL rembrane.workspace_id = 'workspace_01';
SELECT
    (SELECT count(*) FROM principals),
    (SELECT count(*) FROM workspaces),
    (SELECT count(*) FROM memberships),
    (SELECT count(*) FROM memories),
    (SELECT count(*) FROM memory_share_proposals);
ROLLBACK;
SQL
)
test "$result" = "1|1|1|1|1"

if psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<'SQL'
BEGIN;
SET LOCAL ROLE rembrane_runtime_test;
SET LOCAL rembrane.workspace_id = 'workspace_01';
INSERT INTO memories (
    workspace_id, id, subject_id, scope_type, kind, status,
    content_ciphertext, encryption_key_id, encryption_algorithm,
    encryption_nonce, version
) VALUES (
    'workspace_02', 'forbidden', 'principal_02', 'global',
    'preference', 'confirmed', '\x03', 'key_02',
    'xchacha20poly1305-ietf', decode(repeat('03', 24), 'hex'), 1
);
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
SELECT
    (SELECT count(*) FROM principals),
    (SELECT count(*) FROM workspaces),
    (SELECT count(*) FROM memberships),
    (SELECT count(*) FROM memories),
    (SELECT count(*) FROM memory_share_proposals);
ROLLBACK;
SQL
)
test "$unscoped" = "0|0|0|0|0"

echo "PostgreSQL two-tenant RLS test passed"
