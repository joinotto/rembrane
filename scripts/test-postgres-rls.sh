#!/bin/sh
set -eu

: "${REMBRANE_POSTGRES_URL:?REMBRANE_POSTGRES_URL is required}"

psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA IF EXISTS rembrane CASCADE;
DROP TABLE IF EXISTS
    channel_inbox,
    channel_sender_bindings,
    channel_event_receipts,
    graph_projection_outbox,
    knowledge_edges,
    knowledge_nodes,
    disclosed_booking_research,
    travel_disclosure_receipts,
    booking_research,
    trips,
    checkpoint_disclosures,
    workspace_legal_holds,
    workspace_retention_policies,
    administrative_audit_events,
    workspace_key_rotation_recipients,
    workspace_key_rotation_receipts,
    workspace_key_rotations,
    member_scope_grants,
    workspace_invitations,
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
psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 \
    -f migrations/postgres/0002_workspace_administration.sql
psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 \
    -f migrations/postgres/0003_travel_continuity.sql
psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 \
    -f migrations/postgres/0004_knowledge_graph.sql
psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 \
    -f migrations/postgres/0005_channel_continuity.sql

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
INSERT INTO workspace_invitations (
    workspace_id, id, invited_principal_id, invited_by, role, status,
    created_at_epoch_seconds, expires_at_epoch_seconds
) VALUES
    (
        'workspace_01', 'invitation_01', 'principal_02', 'principal_01',
        'viewer', 'pending', 1000, 2000
    ),
    (
        'workspace_02', 'invitation_02', 'principal_01', 'principal_02',
        'viewer', 'pending', 1000, 2000
    );
INSERT INTO member_scope_grants (
    workspace_id, principal_id, scope_type, scope_value
) VALUES
    ('workspace_01', 'principal_01', 'entity', 'project_01'),
    ('workspace_02', 'principal_02', 'entity', 'project_02');
INSERT INTO workspace_retention_policies (
    workspace_id, version, user_memory_days, disclosure_receipt_days
) VALUES
    ('workspace_01', 1, 365, 730),
    ('workspace_02', 1, 180, 365);
INSERT INTO administrative_audit_events (
    workspace_id, id, actor_id, action, target_kind, target_id,
    request_id, occurred_at_epoch_seconds
) VALUES
    (
        'workspace_01', 'audit_01', 'principal_01',
        'retention-policy-changed', 'retention-policy', 'workspace_01',
        'request_01', 1
    ),
    (
        'workspace_02', 'audit_02', 'principal_02',
        'retention-policy-changed', 'retention-policy', 'workspace_02',
        'request_02', 1
    );
INSERT INTO trips (
    workspace_id, id, owner_subject_id, trip_ciphertext,
    encryption_key_id, encryption_algorithm, encryption_nonce, version
) VALUES
    (
        'workspace_01', 'trip_01', 'principal_01', '\x11', 'key_01',
        'xchacha20poly1305-ietf', decode(repeat('11', 24), 'hex'), 1
    ),
    (
        'workspace_02', 'trip_02', 'principal_02', '\x12', 'key_02',
        'xchacha20poly1305-ietf', decode(repeat('12', 24), 'hex'), 1
    );
INSERT INTO booking_research (
    workspace_id, id, trip_id, observed_by, research_ciphertext,
    encryption_key_id, encryption_algorithm, encryption_nonce, version
) VALUES
    (
        'workspace_01', 'research_01', 'trip_01', 'principal_01', '\x21',
        'key_01', 'xchacha20poly1305-ietf',
        decode(repeat('21', 24), 'hex'), 1
    ),
    (
        'workspace_02', 'research_02', 'trip_02', 'principal_02', '\x22',
        'key_02', 'xchacha20poly1305-ietf',
        decode(repeat('22', 24), 'hex'), 1
    );
INSERT INTO travel_disclosure_receipts (
    workspace_id, id, subject_id, client_id, purpose_code, trip_id,
    trip_version, as_of, source_references_included,
    sensitive_profile_included
) VALUES
    (
        'workspace_01', 'travel_disclosure_01', 'principal_01', 'client_01',
        'travel-handoff', 'trip_01', 1, '2026-10-24T00:00:00Z', true, false
    ),
    (
        'workspace_02', 'travel_disclosure_02', 'principal_02', 'client_02',
        'travel-handoff', 'trip_02', 1, '2026-10-24T00:00:00Z', false, true
    );
INSERT INTO disclosed_booking_research (
    workspace_id, disclosure_id, research_id, research_version,
    freshness, ordinal
) VALUES
    (
        'workspace_01', 'travel_disclosure_01', 'research_01', 1,
        'fresh', 0
    ),
    (
        'workspace_02', 'travel_disclosure_02', 'research_02', 1,
        'expired', 0
    );
INSERT INTO knowledge_nodes (
    workspace_id, id, node_ciphertext, encryption_key_id,
    encryption_algorithm, encryption_nonce, version, valid_from, recorded_at
) VALUES
    (
        'workspace_01', 'node_01a', '\x31', 'key_01',
        'xchacha20poly1305-ietf', decode(repeat('31', 24), 'hex'), 1, 1, 1
    ),
    (
        'workspace_01', 'node_01b', '\x32', 'key_01',
        'xchacha20poly1305-ietf', decode(repeat('32', 24), 'hex'), 1, 1, 1
    ),
    (
        'workspace_02', 'node_02a', '\x33', 'key_02',
        'xchacha20poly1305-ietf', decode(repeat('33', 24), 'hex'), 1, 1, 1
    ),
    (
        'workspace_02', 'node_02b', '\x34', 'key_02',
        'xchacha20poly1305-ietf', decode(repeat('34', 24), 'hex'), 1, 1, 1
    );
INSERT INTO knowledge_edges (
    workspace_id, id, source_id, target_id, edge_ciphertext,
    encryption_key_id, encryption_algorithm, encryption_nonce, version,
    valid_from, recorded_at
) VALUES
    (
        'workspace_01', 'edge_01', 'node_01a', 'node_01b', '\x41', 'key_01',
        'xchacha20poly1305-ietf', decode(repeat('41', 24), 'hex'), 1, 1, 1
    ),
    (
        'workspace_02', 'edge_02', 'node_02a', 'node_02b', '\x42', 'key_02',
        'xchacha20poly1305-ietf', decode(repeat('42', 24), 'hex'), 1, 1, 1
    );
INSERT INTO graph_projection_outbox (
    id, workspace_id, resource_type, node_id, resource_version, provider_id,
    operation, status
) VALUES
    (
        'graph_job_01', 'workspace_01', 'node', 'node_01a', 1,
        'provider_graph', 'upsert', 'pending'
    ),
    (
        'graph_job_02', 'workspace_02', 'node', 'node_02a', 1,
        'provider_graph', 'upsert', 'pending'
    );
INSERT INTO channel_event_receipts (
    channel, event_id, workspace_id, accepted_at_epoch_seconds,
    expires_at_epoch_seconds
) VALUES
    ('mobile-share', 'event_01', 'workspace_01', 1, 3601),
    ('mobile-share', 'event_02', 'workspace_02', 1, 3601);
INSERT INTO channel_sender_bindings (
    channel, account_lookup_key, sender_lookup_key, workspace_id,
    principal_id, client_id
) VALUES
    (
        'mobile-share', 'account_01', 'sender_01', 'workspace_01',
        'principal_01', 'client_01'
    ),
    (
        'mobile-share', 'account_02', 'sender_02', 'workspace_02',
        'principal_02', 'client_02'
    );
INSERT INTO channel_inbox (
    channel, event_id, workspace_id, principal_id, client_id,
    received_at_epoch_seconds, text_ciphertext, encryption_key_id,
    encryption_algorithm, encryption_nonce, available_at_epoch_seconds
) VALUES
    (
        'mobile-share', 'inbox_01', 'workspace_01', 'principal_01',
        'client_01', 1, '\x51', 'key_01', 'xchacha20poly1305-ietf',
        decode(repeat('51', 24), 'hex'), 1
    ),
    (
        'mobile-share', 'inbox_02', 'workspace_02', 'principal_02',
        'client_02', 1, '\x52', 'key_02', 'xchacha20poly1305-ietf',
        decode(repeat('52', 24), 'hex'), 1
    );
SQL

psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 \
    -f migrations/postgres/9999_tenant_rls.sql

unprotected_tables=$(
    psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 -qAt <<'SQL'
SELECT count(*)
FROM information_schema.columns AS columns
JOIN pg_catalog.pg_class AS relation
  ON relation.relname = columns.table_name
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
 AND namespace.nspname = columns.table_schema
WHERE columns.table_schema = 'public'
  AND columns.column_name = 'workspace_id'
  AND (
      NOT relation.relrowsecurity
      OR NOT relation.relforcerowsecurity
  );
SQL
)
test "$unprotected_tables" = "0"

result=$(
    psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 -qAt <<'SQL'
BEGIN;
SET LOCAL ROLE rembrane_runtime_test;
SELECT set_config('rembrane.workspace_id', 'workspace_01', true);
SELECT
    (SELECT count(*) FROM principals),
    (SELECT count(*) FROM workspaces),
    (SELECT count(*) FROM memberships),
    (SELECT count(*) FROM memories),
    (SELECT count(*) FROM memory_share_proposals),
    (SELECT count(*) FROM workspace_invitations),
    (SELECT count(*) FROM member_scope_grants),
    (SELECT count(*) FROM workspace_retention_policies),
    (SELECT count(*) FROM administrative_audit_events),
    (SELECT count(*) FROM trips),
    (SELECT count(*) FROM booking_research),
    (SELECT count(*) FROM travel_disclosure_receipts),
    (SELECT count(*) FROM disclosed_booking_research),
    (SELECT count(*) FROM knowledge_nodes),
    (SELECT count(*) FROM knowledge_edges),
    (SELECT count(*) FROM graph_projection_outbox),
    (SELECT count(*) FROM channel_event_receipts),
    (SELECT count(*) FROM channel_sender_bindings),
    (SELECT count(*) FROM channel_inbox);
ROLLBACK;
SQL
)
test "$result" = "1|1|1|1|1|1|1|1|1|1|1|1|1|2|1|1|1|1|1"

if psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<'SQL'
BEGIN;
SET LOCAL ROLE rembrane_runtime_test;
SELECT set_config('rembrane.workspace_id', 'workspace_01', true);
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
    (SELECT count(*) FROM memory_share_proposals),
    (SELECT count(*) FROM workspace_invitations),
    (SELECT count(*) FROM member_scope_grants),
    (SELECT count(*) FROM workspace_retention_policies),
    (SELECT count(*) FROM administrative_audit_events),
    (SELECT count(*) FROM trips),
    (SELECT count(*) FROM booking_research),
    (SELECT count(*) FROM travel_disclosure_receipts),
    (SELECT count(*) FROM disclosed_booking_research),
    (SELECT count(*) FROM knowledge_nodes),
    (SELECT count(*) FROM knowledge_edges),
    (SELECT count(*) FROM graph_projection_outbox),
    (SELECT count(*) FROM channel_event_receipts),
    (SELECT count(*) FROM channel_sender_bindings),
    (SELECT count(*) FROM channel_inbox);
ROLLBACK;
SQL
)
test "$unscoped" = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0"

pooled_connection_result=$(
    psql "$REMBRANE_POSTGRES_URL" -v ON_ERROR_STOP=1 -qAt <<'SQL'
SET ROLE rembrane_runtime_test;
BEGIN;
SELECT set_config('rembrane.workspace_id', 'workspace_01', true);
SELECT count(*) FROM memories;
COMMIT;
SELECT count(*) FROM memories;
RESET ROLE;
SQL
)
test "$pooled_connection_result" = "workspace_01
1
0"

echo "PostgreSQL two-tenant RLS test passed"
