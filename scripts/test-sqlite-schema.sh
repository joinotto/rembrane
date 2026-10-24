#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
database=$(mktemp "${TMPDIR:-/tmp}/rembrane-schema.sqlite.XXXXXX")
trap 'rm -f "$database"' EXIT

sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0001_canonical_schema.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0002_checkpoint_disclosures.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0003_workspace_invitations.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0004_member_scope_grants.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0005_memory_share_proposals.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0006_trips.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0007_booking_research.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0008_travel_disclosures.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0009_travel_sensitive_disclosures.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0010_travel_sensitive_profiles.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0011_knowledge_graph.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0012_graph_projection_outbox.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0013_workspace_key_rotations.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0014_key_rotation_receipts.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0015_administrative_audit.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0016_retention_and_legal_holds.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0017_channel_event_receipts.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0018_channel_sender_bindings.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0019_channel_binding_lifecycle.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0020_channel_binding_audit.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0021_encrypted_channel_inbox.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0022_channel_inbox_retry.sql"
sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0023_channel_inbox_leases.sql"
sqlite3 "$database" "PRAGMA user_version = 23;"

sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO principals (id) VALUES ('principal_01'), ('principal_02');
INSERT INTO workspaces (id, kind)
VALUES ('workspace_01', 'personal'), ('workspace_02', 'personal');
INSERT INTO memberships (workspace_id, principal_id, role, status)
VALUES
    ('workspace_01', 'principal_01', 'owner', 'active'),
    ('workspace_02', 'principal_02', 'owner', 'active');
INSERT INTO knowledge_nodes (
    workspace_id, id, node_ciphertext, encryption_key_id,
    encryption_algorithm, encryption_nonce, version,
    valid_from, valid_until, recorded_at
) VALUES
    (
        'workspace_01', 'node_project', X'01', 'key_01',
        'xchacha20poly1305', zeroblob(24), 1, 100, NULL, 100
    ),
    (
        'workspace_01', 'node_rust', X'02', 'key_01',
        'xchacha20poly1305', zeroblob(24), 1, 100, NULL, 100
    ),
    (
        'workspace_02', 'node_project', X'03', 'key_02',
        'xchacha20poly1305', zeroblob(24), 1, 100, NULL, 100
    ),
    (
        'workspace_02', 'node_external', X'04', 'key_02',
        'xchacha20poly1305', zeroblob(24), 1, 100, NULL, 100
    );
INSERT INTO knowledge_edges (
    workspace_id, id, source_id, target_id, supersedes_id,
    edge_ciphertext, encryption_key_id, encryption_algorithm,
    encryption_nonce, version, valid_from, valid_until, recorded_at
) VALUES (
    'workspace_01', 'edge_uses', 'node_project', 'node_rust', NULL,
    X'05', 'key_01', 'xchacha20poly1305', zeroblob(24),
    1, 100, 200, 100
);
INSERT INTO graph_projection_outbox (
    id, workspace_id, resource_type, node_id, edge_id,
    resource_version, provider_id, operation, status, attempts
) VALUES
    (
        'graph_projection_node', 'workspace_01', 'node',
        'node_project', NULL, 1, 'graph.primary', 'upsert', 'pending', 0
    ),
    (
        'graph_projection_edge', 'workspace_01', 'edge',
        NULL, 'edge_uses', 1, 'graph.primary', 'upsert', 'pending', 0
    );
INSERT INTO workspace_events (
    workspace_id,
    sequence,
    id,
    actor_id,
    subject_id,
    event_type,
    payload_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce
) VALUES (
    'workspace_01',
    1,
    'event_01',
    'principal_01',
    'principal_01',
    'memory-created',
    X'01',
    'key_01',
    'xchacha20poly1305',
    zeroblob(24)
);
INSERT INTO memories (
    workspace_id,
    id,
    subject_id,
    scope_type,
    scope_value,
    kind,
    status,
    content_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce,
    version
) VALUES
    (
        'workspace_01',
        'memory_01',
        'principal_01',
        'global',
        NULL,
        'preference',
        'confirmed',
        X'01',
        'key_01',
        'xchacha20poly1305',
        zeroblob(24),
        1
    ),
    (
        'workspace_02',
        'memory_01',
        'principal_02',
        'global',
        NULL,
        'preference',
        'confirmed',
        X'02',
        'key_02',
        'xchacha20poly1305',
        zeroblob(24),
        1
    ),
    (
        'workspace_01',
        'memory_deleted',
        'principal_01',
        'global',
        NULL,
        'preference',
        'deleted',
        X'03',
        'key_01',
        'xchacha20poly1305',
        zeroblob(24),
        2
    );
INSERT INTO memory_evidence (
    workspace_id,
    memory_id,
    ordinal,
    evidence_id,
    source_type
) VALUES (
    'workspace_01',
    'memory_01',
    0,
    'evidence_01',
    'user-statement'
);
INSERT INTO projection_outbox (
    id,
    workspace_id,
    memory_id,
    memory_version,
    provider_id,
    operation,
    status
) VALUES (
    'projection_01',
    'workspace_01',
    'memory_01',
    1,
    'semantic.primary',
    'upsert',
    'pending'
);
INSERT INTO activity_checkpoints (
    workspace_id,
    id,
    subject_id,
    activity_id,
    checkpoint_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce,
    version
) VALUES (
    'workspace_01',
    'checkpoint_01',
    'principal_01',
    'activity_01',
    X'01',
    'key_01',
    'xchacha20poly1305',
    zeroblob(24),
    1
);
INSERT INTO trips (
    workspace_id,
    id,
    owner_subject_id,
    trip_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce,
    version
) VALUES
    (
        'workspace_01',
        'trip_01',
        'principal_01',
        X'01',
        'key_01',
        'xchacha20poly1305',
        zeroblob(24),
        1
    ),
    (
        'workspace_02',
        'trip_01',
        'principal_02',
        X'02',
        'key_02',
        'xchacha20poly1305',
        zeroblob(24),
        1
    );
INSERT INTO booking_research (
    workspace_id,
    id,
    trip_id,
    observed_by,
    research_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce,
    version
) VALUES
    (
        'workspace_01',
        'research_01',
        'trip_01',
        'principal_01',
        X'03',
        'key_01',
        'xchacha20poly1305',
        zeroblob(24),
        1
    ),
    (
        'workspace_02',
        'research_01',
        'trip_01',
        'principal_02',
        X'04',
        'key_02',
        'xchacha20poly1305',
        zeroblob(24),
        1
    );
INSERT INTO travel_disclosure_receipts (
    workspace_id,
    id,
    subject_id,
    client_id,
    purpose_code,
    trip_id,
    trip_version,
    as_of
) VALUES (
    'workspace_01',
    'travel_disclosure_01',
    'principal_01',
    'assistant_01',
    'continue-flight-planning',
    'trip_01',
    1,
    '2026-10-24T10:00:00Z'
);
INSERT INTO disclosed_booking_research (
    workspace_id,
    disclosure_id,
    research_id,
    research_version,
    freshness,
    ordinal
) VALUES (
    'workspace_01',
    'travel_disclosure_01',
    'research_01',
    1,
    'fresh',
    0
);
INSERT INTO checkpoint_disclosures (
    workspace_id,
    id,
    checkpoint_id,
    checkpoint_version,
    activity_id,
    subject_id,
    client_id,
    purpose_code
) VALUES (
    'workspace_01',
    'checkpoint_disclosure_01',
    'checkpoint_01',
    1,
    'activity_01',
    'principal_01',
    'assistant_01',
    'resume-activity'
);
INSERT INTO workspaces (id, kind) VALUES ('workspace_shared', 'shared');
INSERT INTO memberships (workspace_id, principal_id, role, status)
VALUES ('workspace_shared', 'principal_01', 'owner', 'active');
INSERT INTO workspace_invitations (
    workspace_id,
    id,
    invited_principal_id,
    invited_by,
    role,
    status
) VALUES (
    'workspace_shared',
    'invitation_01',
    'principal_02',
    'principal_01',
    'member',
    'pending'
);
BEGIN IMMEDIATE;
UPDATE workspace_invitations
SET status = 'accepted'
WHERE workspace_id = 'workspace_shared'
  AND id = 'invitation_01'
  AND status = 'pending';
INSERT INTO memberships (workspace_id, principal_id, role, status)
VALUES ('workspace_shared', 'principal_02', 'member', 'active');
INSERT INTO member_scope_grants (
    workspace_id,
    principal_id,
    scope_type,
    scope_value
) VALUES (
    'workspace_shared',
    'principal_02',
    'entity',
    'project_01'
);
INSERT INTO memory_share_proposals (
    source_workspace_id,
    id,
    source_memory_id,
    source_memory_version,
    source_subject_id,
    target_workspace_id,
    target_scope_type,
    target_scope_value,
    proposed_by,
    status
) VALUES (
    'workspace_01',
    'share_01',
    'memory_01',
    1,
    'principal_01',
    'workspace_shared',
    'global',
    '',
    'principal_01',
    'pending'
);
COMMIT;
SQL

if sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO graph_projection_outbox (
    id, workspace_id, resource_type, node_id, edge_id,
    resource_version, provider_id, operation, status, attempts
) VALUES (
    'graph_projection_node_duplicate', 'workspace_01', 'node',
    'node_project', NULL, 1, 'graph.primary', 'upsert', 'pending', 0
);
SQL
then
    echo "duplicate graph node projection unexpectedly succeeded" >&2
    exit 1
fi

if sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO knowledge_edges (
    workspace_id, id, source_id, target_id, supersedes_id,
    edge_ciphertext, encryption_key_id, encryption_algorithm,
    encryption_nonce, version, valid_from, valid_until, recorded_at
) VALUES (
    'workspace_01', 'edge_cross_tenant', 'node_project', 'node_external', NULL,
    X'06', 'key_01', 'xchacha20poly1305', zeroblob(24),
    1, 100, NULL, 100
);
SQL
then
    echo "cross-workspace knowledge edge unexpectedly succeeded" >&2
    exit 1
fi

if sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO memory_evidence (
    workspace_id,
    memory_id,
    ordinal,
    evidence_id,
    source_type
) VALUES (
    'workspace_02',
    'memory_missing',
    0,
    'evidence_cross_workspace',
    'user-statement'
);
SQL
then
    echo "cross-workspace evidence unexpectedly succeeded" >&2
    exit 1
fi

if sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO workspace_events (
    workspace_id,
    sequence,
    id,
    actor_id,
    event_type,
    payload_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce
) VALUES (
    'workspace_01',
    3,
    'event_gap',
    'principal_01',
    'invalid-gap',
    X'01',
    'key_01',
    'xchacha20poly1305',
    zeroblob(24)
);
SQL
then
    echo "workspace event sequence gap unexpectedly succeeded" >&2
    exit 1
fi

if sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO projection_outbox (
    id,
    workspace_id,
    memory_id,
    memory_version,
    provider_id,
    operation,
    status
) VALUES (
    'projection_duplicate',
    'workspace_01',
    'memory_01',
    1,
    'semantic.primary',
    'upsert',
    'pending'
);
SQL
then
    echo "duplicate projection unexpectedly succeeded" >&2
    exit 1
fi

if sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO memory_share_proposals (
    source_workspace_id, id, source_memory_id, source_memory_version,
    source_subject_id, target_workspace_id, target_scope_type,
    target_scope_value, proposed_by, status
) VALUES (
    'workspace_01', 'share_stale', 'memory_01', 2,
    'principal_01', 'workspace_shared', 'global', '',
    'principal_01', 'pending'
);
SQL
then
    echo "stale share proposal unexpectedly succeeded" >&2
    exit 1
fi

if sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO memory_share_proposals (
    source_workspace_id, id, source_memory_id, source_memory_version,
    source_subject_id, target_workspace_id, target_scope_type,
    target_scope_value, proposed_by, status
) VALUES (
    'workspace_01', 'share_to_personal', 'memory_01', 1,
    'principal_01', 'workspace_02', 'global', '',
    'principal_01', 'pending'
);
SQL
then
    echo "share proposal targeting a personal workspace unexpectedly succeeded" >&2
    exit 1
fi

sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO workspace_key_rotations (
    workspace_id, id, generation, removed_principal_id, requested_by, status
) VALUES (
    'workspace_shared', 'rotation_01', 1,
    'principal_02', 'principal_01', 'required'
);
SQL

if sqlite3 "$database" <<'SQL'
.bail on
PRAGMA foreign_keys = ON;
INSERT INTO workspace_key_rotations (
    workspace_id, id, generation, removed_principal_id, requested_by, status
) VALUES (
    'workspace_shared', 'rotation_02', 2,
    'principal_02', 'principal_01', 'required'
);
SQL
then
    echo "second required workspace key rotation unexpectedly succeeded" >&2
    exit 1
fi

sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
UPDATE workspace_key_rotations
SET status = 'completed',
    completed_key_id = 'workspace-key:v1',
    completed_by = 'principal_01',
    completed_at = CURRENT_TIMESTAMP
WHERE workspace_id = 'workspace_shared' AND id = 'rotation_01';
INSERT INTO workspace_key_rotation_receipts (
    workspace_id, rotation_id, provider_id, request_id, generation, key_id
) VALUES (
    'workspace_shared', 'rotation_01', 'customer.kms',
    'rotation-request-01', 1, 'workspace-key:v1'
);
INSERT INTO workspace_key_rotation_recipients (
    workspace_id, rotation_id, principal_id
) VALUES (
    'workspace_shared', 'rotation_01', 'principal_01'
);
INSERT INTO administrative_audit_events (
    workspace_id, id, actor_id, action, target_kind, target_id,
    request_id, occurred_at_epoch_seconds
) VALUES (
    'workspace_01', 'audit_01', 'principal_01', 'member-removed',
    'principal', 'principal_02', 'request_01', 100
);
INSERT INTO workspace_retention_policies (
    workspace_id, version, user_memory_days, activity_checkpoint_days,
    travel_research_days, disclosure_receipt_days, canonical_event_days,
    administrative_audit_days
) VALUES ('workspace_01', 1, 30, 7, 14, 90, 365, 365);
INSERT INTO workspace_legal_holds (
    workspace_id, id, placed_by, placed_at_epoch_seconds, status, version
) VALUES ('workspace_01', 'hold_01', 'principal_01', 100, 'active', 1);
SQL

if sqlite3 "$database" \
    "UPDATE administrative_audit_events SET target_id = 'changed' WHERE id = 'audit_01';"
then
    echo "append-only administrative audit update unexpectedly succeeded" >&2
    exit 1
fi
if sqlite3 "$database" \
    "DELETE FROM administrative_audit_events WHERE id = 'audit_01';"
then
    echo "append-only administrative audit deletion unexpectedly succeeded" >&2
    exit 1
fi
sqlite3 "$database" "
    INSERT INTO channel_event_receipts (
        channel, event_id, workspace_id,
        accepted_at_epoch_seconds, expires_at_epoch_seconds
    ) VALUES (
        'whatsapp-business', 'event_channel_01', 'workspace_01', 1000, 1100
    );
    INSERT INTO channel_event_receipts (
        channel, event_id, workspace_id,
        accepted_at_epoch_seconds, expires_at_epoch_seconds
    ) VALUES (
        'imessage-extension', 'event_channel_01', 'workspace_02', 1000, 1100
    );
"
sqlite3 "$database" "
    INSERT INTO channel_sender_bindings (
        channel, account_lookup_key, sender_lookup_key,
        workspace_id, principal_id, client_id
    ) VALUES (
        'whatsapp-business', 'hmac-account-01', 'hmac-sender-01',
        'workspace_01', 'principal_01', 'client_whatsapp_01'
    );
"
if sqlite3 "$database" "
    INSERT INTO channel_event_receipts (
        channel, event_id, workspace_id,
        accepted_at_epoch_seconds, expires_at_epoch_seconds
    ) VALUES (
        'whatsapp-business', 'event_channel_01', 'workspace_02', 1001, 1101
    );
"
then
    echo "cross-workspace channel replay unexpectedly succeeded" >&2
    exit 1
fi

table_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table';"
)

test "$table_count" -ge 9
test "$(sqlite3 "$database" "PRAGMA user_version;")" -eq 23
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM channel_event_receipts WHERE event_id = 'event_channel_01';"
)" -eq 2
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM channel_sender_bindings WHERE workspace_id = 'workspace_01' AND principal_id = 'principal_01';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM pragma_table_info('channel_event_receipts') WHERE name IN ('text', 'content', 'principal_id', 'client_id');"
)" -eq 0
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM graph_projection_outbox WHERE provider_id = 'graph.primary' AND status = 'pending';"
)" -eq 2
test "$(
    sqlite3 "$database" "
        UPDATE graph_projection_outbox
        SET status = 'processing', attempts = 1
        WHERE id = 'graph_projection_node'
          AND workspace_id = 'workspace_01'
          AND resource_type = 'node'
          AND node_id IS 'node_project'
          AND edge_id IS NULL
          AND resource_version = 1
          AND provider_id = 'graph.primary'
          AND operation = 'upsert'
          AND status = 'pending'
          AND attempts = 0;
        SELECT changes();
    "
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM graph_projection_outbox WHERE id = 'graph_projection_node' AND status = 'processing' AND attempts = 1;"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM graph_projection_outbox WHERE workspace_id = 'workspace_02' AND id = 'graph_projection_node';"
)" -eq 0
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM knowledge_nodes WHERE workspace_id = 'workspace_01';"
)" -eq 2
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM knowledge_edges WHERE workspace_id = 'workspace_01' AND source_id = 'node_project' AND valid_from <= 150 AND (valid_until IS NULL OR valid_until > 150);"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM checkpoint_disclosures;"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM trips WHERE id = 'trip_01';"
)" -eq 2
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM booking_research WHERE id = 'research_01';"
)" -eq 2
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM travel_disclosure_receipts WHERE workspace_id = 'workspace_01' AND trip_id = 'trip_01' AND trip_version = 1 AND source_references_included = 0 AND sensitive_profile_included = 0;"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM disclosed_booking_research WHERE workspace_id = 'workspace_01' AND research_id = 'research_01' AND research_version = 1 AND freshness = 'fresh';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'workspace_invitations';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM workspace_invitations WHERE workspace_id = 'workspace_shared' AND status = 'accepted';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM memberships WHERE workspace_id = 'workspace_shared' AND principal_id = 'principal_02' AND role = 'member' AND status = 'active';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM member_scope_grants WHERE workspace_id = 'workspace_shared' AND principal_id = 'principal_02' AND scope_type = 'entity' AND scope_value = 'project_01';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM memory_share_proposals WHERE source_workspace_id = 'workspace_01' AND id = 'share_01' AND status = 'pending';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM workspace_key_rotations WHERE workspace_id = 'workspace_shared' AND generation = 1 AND status = 'completed';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM workspace_key_rotation_receipts WHERE workspace_id = 'workspace_shared' AND rotation_id = 'rotation_01' AND provider_id = 'customer.kms';"
)" -eq 1
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM workspace_key_rotation_recipients WHERE workspace_id = 'workspace_shared' AND rotation_id = 'rotation_01' AND principal_id = 'principal_01';"
)" -eq 1
echo "sqlite schema checks passed"
