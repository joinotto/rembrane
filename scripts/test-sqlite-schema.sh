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
sqlite3 "$database" "PRAGMA user_version = 6;"

sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO principals (id) VALUES ('principal_01'), ('principal_02');
INSERT INTO workspaces (id, kind)
VALUES ('workspace_01', 'personal'), ('workspace_02', 'personal');
INSERT INTO memberships (workspace_id, principal_id, role, status)
VALUES
    ('workspace_01', 'principal_01', 'owner', 'active'),
    ('workspace_02', 'principal_02', 'owner', 'active');
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

table_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table';"
)

test "$table_count" -ge 9
test "$(sqlite3 "$database" "PRAGMA user_version;")" -eq 6
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
echo "sqlite schema checks passed"
