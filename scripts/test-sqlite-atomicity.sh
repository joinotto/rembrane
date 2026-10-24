#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
database=$(mktemp "${TMPDIR:-/tmp}/rembrane-atomicity.sqlite.XXXXXX")
trap 'rm -f "$database"' EXIT

sqlite3 "$database" < \
    "$repository_root/migrations/sqlite/0001_canonical_schema.sql"

sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
INSERT INTO principals (id) VALUES ('principal_01');
INSERT INTO workspaces (id, kind) VALUES ('workspace_01', 'personal');
INSERT INTO memberships (workspace_id, principal_id, role, status)
VALUES ('workspace_01', 'principal_01', 'owner', 'active');
SQL

if sqlite3 "$database" <<'SQL'
.bail on
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;
INSERT INTO memories (
    workspace_id,
    id,
    subject_id,
    scope_type,
    kind,
    status,
    content_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce,
    version
) VALUES (
    'workspace_01',
    'memory_rollback',
    'principal_01',
    'global',
    'preference',
    'confirmed',
    X'01',
    'key_01',
    'xchacha20poly1305',
    zeroblob(24),
    1
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
    'event_rollback',
    'principal_01',
    'principal_01',
    'memory-created',
    X'01',
    'key_01',
    'xchacha20poly1305',
    zeroblob(24)
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
    'projection_rollback',
    'workspace_01',
    'memory_missing',
    1,
    'semantic.primary',
    'upsert',
    'pending'
);
COMMIT;
SQL
then
    echo "invalid atomic mutation unexpectedly succeeded" >&2
    exit 1
fi

rollback_counts=$(
    sqlite3 "$database" <<'SQL'
SELECT
    (SELECT count(*) FROM memories WHERE id = 'memory_rollback')
    || ':'
    || (SELECT count(*) FROM workspace_events WHERE id = 'event_rollback')
    || ':'
    || (SELECT count(*) FROM projection_outbox WHERE id = 'projection_rollback');
SQL
)
test "$rollback_counts" = "0:0:0"

sqlite3 "$database" <<'SQL'
.bail on
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;
INSERT INTO memories (
    workspace_id,
    id,
    subject_id,
    scope_type,
    kind,
    status,
    content_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce,
    version
) VALUES (
    'workspace_01',
    'memory_commit',
    'principal_01',
    'global',
    'preference',
    'confirmed',
    X'01',
    'key_01',
    'xchacha20poly1305',
    zeroblob(24),
    1
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
    'event_commit',
    'principal_01',
    'principal_01',
    'memory-created',
    X'01',
    'key_01',
    'xchacha20poly1305',
    zeroblob(24)
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
    'projection_commit',
    'workspace_01',
    'memory_commit',
    1,
    'semantic.primary',
    'upsert',
    'pending'
);
COMMIT;
SQL

commit_counts=$(
    sqlite3 "$database" <<'SQL'
SELECT
    (SELECT count(*) FROM memories WHERE id = 'memory_commit')
    || ':'
    || (SELECT count(*) FROM workspace_events WHERE id = 'event_commit')
    || ':'
    || (SELECT count(*) FROM projection_outbox WHERE id = 'projection_commit');
SQL
)
test "$commit_counts" = "1:1:1"

echo "sqlite atomicity checks passed"
