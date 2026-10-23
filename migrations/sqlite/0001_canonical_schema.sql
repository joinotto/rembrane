PRAGMA foreign_keys = ON;

CREATE TABLE principals (
    id TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE workspaces (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('personal', 'shared')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE memberships (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'removed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, principal_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (principal_id) REFERENCES principals (id)
) STRICT;

CREATE TABLE workspace_events (
    workspace_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    subject_id TEXT,
    event_type TEXT NOT NULL,
    payload_ciphertext BLOB NOT NULL,
    encryption_key_id TEXT NOT NULL,
    encryption_algorithm TEXT NOT NULL,
    encryption_nonce BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, sequence),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (actor_id) REFERENCES principals (id),
    FOREIGN KEY (subject_id) REFERENCES principals (id),
    CHECK (length(payload_ciphertext) > 0),
    CHECK (length(encryption_key_id) > 0),
    CHECK (length(encryption_algorithm) > 0),
    CHECK (length(encryption_nonce) >= 12)
) STRICT;

CREATE TRIGGER workspace_events_require_contiguous_sequence
BEFORE INSERT ON workspace_events
FOR EACH ROW
WHEN NEW.sequence != (
    SELECT COALESCE(MAX(sequence), 0) + 1
    FROM workspace_events
    WHERE workspace_id = NEW.workspace_id
)
BEGIN
    SELECT RAISE(ABORT, 'workspace event sequence conflict');
END;

CREATE TRIGGER workspace_events_are_immutable
BEFORE UPDATE ON workspace_events
BEGIN
    SELECT RAISE(ABORT, 'workspace events are immutable');
END;

CREATE TABLE memories (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    scope_type TEXT NOT NULL
        CHECK (scope_type IN ('global', 'domain', 'entity', 'activity')),
    scope_value TEXT,
    kind TEXT NOT NULL CHECK (
        kind IN (
            'preference',
            'semantic',
            'episodic',
            'procedural',
            'observation',
            'working'
        )
    ),
    status TEXT NOT NULL
        CHECK (status IN ('proposed', 'confirmed', 'superseded', 'deleted')),
    content_ciphertext BLOB NOT NULL,
    encryption_key_id TEXT NOT NULL,
    encryption_algorithm TEXT NOT NULL,
    encryption_nonce BLOB NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (subject_id) REFERENCES principals (id),
    CHECK (
        (scope_type = 'global' AND scope_value IS NULL)
        OR (scope_type != 'global' AND length(scope_value) > 0)
    ),
    CHECK (length(content_ciphertext) > 0),
    CHECK (length(encryption_key_id) > 0),
    CHECK (length(encryption_algorithm) > 0),
    CHECK (length(encryption_nonce) >= 12)
) STRICT;

CREATE INDEX memories_subject_scope
ON memories (workspace_id, subject_id, scope_type, scope_value, status);

CREATE TABLE memory_evidence (
    workspace_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    evidence_id TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (
        source_type IN (
            'user-statement',
            'agent-observation',
            'tool-result',
            'imported-record',
            'workspace-decision'
        )
    ),
    PRIMARY KEY (workspace_id, memory_id, ordinal),
    UNIQUE (workspace_id, memory_id, evidence_id),
    FOREIGN KEY (workspace_id, memory_id)
        REFERENCES memories (workspace_id, id)
        ON DELETE CASCADE
) STRICT;

CREATE TABLE activity_checkpoints (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    activity_id TEXT NOT NULL,
    entity_id TEXT,
    checkpoint_ciphertext BLOB NOT NULL,
    encryption_key_id TEXT NOT NULL,
    encryption_algorithm TEXT NOT NULL,
    encryption_nonce BLOB NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (subject_id) REFERENCES principals (id),
    CHECK (length(checkpoint_ciphertext) > 0),
    CHECK (length(encryption_key_id) > 0),
    CHECK (length(encryption_algorithm) > 0),
    CHECK (length(encryption_nonce) >= 12)
) STRICT;

CREATE INDEX activity_checkpoints_latest
ON activity_checkpoints (
    workspace_id,
    subject_id,
    activity_id,
    version DESC
);

CREATE TABLE disclosure_receipts (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    context_pack_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    purpose_code TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    UNIQUE (workspace_id, context_pack_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (subject_id) REFERENCES principals (id)
) STRICT;

CREATE TABLE disclosed_memories (
    workspace_id TEXT NOT NULL,
    disclosure_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    memory_version INTEGER NOT NULL CHECK (memory_version > 0),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (workspace_id, disclosure_id, ordinal),
    FOREIGN KEY (workspace_id, disclosure_id)
        REFERENCES disclosure_receipts (workspace_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, memory_id)
        REFERENCES memories (workspace_id, id)
) STRICT;

CREATE TABLE projection_outbox (
    id TEXT PRIMARY KEY NOT NULL,
    workspace_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    memory_version INTEGER NOT NULL CHECK (memory_version > 0),
    provider_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('upsert', 'delete')),
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'processing', 'completed', 'quarantined')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (
        workspace_id,
        memory_id,
        memory_version,
        provider_id,
        operation
    ),
    FOREIGN KEY (workspace_id, memory_id)
        REFERENCES memories (workspace_id, id)
) STRICT;

CREATE INDEX projection_outbox_pending
ON projection_outbox (provider_id, status, available_at, id)
WHERE status = 'pending';
