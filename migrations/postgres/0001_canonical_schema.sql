BEGIN;

CREATE TABLE principals (
    id text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE workspaces (
    id text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('personal', 'shared')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE memberships (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    principal_id text NOT NULL REFERENCES principals (id),
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    status text NOT NULL CHECK (status IN ('active', 'suspended', 'removed')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, principal_id)
);

CREATE TABLE workspace_events (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    id text NOT NULL UNIQUE,
    actor_id text NOT NULL REFERENCES principals (id),
    subject_id text REFERENCES principals (id),
    event_type text NOT NULL,
    payload_ciphertext bytea NOT NULL CHECK (octet_length(payload_ciphertext) > 0),
    encryption_key_id text NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm text NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce bytea NOT NULL CHECK (octet_length(encryption_nonce) >= 12),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, sequence)
);

CREATE OR REPLACE FUNCTION rembrane_require_contiguous_workspace_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.sequence <> (
        SELECT COALESCE(MAX(sequence), 0) + 1
        FROM workspace_events
        WHERE workspace_id = NEW.workspace_id
    ) THEN
        RAISE EXCEPTION 'workspace event sequence conflict'
            USING ERRCODE = '40001';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER workspace_events_require_contiguous_sequence
BEFORE INSERT ON workspace_events
FOR EACH ROW EXECUTE FUNCTION rembrane_require_contiguous_workspace_event();

CREATE OR REPLACE FUNCTION rembrane_reject_workspace_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'workspace events are immutable'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER workspace_events_are_immutable
BEFORE UPDATE OR DELETE ON workspace_events
FOR EACH ROW EXECUTE FUNCTION rembrane_reject_workspace_event_mutation();

CREATE TABLE memories (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    subject_id text NOT NULL REFERENCES principals (id),
    scope_type text NOT NULL
        CHECK (scope_type IN ('global', 'domain', 'entity', 'activity')),
    scope_value text,
    kind text NOT NULL CHECK (
        kind IN (
            'preference',
            'semantic',
            'episodic',
            'procedural',
            'observation',
            'working'
        )
    ),
    status text NOT NULL
        CHECK (status IN ('proposed', 'confirmed', 'superseded', 'deleted')),
    content_ciphertext bytea NOT NULL CHECK (octet_length(content_ciphertext) > 0),
    encryption_key_id text NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm text NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce bytea NOT NULL CHECK (octet_length(encryption_nonce) >= 12),
    version bigint NOT NULL CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    CHECK (
        (scope_type = 'global' AND scope_value IS NULL)
        OR (scope_type <> 'global' AND length(scope_value) > 0)
    )
);

CREATE INDEX memories_subject_scope
ON memories (workspace_id, subject_id, scope_type, scope_value, status);

CREATE TABLE memory_evidence (
    workspace_id text NOT NULL,
    memory_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    evidence_id text NOT NULL,
    source_type text NOT NULL CHECK (
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
);

CREATE TABLE activity_checkpoints (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    subject_id text NOT NULL REFERENCES principals (id),
    activity_id text NOT NULL,
    entity_id text,
    checkpoint_ciphertext bytea NOT NULL
        CHECK (octet_length(checkpoint_ciphertext) > 0),
    encryption_key_id text NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm text NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce bytea NOT NULL CHECK (octet_length(encryption_nonce) >= 12),
    version bigint NOT NULL CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id)
);

CREATE INDEX activity_checkpoints_latest
ON activity_checkpoints (
    workspace_id,
    subject_id,
    activity_id,
    version DESC
);

CREATE TABLE disclosure_receipts (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    context_pack_id text NOT NULL,
    subject_id text NOT NULL REFERENCES principals (id),
    client_id text NOT NULL,
    purpose_code text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    UNIQUE (workspace_id, context_pack_id)
);

CREATE TABLE disclosed_memories (
    workspace_id text NOT NULL,
    disclosure_id text NOT NULL,
    memory_id text NOT NULL,
    memory_version bigint NOT NULL CHECK (memory_version > 0),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (workspace_id, disclosure_id, ordinal),
    FOREIGN KEY (workspace_id, disclosure_id)
        REFERENCES disclosure_receipts (workspace_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, memory_id)
        REFERENCES memories (workspace_id, id)
);

CREATE TABLE projection_outbox (
    id text PRIMARY KEY,
    workspace_id text NOT NULL,
    memory_id text NOT NULL,
    memory_version bigint NOT NULL CHECK (memory_version > 0),
    provider_id text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('upsert', 'delete')),
    status text NOT NULL
        CHECK (status IN ('pending', 'processing', 'completed', 'quarantined')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (
        workspace_id,
        memory_id,
        memory_version,
        provider_id,
        operation
    ),
    FOREIGN KEY (workspace_id, memory_id)
        REFERENCES memories (workspace_id, id)
);

CREATE INDEX projection_outbox_pending
ON projection_outbox (provider_id, status, available_at, id)
WHERE status = 'pending';

CREATE TABLE memory_share_proposals (
    source_workspace_id text NOT NULL,
    id text NOT NULL,
    source_memory_id text NOT NULL,
    source_memory_version bigint NOT NULL CHECK (source_memory_version > 0),
    source_subject_id text NOT NULL REFERENCES principals (id),
    target_workspace_id text NOT NULL REFERENCES workspaces (id),
    target_scope_type text NOT NULL
        CHECK (target_scope_type IN ('global', 'domain', 'entity', 'activity')),
    target_scope_value text NOT NULL DEFAULT '',
    proposed_by text NOT NULL REFERENCES principals (id),
    status text NOT NULL
        CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_workspace_id, id),
    FOREIGN KEY (source_workspace_id, source_memory_id)
        REFERENCES memories (workspace_id, id),
    CHECK (source_workspace_id <> target_workspace_id),
    CHECK (
        (target_scope_type = 'global' AND target_scope_value = '')
        OR (
            target_scope_type <> 'global'
            AND length(target_scope_value) > 0
        )
    )
);

CREATE UNIQUE INDEX memory_share_proposals_one_pending_intent
ON memory_share_proposals (
    source_workspace_id,
    source_memory_id,
    source_memory_version,
    target_workspace_id,
    target_scope_type,
    target_scope_value
)
WHERE status = 'pending';

CREATE INDEX memory_share_proposals_source_owner
ON memory_share_proposals (
    source_workspace_id,
    source_subject_id,
    status,
    created_at DESC
);

CREATE OR REPLACE FUNCTION rembrane_validate_memory_share_proposal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM memories AS source
        JOIN workspaces AS source_workspace
            ON source_workspace.id = source.workspace_id
        JOIN workspaces AS target_workspace
            ON target_workspace.id = NEW.target_workspace_id
        WHERE source.workspace_id = NEW.source_workspace_id
          AND source.id = NEW.source_memory_id
          AND source.version = NEW.source_memory_version
          AND source.subject_id = NEW.source_subject_id
          AND source.status = 'confirmed'
          AND source_workspace.kind = 'personal'
          AND target_workspace.kind = 'shared'
    ) THEN
        RAISE EXCEPTION 'share proposal source conflict'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER memory_share_proposals_validate_source
BEFORE INSERT ON memory_share_proposals
FOR EACH ROW EXECUTE FUNCTION rembrane_validate_memory_share_proposal();

COMMIT;
