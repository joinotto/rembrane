CREATE TABLE memory_share_proposals (
    source_workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    source_memory_id TEXT NOT NULL,
    source_memory_version INTEGER NOT NULL CHECK (source_memory_version > 0),
    source_subject_id TEXT NOT NULL,
    target_workspace_id TEXT NOT NULL,
    target_scope_type TEXT NOT NULL
        CHECK (target_scope_type IN ('global', 'domain', 'entity', 'activity')),
    target_scope_value TEXT NOT NULL DEFAULT '',
    proposed_by TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_workspace_id, id),
    FOREIGN KEY (source_workspace_id, source_memory_id)
        REFERENCES memories (workspace_id, id),
    FOREIGN KEY (source_subject_id) REFERENCES principals (id),
    FOREIGN KEY (target_workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (proposed_by) REFERENCES principals (id),
    CHECK (source_workspace_id != target_workspace_id),
    CHECK (
        (target_scope_type = 'global' AND target_scope_value = '')
        OR (
            target_scope_type != 'global'
            AND length(target_scope_value) > 0
        )
    )
) STRICT;

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

CREATE TRIGGER memory_share_proposals_validate_source
BEFORE INSERT ON memory_share_proposals
FOR EACH ROW
WHEN NOT EXISTS (
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
)
BEGIN
    SELECT RAISE(ABORT, 'share proposal source conflict');
END;
