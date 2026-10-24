CREATE TABLE workspace_retention_policies (
    workspace_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version > 0),
    user_memory_days INTEGER CHECK (user_memory_days BETWEEN 1 AND 36500),
    activity_checkpoint_days INTEGER CHECK (activity_checkpoint_days BETWEEN 1 AND 36500),
    travel_research_days INTEGER CHECK (travel_research_days BETWEEN 1 AND 36500),
    disclosure_receipt_days INTEGER CHECK (disclosure_receipt_days BETWEEN 1 AND 36500),
    canonical_event_days INTEGER CHECK (canonical_event_days BETWEEN 1 AND 36500),
    administrative_audit_days INTEGER CHECK (administrative_audit_days BETWEEN 1 AND 36500),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id)
) STRICT;

CREATE TABLE workspace_legal_holds (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    placed_by TEXT NOT NULL,
    placed_at_epoch_seconds INTEGER NOT NULL CHECK (placed_at_epoch_seconds > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'released')),
    version INTEGER NOT NULL CHECK (version > 0),
    released_by TEXT,
    released_at_epoch_seconds INTEGER,
    PRIMARY KEY (workspace_id, id),
    CHECK (
        (status = 'active' AND released_by IS NULL AND released_at_epoch_seconds IS NULL)
        OR
        (status = 'released' AND released_by IS NOT NULL AND released_at_epoch_seconds >= placed_at_epoch_seconds)
    ),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (workspace_id, placed_by)
        REFERENCES memberships (workspace_id, principal_id),
    FOREIGN KEY (workspace_id, released_by)
        REFERENCES memberships (workspace_id, principal_id)
) STRICT;

CREATE INDEX workspace_legal_holds_active
    ON workspace_legal_holds (workspace_id, status);
