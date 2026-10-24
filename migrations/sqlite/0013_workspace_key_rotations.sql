CREATE TABLE workspace_key_rotations (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL CHECK (generation > 0),
    removed_principal_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('required', 'completed')),
    completed_key_id TEXT,
    completed_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    PRIMARY KEY (workspace_id, generation),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (workspace_id, removed_principal_id)
        REFERENCES memberships (workspace_id, principal_id),
    FOREIGN KEY (workspace_id, requested_by)
        REFERENCES memberships (workspace_id, principal_id),
    FOREIGN KEY (workspace_id, completed_by)
        REFERENCES memberships (workspace_id, principal_id),
    CHECK (
        (status = 'required'
            AND completed_key_id IS NULL
            AND completed_by IS NULL
            AND completed_at IS NULL)
        OR
        (status = 'completed'
            AND completed_key_id IS NOT NULL
            AND length(completed_key_id) BETWEEN 1 AND 200
            AND completed_by IS NOT NULL
            AND completed_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_required_key_rotation_per_workspace
ON workspace_key_rotations (workspace_id)
WHERE status = 'required';
