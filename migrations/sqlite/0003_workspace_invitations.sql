CREATE TABLE workspace_invitations (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    invited_principal_id TEXT NOT NULL,
    invited_by TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (invited_principal_id) REFERENCES principals (id),
    FOREIGN KEY (invited_by) REFERENCES principals (id),
    CHECK (invited_principal_id != invited_by)
) STRICT;

CREATE UNIQUE INDEX workspace_invitations_one_pending_per_principal
ON workspace_invitations (workspace_id, invited_principal_id)
WHERE status = 'pending';
