ALTER TABLE workspace_invitations
RENAME TO workspace_invitations_before_expired_status;

CREATE TABLE workspace_invitations (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    invited_principal_id TEXT NOT NULL,
    invited_by TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at_epoch_seconds INTEGER NOT NULL
        CHECK (created_at_epoch_seconds > 0),
    expires_at_epoch_seconds INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (invited_principal_id) REFERENCES principals (id),
    FOREIGN KEY (invited_by) REFERENCES principals (id),
    CHECK (invited_principal_id != invited_by),
    CHECK (
        expires_at_epoch_seconds > created_at_epoch_seconds
        AND expires_at_epoch_seconds - created_at_epoch_seconds <= 2592000
    )
) STRICT;

INSERT INTO workspace_invitations (
    workspace_id,
    id,
    invited_principal_id,
    invited_by,
    role,
    status,
    created_at,
    updated_at,
    created_at_epoch_seconds,
    expires_at_epoch_seconds
)
SELECT
    workspace_id,
    id,
    invited_principal_id,
    invited_by,
    role,
    status,
    created_at,
    updated_at,
    created_at_epoch_seconds,
    expires_at_epoch_seconds
FROM workspace_invitations_before_expired_status;

DROP TABLE workspace_invitations_before_expired_status;

CREATE UNIQUE INDEX workspace_invitations_one_pending_per_principal
ON workspace_invitations (workspace_id, invited_principal_id)
WHERE status = 'pending';
