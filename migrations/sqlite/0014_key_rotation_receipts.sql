CREATE TABLE workspace_key_rotation_receipts (
    workspace_id TEXT NOT NULL,
    rotation_id TEXT NOT NULL,
    provider_id TEXT NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 255),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 255),
    generation INTEGER NOT NULL CHECK (generation > 0),
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 200),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, rotation_id),
    UNIQUE (provider_id, request_id),
    FOREIGN KEY (workspace_id, generation)
        REFERENCES workspace_key_rotations (workspace_id, generation),
    FOREIGN KEY (rotation_id)
        REFERENCES workspace_key_rotations (id)
) STRICT;

CREATE TABLE workspace_key_rotation_recipients (
    workspace_id TEXT NOT NULL,
    rotation_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    PRIMARY KEY (workspace_id, rotation_id, principal_id),
    FOREIGN KEY (workspace_id, rotation_id)
        REFERENCES workspace_key_rotation_receipts (workspace_id, rotation_id)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships (workspace_id, principal_id)
) STRICT;
