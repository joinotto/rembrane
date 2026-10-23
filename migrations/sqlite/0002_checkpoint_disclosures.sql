CREATE TABLE checkpoint_disclosures (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    checkpoint_id TEXT NOT NULL,
    checkpoint_version INTEGER NOT NULL CHECK (checkpoint_version > 0),
    activity_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    purpose_code TEXT NOT NULL CHECK (length(purpose_code) > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, checkpoint_id)
        REFERENCES activity_checkpoints (workspace_id, id),
    FOREIGN KEY (subject_id) REFERENCES principals (id)
) STRICT;

CREATE INDEX checkpoint_disclosures_activity
ON checkpoint_disclosures (
    workspace_id,
    subject_id,
    activity_id,
    created_at DESC
);
