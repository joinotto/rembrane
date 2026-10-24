CREATE TABLE trips (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    owner_subject_id TEXT NOT NULL,
    trip_ciphertext BLOB NOT NULL CHECK (length(trip_ciphertext) > 0),
    encryption_key_id TEXT NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm TEXT NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce BLOB NOT NULL CHECK (length(encryption_nonce) > 0),
    version INTEGER NOT NULL CHECK (version > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (owner_subject_id) REFERENCES principals (id)
) STRICT;

CREATE INDEX trips_by_owner
ON trips (workspace_id, owner_subject_id, updated_at DESC, id);
