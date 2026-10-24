CREATE TABLE booking_research (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    trip_id TEXT NOT NULL,
    observed_by TEXT NOT NULL,
    research_ciphertext BLOB NOT NULL CHECK (length(research_ciphertext) > 0),
    encryption_key_id TEXT NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm TEXT NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce BLOB NOT NULL CHECK (length(encryption_nonce) > 0),
    version INTEGER NOT NULL CHECK (version > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, trip_id) REFERENCES trips (workspace_id, id),
    FOREIGN KEY (observed_by) REFERENCES principals (id)
) STRICT;

CREATE INDEX booking_research_by_trip
ON booking_research (workspace_id, trip_id, created_at DESC, id);
