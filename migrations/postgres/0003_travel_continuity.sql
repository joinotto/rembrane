BEGIN;

CREATE TABLE checkpoint_disclosures (
    workspace_id text NOT NULL,
    id text NOT NULL,
    checkpoint_id text NOT NULL,
    checkpoint_version bigint NOT NULL CHECK (checkpoint_version > 0),
    activity_id text NOT NULL,
    subject_id text NOT NULL REFERENCES principals (id),
    client_id text NOT NULL,
    purpose_code text NOT NULL CHECK (length(purpose_code) > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, checkpoint_id)
        REFERENCES activity_checkpoints (workspace_id, id)
);

CREATE INDEX checkpoint_disclosures_activity
ON checkpoint_disclosures (
    workspace_id,
    subject_id,
    activity_id,
    created_at DESC
);

CREATE TABLE trips (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    owner_subject_id text NOT NULL REFERENCES principals (id),
    trip_ciphertext bytea NOT NULL CHECK (octet_length(trip_ciphertext) > 0),
    encryption_key_id text NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm text NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce bytea NOT NULL CHECK (octet_length(encryption_nonce) >= 12),
    version bigint NOT NULL CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id)
);

CREATE INDEX trips_by_owner
ON trips (workspace_id, owner_subject_id, updated_at DESC, id);

CREATE TABLE booking_research (
    workspace_id text NOT NULL,
    id text NOT NULL,
    trip_id text NOT NULL,
    observed_by text NOT NULL REFERENCES principals (id),
    research_ciphertext bytea NOT NULL
        CHECK (octet_length(research_ciphertext) > 0),
    encryption_key_id text NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm text NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce bytea NOT NULL CHECK (octet_length(encryption_nonce) >= 12),
    version bigint NOT NULL CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, trip_id)
        REFERENCES trips (workspace_id, id)
);

CREATE INDEX booking_research_by_trip
ON booking_research (workspace_id, trip_id, created_at DESC, id);

CREATE TABLE travel_disclosure_receipts (
    workspace_id text NOT NULL,
    id text NOT NULL,
    subject_id text NOT NULL REFERENCES principals (id),
    client_id text NOT NULL,
    purpose_code text NOT NULL CHECK (length(btrim(purpose_code)) > 0),
    trip_id text NOT NULL,
    trip_version bigint NOT NULL CHECK (trip_version > 0),
    as_of text NOT NULL CHECK (length(btrim(as_of)) > 0),
    source_references_included boolean NOT NULL DEFAULT false,
    sensitive_profile_included boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, trip_id)
        REFERENCES trips (workspace_id, id)
);

CREATE TABLE disclosed_booking_research (
    workspace_id text NOT NULL,
    disclosure_id text NOT NULL,
    research_id text NOT NULL,
    research_version bigint NOT NULL CHECK (research_version > 0),
    freshness text NOT NULL CHECK (freshness IN ('fresh', 'expired')),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (workspace_id, disclosure_id, research_id),
    UNIQUE (workspace_id, disclosure_id, ordinal),
    FOREIGN KEY (workspace_id, disclosure_id)
        REFERENCES travel_disclosure_receipts (workspace_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, research_id)
        REFERENCES booking_research (workspace_id, id)
);

CREATE INDEX travel_disclosures_by_trip
ON travel_disclosure_receipts (
    workspace_id,
    trip_id,
    created_at DESC,
    id
);

COMMIT;
