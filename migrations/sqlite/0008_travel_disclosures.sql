CREATE TABLE travel_disclosure_receipts (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    purpose_code TEXT NOT NULL CHECK (length(trim(purpose_code)) > 0),
    trip_id TEXT NOT NULL,
    trip_version INTEGER NOT NULL CHECK (trip_version > 0),
    as_of TEXT NOT NULL CHECK (length(trim(as_of)) > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, trip_id) REFERENCES trips (workspace_id, id),
    FOREIGN KEY (subject_id) REFERENCES principals (id)
) STRICT;

CREATE TABLE disclosed_booking_research (
    workspace_id TEXT NOT NULL,
    disclosure_id TEXT NOT NULL,
    research_id TEXT NOT NULL,
    research_version INTEGER NOT NULL CHECK (research_version > 0),
    freshness TEXT NOT NULL CHECK (freshness IN ('fresh', 'expired')),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (workspace_id, disclosure_id, research_id),
    UNIQUE (workspace_id, disclosure_id, ordinal),
    FOREIGN KEY (workspace_id, disclosure_id)
        REFERENCES travel_disclosure_receipts (workspace_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, research_id)
        REFERENCES booking_research (workspace_id, id)
) STRICT;

CREATE INDEX travel_disclosures_by_trip
ON travel_disclosure_receipts (
    workspace_id,
    trip_id,
    created_at DESC,
    id
);
