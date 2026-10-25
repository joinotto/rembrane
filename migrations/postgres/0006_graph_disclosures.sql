BEGIN;

CREATE TABLE graph_disclosure_receipts (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    subject_id text NOT NULL REFERENCES principals (id),
    client_id text NOT NULL,
    purpose_code text NOT NULL CHECK (length(btrim(purpose_code)) > 0),
    node_id text NOT NULL,
    direction text NOT NULL CHECK (direction IN ('incoming', 'outgoing', 'both')),
    valid_at_epoch_seconds bigint NOT NULL CHECK (valid_at_epoch_seconds > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, node_id)
        REFERENCES knowledge_nodes (workspace_id, id)
);

CREATE TABLE disclosed_knowledge_edges (
    workspace_id text NOT NULL,
    disclosure_id text NOT NULL,
    edge_id text NOT NULL,
    edge_version bigint NOT NULL CHECK (edge_version > 0),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (workspace_id, disclosure_id, edge_id),
    UNIQUE (workspace_id, disclosure_id, ordinal),
    FOREIGN KEY (workspace_id, disclosure_id)
        REFERENCES graph_disclosure_receipts (workspace_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, edge_id)
        REFERENCES knowledge_edges (workspace_id, id)
);

CREATE INDEX graph_disclosures_by_node
ON graph_disclosure_receipts (
    workspace_id, node_id, valid_at_epoch_seconds, created_at, id
);

COMMIT;
