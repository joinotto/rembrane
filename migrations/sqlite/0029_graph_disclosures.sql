CREATE TABLE graph_disclosure_receipts (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    purpose_code TEXT NOT NULL CHECK (length(trim(purpose_code)) > 0),
    node_id TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('incoming', 'outgoing', 'both')),
    valid_at_epoch_seconds INTEGER NOT NULL CHECK (valid_at_epoch_seconds > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (subject_id) REFERENCES principals (id),
    FOREIGN KEY (workspace_id, node_id)
        REFERENCES knowledge_nodes (workspace_id, id)
) STRICT;

CREATE TABLE disclosed_knowledge_edges (
    workspace_id TEXT NOT NULL,
    disclosure_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    edge_version INTEGER NOT NULL CHECK (edge_version > 0),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (workspace_id, disclosure_id, edge_id),
    UNIQUE (workspace_id, disclosure_id, ordinal),
    FOREIGN KEY (workspace_id, disclosure_id)
        REFERENCES graph_disclosure_receipts (workspace_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, edge_id)
        REFERENCES knowledge_edges (workspace_id, id)
) STRICT;

CREATE INDEX graph_disclosures_by_node
ON graph_disclosure_receipts (
    workspace_id, node_id, valid_at_epoch_seconds, created_at, id
);
