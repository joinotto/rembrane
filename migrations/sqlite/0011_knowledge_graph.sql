CREATE TABLE knowledge_nodes (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    node_ciphertext BLOB NOT NULL CHECK (length(node_ciphertext) > 0),
    encryption_key_id TEXT NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm TEXT NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce BLOB NOT NULL CHECK (length(encryption_nonce) >= 12),
    version INTEGER NOT NULL CHECK (version > 0),
    valid_from INTEGER NOT NULL CHECK (valid_from > 0),
    valid_until INTEGER CHECK (valid_until IS NULL OR valid_until > valid_from),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id)
) STRICT;

CREATE TABLE knowledge_edges (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    supersedes_id TEXT,
    edge_ciphertext BLOB NOT NULL CHECK (length(edge_ciphertext) > 0),
    encryption_key_id TEXT NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm TEXT NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce BLOB NOT NULL CHECK (length(encryption_nonce) >= 12),
    version INTEGER NOT NULL CHECK (version > 0),
    valid_from INTEGER NOT NULL CHECK (valid_from > 0),
    valid_until INTEGER CHECK (valid_until IS NULL OR valid_until > valid_from),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (source_id <> target_id),
    CHECK (supersedes_id IS NULL OR supersedes_id <> id),
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (workspace_id, source_id)
        REFERENCES knowledge_nodes (workspace_id, id),
    FOREIGN KEY (workspace_id, target_id)
        REFERENCES knowledge_nodes (workspace_id, id),
    FOREIGN KEY (workspace_id, supersedes_id)
        REFERENCES knowledge_edges (workspace_id, id)
) STRICT;

CREATE INDEX knowledge_nodes_by_validity
ON knowledge_nodes (workspace_id, valid_from, valid_until, id);

CREATE INDEX knowledge_edges_by_source_validity
ON knowledge_edges (workspace_id, source_id, valid_from, valid_until, id);

CREATE INDEX knowledge_edges_by_target_validity
ON knowledge_edges (workspace_id, target_id, valid_from, valid_until, id);
