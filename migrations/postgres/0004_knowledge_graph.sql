BEGIN;

CREATE TABLE knowledge_nodes (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    node_ciphertext bytea NOT NULL CHECK (octet_length(node_ciphertext) > 0),
    encryption_key_id text NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm text NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce bytea NOT NULL CHECK (octet_length(encryption_nonce) >= 12),
    version bigint NOT NULL CHECK (version > 0),
    valid_from bigint NOT NULL CHECK (valid_from > 0),
    valid_until bigint CHECK (valid_until IS NULL OR valid_until > valid_from),
    recorded_at bigint NOT NULL CHECK (recorded_at > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id)
);

CREATE TABLE knowledge_edges (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    source_id text NOT NULL,
    target_id text NOT NULL,
    supersedes_id text,
    edge_ciphertext bytea NOT NULL CHECK (octet_length(edge_ciphertext) > 0),
    encryption_key_id text NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm text NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce bytea NOT NULL CHECK (octet_length(encryption_nonce) >= 12),
    version bigint NOT NULL CHECK (version > 0),
    valid_from bigint NOT NULL CHECK (valid_from > 0),
    valid_until bigint CHECK (valid_until IS NULL OR valid_until > valid_from),
    recorded_at bigint NOT NULL CHECK (recorded_at > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (source_id <> target_id),
    CHECK (supersedes_id IS NULL OR supersedes_id <> id),
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, source_id)
        REFERENCES knowledge_nodes (workspace_id, id),
    FOREIGN KEY (workspace_id, target_id)
        REFERENCES knowledge_nodes (workspace_id, id),
    FOREIGN KEY (workspace_id, supersedes_id)
        REFERENCES knowledge_edges (workspace_id, id)
);

CREATE INDEX knowledge_nodes_by_validity
ON knowledge_nodes (workspace_id, valid_from, valid_until, id);

CREATE INDEX knowledge_edges_by_source_validity
ON knowledge_edges (workspace_id, source_id, valid_from, valid_until, id);

CREATE INDEX knowledge_edges_by_target_validity
ON knowledge_edges (workspace_id, target_id, valid_from, valid_until, id);

CREATE TABLE graph_projection_outbox (
    id text PRIMARY KEY,
    workspace_id text NOT NULL REFERENCES workspaces (id),
    resource_type text NOT NULL CHECK (resource_type IN ('node', 'edge')),
    node_id text,
    edge_id text,
    resource_version bigint NOT NULL CHECK (resource_version > 0),
    provider_id text NOT NULL CHECK (length(provider_id) > 0),
    operation text NOT NULL CHECK (operation IN ('upsert', 'delete')),
    status text NOT NULL
        CHECK (status IN ('pending', 'processing', 'completed', 'quarantined')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        (
            resource_type = 'node'
            AND node_id IS NOT NULL
            AND edge_id IS NULL
        )
        OR
        (
            resource_type = 'edge'
            AND edge_id IS NOT NULL
            AND node_id IS NULL
        )
    ),
    FOREIGN KEY (workspace_id, node_id)
        REFERENCES knowledge_nodes (workspace_id, id),
    FOREIGN KEY (workspace_id, edge_id)
        REFERENCES knowledge_edges (workspace_id, id)
);

CREATE INDEX graph_projection_outbox_pending
ON graph_projection_outbox (provider_id, status, available_at, id)
WHERE status = 'pending';

CREATE UNIQUE INDEX graph_projection_outbox_node_idempotency
ON graph_projection_outbox (
    workspace_id,
    node_id,
    resource_version,
    provider_id,
    operation
)
WHERE resource_type = 'node';

CREATE UNIQUE INDEX graph_projection_outbox_edge_idempotency
ON graph_projection_outbox (
    workspace_id,
    edge_id,
    resource_version,
    provider_id,
    operation
)
WHERE resource_type = 'edge';

COMMIT;
