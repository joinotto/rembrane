CREATE TABLE graph_projection_outbox (
    id TEXT PRIMARY KEY NOT NULL,
    workspace_id TEXT NOT NULL,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('node', 'edge')),
    node_id TEXT,
    edge_id TEXT,
    resource_version INTEGER NOT NULL CHECK (resource_version > 0),
    provider_id TEXT NOT NULL CHECK (length(provider_id) > 0),
    operation TEXT NOT NULL CHECK (operation IN ('upsert', 'delete')),
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'processing', 'completed', 'quarantined')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        (resource_type = 'node' AND node_id IS NOT NULL AND edge_id IS NULL)
        OR
        (resource_type = 'edge' AND edge_id IS NOT NULL AND node_id IS NULL)
    ),
    UNIQUE (
        workspace_id,
        resource_type,
        node_id,
        edge_id,
        resource_version,
        provider_id,
        operation
    ),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (workspace_id, node_id)
        REFERENCES knowledge_nodes (workspace_id, id),
    FOREIGN KEY (workspace_id, edge_id)
        REFERENCES knowledge_edges (workspace_id, id)
) STRICT;

CREATE INDEX graph_projection_outbox_pending
ON graph_projection_outbox (provider_id, status, available_at, id)
WHERE status = 'pending';
