CREATE TABLE member_scope_grants (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    scope_type TEXT NOT NULL
        CHECK (scope_type IN ('global', 'domain', 'entity', 'activity')),
    scope_value TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, principal_id, scope_type, scope_value),
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships (workspace_id, principal_id)
        ON DELETE CASCADE,
    CHECK (
        (scope_type = 'global' AND scope_value = '')
        OR (scope_type != 'global' AND length(scope_value) > 0)
    )
) STRICT;

CREATE INDEX member_scope_grants_lookup
ON member_scope_grants (workspace_id, principal_id);
