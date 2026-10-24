BEGIN;

CREATE TABLE workspace_invitations (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    invited_principal_id text NOT NULL REFERENCES principals (id),
    invited_by text NOT NULL REFERENCES principals (id),
    role text NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    status text NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, id),
    CHECK (invited_principal_id <> invited_by)
);

CREATE UNIQUE INDEX workspace_invitations_one_pending_per_principal
ON workspace_invitations (workspace_id, invited_principal_id)
WHERE status = 'pending';

CREATE TABLE member_scope_grants (
    workspace_id text NOT NULL,
    principal_id text NOT NULL,
    scope_type text NOT NULL
        CHECK (scope_type IN ('global', 'domain', 'entity', 'activity')),
    scope_value text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, principal_id, scope_type, scope_value),
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships (workspace_id, principal_id)
        ON DELETE CASCADE,
    CHECK (
        (scope_type = 'global' AND scope_value = '')
        OR (scope_type <> 'global' AND length(scope_value) > 0)
    )
);

CREATE INDEX member_scope_grants_lookup
ON member_scope_grants (workspace_id, principal_id);

CREATE TABLE workspace_key_rotations (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL UNIQUE,
    generation bigint NOT NULL CHECK (generation > 0),
    removed_principal_id text NOT NULL,
    requested_by text NOT NULL,
    status text NOT NULL CHECK (status IN ('required', 'completed')),
    completed_key_id text,
    completed_by text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamptz,
    PRIMARY KEY (workspace_id, generation),
    FOREIGN KEY (workspace_id, removed_principal_id)
        REFERENCES memberships (workspace_id, principal_id),
    FOREIGN KEY (workspace_id, requested_by)
        REFERENCES memberships (workspace_id, principal_id),
    FOREIGN KEY (workspace_id, completed_by)
        REFERENCES memberships (workspace_id, principal_id),
    CHECK (
        (
            status = 'required'
            AND completed_key_id IS NULL
            AND completed_by IS NULL
            AND completed_at IS NULL
        )
        OR
        (
            status = 'completed'
            AND completed_key_id IS NOT NULL
            AND length(completed_key_id) BETWEEN 1 AND 200
            AND completed_by IS NOT NULL
            AND completed_at IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX one_required_key_rotation_per_workspace
ON workspace_key_rotations (workspace_id)
WHERE status = 'required';

CREATE TABLE workspace_key_rotation_receipts (
    workspace_id text NOT NULL,
    rotation_id text NOT NULL,
    provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 255),
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 255),
    generation bigint NOT NULL CHECK (generation > 0),
    key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (workspace_id, rotation_id),
    UNIQUE (provider_id, request_id),
    FOREIGN KEY (workspace_id, generation)
        REFERENCES workspace_key_rotations (workspace_id, generation),
    FOREIGN KEY (rotation_id)
        REFERENCES workspace_key_rotations (id)
);

CREATE TABLE workspace_key_rotation_recipients (
    workspace_id text NOT NULL,
    rotation_id text NOT NULL,
    principal_id text NOT NULL,
    PRIMARY KEY (workspace_id, rotation_id, principal_id),
    FOREIGN KEY (workspace_id, rotation_id)
        REFERENCES workspace_key_rotation_receipts (workspace_id, rotation_id)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships (workspace_id, principal_id)
);

CREATE TABLE administrative_audit_events (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL CHECK (action IN (
        'member-removed',
        'key-rotation-required',
        'key-rotation-completed',
        'scope-grant-changed',
        'retention-policy-changed',
        'legal-hold-placed',
        'legal-hold-released'
    )),
    target_kind text NOT NULL CHECK (target_kind IN (
        'principal',
        'key-rotation',
        'scope-grant',
        'retention-policy',
        'legal-hold'
    )),
    target_id text NOT NULL CHECK (length(target_id) BETWEEN 1 AND 255),
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 255),
    occurred_at_epoch_seconds bigint NOT NULL
        CHECK (occurred_at_epoch_seconds > 0),
    PRIMARY KEY (workspace_id, id),
    UNIQUE (workspace_id, request_id, action, target_id),
    FOREIGN KEY (workspace_id, actor_id)
        REFERENCES memberships (workspace_id, principal_id)
);

CREATE INDEX administrative_audit_workspace_time
ON administrative_audit_events (
    workspace_id,
    occurred_at_epoch_seconds,
    id
);

CREATE OR REPLACE FUNCTION rembrane_reject_administrative_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'administrative audit events are append-only'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER administrative_audit_events_are_append_only
BEFORE UPDATE OR DELETE ON administrative_audit_events
FOR EACH ROW EXECUTE FUNCTION rembrane_reject_administrative_audit_mutation();

CREATE TABLE workspace_retention_policies (
    workspace_id text PRIMARY KEY REFERENCES workspaces (id),
    version bigint NOT NULL CHECK (version > 0),
    user_memory_days integer CHECK (user_memory_days BETWEEN 1 AND 36500),
    activity_checkpoint_days integer
        CHECK (activity_checkpoint_days BETWEEN 1 AND 36500),
    travel_research_days integer
        CHECK (travel_research_days BETWEEN 1 AND 36500),
    disclosure_receipt_days integer
        CHECK (disclosure_receipt_days BETWEEN 1 AND 36500),
    canonical_event_days integer
        CHECK (canonical_event_days BETWEEN 1 AND 36500),
    administrative_audit_days integer
        CHECK (administrative_audit_days BETWEEN 1 AND 36500)
);

CREATE TABLE workspace_legal_holds (
    workspace_id text NOT NULL REFERENCES workspaces (id),
    id text NOT NULL,
    placed_by text NOT NULL,
    placed_at_epoch_seconds bigint NOT NULL
        CHECK (placed_at_epoch_seconds > 0),
    status text NOT NULL CHECK (status IN ('active', 'released')),
    version bigint NOT NULL CHECK (version > 0),
    released_by text,
    released_at_epoch_seconds bigint,
    PRIMARY KEY (workspace_id, id),
    FOREIGN KEY (workspace_id, placed_by)
        REFERENCES memberships (workspace_id, principal_id),
    FOREIGN KEY (workspace_id, released_by)
        REFERENCES memberships (workspace_id, principal_id),
    CHECK (
        (
            status = 'active'
            AND released_by IS NULL
            AND released_at_epoch_seconds IS NULL
        )
        OR
        (
            status = 'released'
            AND released_by IS NOT NULL
            AND released_at_epoch_seconds IS NOT NULL
            AND released_at_epoch_seconds >= placed_at_epoch_seconds
        )
    )
);

CREATE INDEX workspace_legal_holds_active
ON workspace_legal_holds (workspace_id, status);

COMMIT;
