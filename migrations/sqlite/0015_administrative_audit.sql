CREATE TABLE administrative_audit_events (
    workspace_id TEXT NOT NULL,
    id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN (
        'member-removed',
        'key-rotation-required',
        'key-rotation-completed',
        'scope-grant-changed',
        'retention-policy-changed',
        'legal-hold-placed',
        'legal-hold-released'
    )),
    target_kind TEXT NOT NULL CHECK (target_kind IN (
        'principal',
        'key-rotation',
        'scope-grant',
        'retention-policy',
        'legal-hold'
    )),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 255),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 255),
    occurred_at_epoch_seconds INTEGER NOT NULL CHECK (occurred_at_epoch_seconds > 0),
    PRIMARY KEY (workspace_id, id),
    UNIQUE (workspace_id, request_id, action, target_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (workspace_id, actor_id)
        REFERENCES memberships (workspace_id, principal_id)
) STRICT;

CREATE INDEX administrative_audit_workspace_time
    ON administrative_audit_events (
        workspace_id, occurred_at_epoch_seconds, id
    );

CREATE TRIGGER administrative_audit_events_no_update
BEFORE UPDATE ON administrative_audit_events
BEGIN
    SELECT RAISE(ABORT, 'administrative audit events are append-only');
END;

CREATE TRIGGER administrative_audit_events_no_delete
BEFORE DELETE ON administrative_audit_events
BEGIN
    SELECT RAISE(ABORT, 'administrative audit events are append-only');
END;
