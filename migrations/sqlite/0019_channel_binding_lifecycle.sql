CREATE TRIGGER channel_sender_bindings_require_active_membership_insert
BEFORE INSERT ON channel_sender_bindings
WHEN NOT EXISTS (
    SELECT 1
    FROM memberships
    WHERE workspace_id = NEW.workspace_id
      AND principal_id = NEW.principal_id
      AND status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'active channel binding membership required');
END;

CREATE TRIGGER channel_sender_bindings_require_active_membership_update
BEFORE UPDATE OF workspace_id, principal_id ON channel_sender_bindings
WHEN NOT EXISTS (
    SELECT 1
    FROM memberships
    WHERE workspace_id = NEW.workspace_id
      AND principal_id = NEW.principal_id
      AND status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'active channel binding membership required');
END;

CREATE TRIGGER channel_sender_bindings_revoke_inactive_membership
AFTER UPDATE OF status ON memberships
WHEN NEW.status <> 'active'
BEGIN
    DELETE FROM channel_sender_bindings
    WHERE workspace_id = NEW.workspace_id
      AND principal_id = NEW.principal_id;
END;
