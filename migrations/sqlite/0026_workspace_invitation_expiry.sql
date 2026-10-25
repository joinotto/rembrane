ALTER TABLE workspace_invitations
ADD COLUMN created_at_epoch_seconds INTEGER NOT NULL DEFAULT 1
CHECK (created_at_epoch_seconds > 0);

ALTER TABLE workspace_invitations
ADD COLUMN expires_at_epoch_seconds INTEGER NOT NULL DEFAULT 2
CHECK (
    expires_at_epoch_seconds > created_at_epoch_seconds
    AND expires_at_epoch_seconds - created_at_epoch_seconds <= 2592000
);
