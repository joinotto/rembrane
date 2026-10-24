CREATE TABLE channel_event_receipts (
    channel TEXT NOT NULL
        CHECK (channel IN ('whatsapp-business', 'imessage-extension', 'mobile-share')),
    event_id TEXT NOT NULL
        CHECK (
            length(event_id) BETWEEN 1 AND 256
            AND event_id NOT GLOB '*[[:space:][:cntrl:]]*'
        ),
    workspace_id TEXT NOT NULL,
    accepted_at_epoch_seconds INTEGER NOT NULL
        CHECK (accepted_at_epoch_seconds > 0),
    expires_at_epoch_seconds INTEGER NOT NULL
        CHECK (expires_at_epoch_seconds > accepted_at_epoch_seconds),
    PRIMARY KEY (channel, event_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
) STRICT;

CREATE INDEX channel_event_receipts_workspace_expiry_idx
    ON channel_event_receipts (workspace_id, expires_at_epoch_seconds);
