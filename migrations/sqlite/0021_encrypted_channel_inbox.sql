CREATE TABLE channel_inbox (
    channel TEXT NOT NULL
        CHECK (channel IN ('whatsapp-business', 'imessage-extension', 'mobile-share')),
    event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 256),
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    received_at_epoch_seconds INTEGER NOT NULL
        CHECK (received_at_epoch_seconds > 0),
    text_ciphertext BLOB NOT NULL CHECK (length(text_ciphertext) > 0),
    encryption_key_id TEXT NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm TEXT NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce BLOB NOT NULL CHECK (length(encryption_nonce) >= 12),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivered')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TEXT,
    PRIMARY KEY (channel, event_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (principal_id) REFERENCES principals (id),
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships (workspace_id, principal_id),
    CHECK (
        (status = 'pending' AND delivered_at IS NULL)
        OR (status = 'delivered' AND delivered_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX channel_inbox_workspace_pending
    ON channel_inbox (
        workspace_id, status, received_at_epoch_seconds, channel, event_id
    );

CREATE TRIGGER channel_inbox_identity_immutable
BEFORE UPDATE OF
    channel,
    event_id,
    workspace_id,
    principal_id,
    client_id,
    received_at_epoch_seconds,
    text_ciphertext,
    encryption_key_id,
    encryption_algorithm,
    encryption_nonce
ON channel_inbox
BEGIN
    SELECT RAISE(ABORT, 'channel inbox identity and ciphertext are immutable');
END;

CREATE TRIGGER channel_inbox_delivery_monotonic
BEFORE UPDATE OF status ON channel_inbox
WHEN OLD.status = 'delivered' OR NEW.status <> 'delivered'
BEGIN
    SELECT RAISE(ABORT, 'channel inbox delivery is monotonic');
END;
