DROP TRIGGER channel_inbox_identity_immutable;
DROP TRIGGER channel_inbox_state_monotonic;
DROP INDEX channel_inbox_workspace_pending;

ALTER TABLE channel_inbox RENAME TO channel_inbox_v22;

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
        CHECK (status IN ('pending', 'processing', 'delivered', 'quarantined')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at_epoch_seconds INTEGER NOT NULL
        CHECK (available_at_epoch_seconds > 0),
    lease_until_epoch_seconds INTEGER
        CHECK (lease_until_epoch_seconds IS NULL OR lease_until_epoch_seconds > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TEXT,
    PRIMARY KEY (channel, event_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    FOREIGN KEY (principal_id) REFERENCES principals (id),
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships (workspace_id, principal_id),
    CHECK (
        (status IN ('pending', 'quarantined')
            AND delivered_at IS NULL
            AND lease_until_epoch_seconds IS NULL)
        OR (status = 'processing'
            AND delivered_at IS NULL
            AND lease_until_epoch_seconds IS NOT NULL)
        OR (status = 'delivered'
            AND delivered_at IS NOT NULL
            AND lease_until_epoch_seconds IS NULL)
    )
) STRICT;

INSERT INTO channel_inbox (
    channel, event_id, workspace_id, principal_id, client_id,
    received_at_epoch_seconds, text_ciphertext, encryption_key_id,
    encryption_algorithm, encryption_nonce, status, attempts,
    available_at_epoch_seconds, lease_until_epoch_seconds, created_at,
    delivered_at
)
SELECT
    channel, event_id, workspace_id, principal_id, client_id,
    received_at_epoch_seconds, text_ciphertext, encryption_key_id,
    encryption_algorithm, encryption_nonce, status, attempts,
    available_at_epoch_seconds, NULL, created_at, delivered_at
FROM channel_inbox_v22;

DROP TABLE channel_inbox_v22;

CREATE INDEX channel_inbox_workspace_claimable
    ON channel_inbox (
        workspace_id, status, available_at_epoch_seconds,
        lease_until_epoch_seconds, received_at_epoch_seconds, channel, event_id
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

CREATE TRIGGER channel_inbox_state_monotonic
BEFORE UPDATE OF status ON channel_inbox
WHEN OLD.status IN ('delivered', 'quarantined')
   OR (OLD.status = 'pending' AND NEW.status <> 'processing')
   OR (OLD.status = 'processing'
       AND NEW.status NOT IN ('processing', 'pending', 'delivered', 'quarantined'))
BEGIN
    SELECT RAISE(ABORT, 'channel inbox state is monotonic');
END;
