CREATE TABLE channel_sender_bindings (
    channel TEXT NOT NULL
        CHECK (channel IN ('whatsapp-business', 'imessage-extension', 'mobile-share')),
    account_lookup_key TEXT NOT NULL
        CHECK (length(account_lookup_key) BETWEEN 1 AND 256),
    sender_lookup_key TEXT NOT NULL
        CHECK (length(sender_lookup_key) BETWEEN 1 AND 256),
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    PRIMARY KEY (channel, account_lookup_key, sender_lookup_key),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
    FOREIGN KEY (principal_id) REFERENCES principals(id),
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships(workspace_id, principal_id)
) STRICT;

CREATE INDEX channel_sender_bindings_workspace_idx
    ON channel_sender_bindings (workspace_id, principal_id);
