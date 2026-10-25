BEGIN;

ALTER TABLE administrative_audit_events
    DROP CONSTRAINT administrative_audit_events_action_check;
ALTER TABLE administrative_audit_events
    ADD CONSTRAINT administrative_audit_events_action_check CHECK (
        action IN (
            'invitation-created',
            'invitation-accepted',
            'invitation-revoked',
            'member-removed',
            'key-rotation-required',
            'key-rotation-completed',
            'scope-grant-changed',
            'retention-policy-changed',
            'legal-hold-placed',
            'legal-hold-released',
            'channel-binding-created',
            'channel-binding-revoked',
            'channel-message-requeued'
        )
    );
ALTER TABLE administrative_audit_events
    DROP CONSTRAINT administrative_audit_events_target_kind_check;
ALTER TABLE administrative_audit_events
    ADD CONSTRAINT administrative_audit_events_target_kind_check CHECK (
        target_kind IN (
            'invitation',
            'principal',
            'key-rotation',
            'scope-grant',
            'retention-policy',
            'legal-hold',
            'channel-binding',
            'channel-message'
        )
    );

CREATE TABLE channel_event_receipts (
    channel text NOT NULL CHECK (
        channel IN ('whatsapp-business', 'imessage-extension', 'mobile-share')
    ),
    event_id text NOT NULL CHECK (
        length(event_id) BETWEEN 1 AND 256
        AND event_id !~ '[[:space:][:cntrl:]]'
    ),
    workspace_id text NOT NULL REFERENCES workspaces (id),
    accepted_at_epoch_seconds bigint NOT NULL
        CHECK (accepted_at_epoch_seconds > 0),
    expires_at_epoch_seconds bigint NOT NULL
        CHECK (expires_at_epoch_seconds > accepted_at_epoch_seconds),
    PRIMARY KEY (channel, event_id)
);

CREATE INDEX channel_event_receipts_workspace_expiry_idx
ON channel_event_receipts (workspace_id, expires_at_epoch_seconds);

CREATE TABLE channel_sender_bindings (
    channel text NOT NULL CHECK (
        channel IN ('whatsapp-business', 'imessage-extension', 'mobile-share')
    ),
    account_lookup_key text NOT NULL
        CHECK (length(account_lookup_key) BETWEEN 1 AND 256),
    sender_lookup_key text NOT NULL
        CHECK (length(sender_lookup_key) BETWEEN 1 AND 256),
    workspace_id text NOT NULL REFERENCES workspaces (id),
    principal_id text NOT NULL REFERENCES principals (id),
    client_id text NOT NULL,
    PRIMARY KEY (channel, account_lookup_key, sender_lookup_key),
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships (workspace_id, principal_id)
);

CREATE INDEX channel_sender_bindings_workspace_idx
ON channel_sender_bindings (workspace_id, principal_id);

CREATE OR REPLACE FUNCTION rembrane_require_active_channel_membership()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM memberships
        WHERE workspace_id = NEW.workspace_id
          AND principal_id = NEW.principal_id
          AND status = 'active'
    ) THEN
        RAISE EXCEPTION 'active channel binding membership required'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER channel_sender_bindings_require_active_membership_insert
BEFORE INSERT ON channel_sender_bindings
FOR EACH ROW EXECUTE FUNCTION rembrane_require_active_channel_membership();

CREATE TRIGGER channel_sender_bindings_require_active_membership_update
BEFORE UPDATE OF workspace_id, principal_id ON channel_sender_bindings
FOR EACH ROW EXECUTE FUNCTION rembrane_require_active_channel_membership();

CREATE OR REPLACE FUNCTION rembrane_revoke_inactive_channel_bindings()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status <> 'active' THEN
        DELETE FROM channel_sender_bindings
        WHERE workspace_id = NEW.workspace_id
          AND principal_id = NEW.principal_id;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER channel_sender_bindings_revoke_inactive_membership
AFTER UPDATE OF status ON memberships
FOR EACH ROW EXECUTE FUNCTION rembrane_revoke_inactive_channel_bindings();

CREATE TABLE channel_inbox (
    channel text NOT NULL CHECK (
        channel IN ('whatsapp-business', 'imessage-extension', 'mobile-share')
    ),
    event_id text NOT NULL CHECK (length(event_id) BETWEEN 1 AND 256),
    workspace_id text NOT NULL REFERENCES workspaces (id),
    principal_id text NOT NULL REFERENCES principals (id),
    client_id text NOT NULL,
    received_at_epoch_seconds bigint NOT NULL
        CHECK (received_at_epoch_seconds > 0),
    text_ciphertext bytea NOT NULL CHECK (octet_length(text_ciphertext) > 0),
    encryption_key_id text NOT NULL CHECK (length(encryption_key_id) > 0),
    encryption_algorithm text NOT NULL CHECK (length(encryption_algorithm) > 0),
    encryption_nonce bytea NOT NULL CHECK (octet_length(encryption_nonce) >= 12),
    status text NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'processing', 'delivered', 'quarantined')
    ),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at_epoch_seconds bigint NOT NULL
        CHECK (available_at_epoch_seconds > 0),
    lease_id text CHECK (
        lease_id IS NULL OR length(lease_id) BETWEEN 8 AND 128
    ),
    lease_until_epoch_seconds bigint CHECK (
        lease_until_epoch_seconds IS NULL OR lease_until_epoch_seconds > 0
    ),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at timestamptz,
    PRIMARY KEY (channel, event_id),
    FOREIGN KEY (workspace_id, principal_id)
        REFERENCES memberships (workspace_id, principal_id),
    CHECK (
        (
            status IN ('pending', 'quarantined')
            AND delivered_at IS NULL
            AND lease_id IS NULL
            AND lease_until_epoch_seconds IS NULL
        )
        OR
        (
            status = 'processing'
            AND delivered_at IS NULL
            AND lease_id IS NOT NULL
            AND lease_until_epoch_seconds IS NOT NULL
        )
        OR
        (
            status = 'delivered'
            AND delivered_at IS NOT NULL
            AND lease_id IS NULL
            AND lease_until_epoch_seconds IS NULL
        )
    )
);

CREATE INDEX channel_inbox_workspace_claimable
ON channel_inbox (
    workspace_id,
    status,
    available_at_epoch_seconds,
    lease_until_epoch_seconds,
    received_at_epoch_seconds,
    channel,
    event_id
);

CREATE OR REPLACE FUNCTION rembrane_enforce_channel_inbox_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.channel IS DISTINCT FROM OLD.channel
        OR NEW.event_id IS DISTINCT FROM OLD.event_id
        OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.client_id IS DISTINCT FROM OLD.client_id
        OR NEW.received_at_epoch_seconds IS DISTINCT FROM OLD.received_at_epoch_seconds
        OR NEW.text_ciphertext IS DISTINCT FROM OLD.text_ciphertext
        OR NEW.encryption_key_id IS DISTINCT FROM OLD.encryption_key_id
        OR NEW.encryption_algorithm IS DISTINCT FROM OLD.encryption_algorithm
        OR NEW.encryption_nonce IS DISTINCT FROM OLD.encryption_nonce
    THEN
        RAISE EXCEPTION 'channel inbox identity and ciphertext are immutable'
            USING ERRCODE = '55000';
    END IF;

    IF NEW.status IS DISTINCT FROM OLD.status
        AND (
            OLD.status = 'delivered'
            OR (OLD.status = 'quarantined' AND NEW.status <> 'pending')
            OR (OLD.status = 'pending' AND NEW.status <> 'processing')
            OR (
                OLD.status = 'processing'
                AND NEW.status NOT IN (
                    'processing',
                    'pending',
                    'delivered',
                    'quarantined'
                )
            )
        )
    THEN
        RAISE EXCEPTION 'channel inbox state is monotonic'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER channel_inbox_transition_guard
BEFORE UPDATE ON channel_inbox
FOR EACH ROW EXECUTE FUNCTION rembrane_enforce_channel_inbox_transition();

COMMIT;
