-- Exact shared read inventory for both scoped tenants and unscoped denial.
-- This file is a live fixture query, not proof that RLS has been executed.
-- Check identities as well as counts: a wrong-tenant row can otherwise replace
-- a correct row while leaving the aggregate cardinality unchanged.
DO $$
DECLARE
    target record;
    foreign_rows_visible boolean;
BEGIN
    FOR target IN
        SELECT * FROM (VALUES
            ('workspaces', 'id'),
            ('memberships', 'workspace_id'),
            ('memories', 'workspace_id'),
            ('memory_share_proposals', 'source_workspace_id'),
            ('workspace_invitations', 'workspace_id'),
            ('member_scope_grants', 'workspace_id'),
            ('workspace_retention_policies', 'workspace_id'),
            ('administrative_audit_events', 'workspace_id'),
            ('trips', 'workspace_id'),
            ('booking_research', 'workspace_id'),
            ('travel_disclosure_receipts', 'workspace_id'),
            ('disclosed_booking_research', 'workspace_id'),
            ('knowledge_nodes', 'workspace_id'),
            ('knowledge_edges', 'workspace_id'),
            ('graph_projection_outbox', 'workspace_id'),
            ('channel_event_receipts', 'workspace_id'),
            ('channel_sender_bindings', 'workspace_id'),
            ('channel_inbox', 'workspace_id'),
            ('workspace_events', 'workspace_id'),
            ('memory_evidence', 'workspace_id'),
            ('activity_checkpoints', 'workspace_id'),
            ('disclosure_receipts', 'workspace_id'),
            ('disclosed_memories', 'workspace_id'),
            ('projection_outbox', 'workspace_id'),
            ('checkpoint_disclosures', 'workspace_id'),
            ('workspace_key_rotations', 'workspace_id'),
            ('workspace_key_rotation_receipts', 'workspace_id'),
            ('workspace_key_rotation_recipients', 'workspace_id'),
            ('workspace_legal_holds', 'workspace_id'),
            ('graph_disclosure_receipts', 'workspace_id'),
            ('disclosed_knowledge_edges', 'workspace_id')
        ) AS protected(table_name, scope_column)
    LOOP
        -- Only fixture-owned literal identifiers are formatted; tenant values
        -- remain database settings and are never interpolated into SQL text.
        EXECUTE pg_catalog.format(
            'SELECT EXISTS (SELECT 1 FROM public.%I WHERE %I IS DISTINCT FROM '
            'NULLIF(pg_catalog.current_setting(''rembrane.workspace_id'', true), ''''))',
            target.table_name, target.scope_column
        ) INTO foreign_rows_visible;
        IF foreign_rows_visible THEN
            RAISE EXCEPTION 'PostgreSQL fixture returned rows outside its bound workspace';
        END IF;
    END LOOP;
    IF EXISTS (
        SELECT 1 FROM public.principals AS principal
        WHERE NOT EXISTS (
            SELECT 1 FROM public.memberships AS membership
            WHERE membership.principal_id = principal.id
              AND membership.workspace_id =
                  NULLIF(pg_catalog.current_setting('rembrane.workspace_id', true), '')
        )
    ) THEN
        RAISE EXCEPTION 'PostgreSQL fixture returned a principal outside its bound membership';
    END IF;
END
$$;

SELECT
    (SELECT count(*) FROM principals),
    (SELECT count(*) FROM workspaces),
    (SELECT count(*) FROM memberships),
    (SELECT count(*) FROM memories),
    (SELECT count(*) FROM memory_share_proposals),
    (SELECT count(*) FROM workspace_invitations),
    (SELECT count(*) FROM member_scope_grants),
    (SELECT count(*) FROM workspace_retention_policies),
    (SELECT count(*) FROM administrative_audit_events),
    (SELECT count(*) FROM trips),
    (SELECT count(*) FROM booking_research),
    (SELECT count(*) FROM travel_disclosure_receipts),
    (SELECT count(*) FROM disclosed_booking_research),
    (SELECT count(*) FROM knowledge_nodes),
    (SELECT count(*) FROM knowledge_edges),
    (SELECT count(*) FROM graph_projection_outbox),
    (SELECT count(*) FROM channel_event_receipts),
    (SELECT count(*) FROM channel_sender_bindings),
    (SELECT count(*) FROM channel_inbox),
    (SELECT count(*) FROM workspace_events),
    (SELECT count(*) FROM memory_evidence),
    (SELECT count(*) FROM activity_checkpoints),
    (SELECT count(*) FROM disclosure_receipts),
    (SELECT count(*) FROM disclosed_memories),
    (SELECT count(*) FROM projection_outbox),
    (SELECT count(*) FROM checkpoint_disclosures),
    (SELECT count(*) FROM workspace_key_rotations),
    (SELECT count(*) FROM workspace_key_rotation_receipts),
    (SELECT count(*) FROM workspace_key_rotation_recipients),
    (SELECT count(*) FROM workspace_legal_holds),
    (SELECT count(*) FROM graph_disclosure_receipts),
    (SELECT count(*) FROM disclosed_knowledge_edges);
