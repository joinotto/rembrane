-- Apply immediately after the canonical schema and before runtime grants.
BEGIN;

CREATE SCHEMA IF NOT EXISTS rembrane;

CREATE OR REPLACE FUNCTION rembrane.current_workspace_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('rembrane.workspace_id', true), '')
$$;

DO $$
DECLARE
    tenant_table record;
BEGIN
    FOR tenant_table IN
        SELECT table_schema, table_name
        FROM information_schema.columns
        WHERE column_name = 'workspace_id'
          AND table_schema = current_schema()
    LOOP
        EXECUTE format(
            'ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',
            tenant_table.table_schema,
            tenant_table.table_name
        );
        EXECUTE format(
            'ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',
            tenant_table.table_schema,
            tenant_table.table_name
        );
        EXECUTE format(
            'DROP POLICY IF EXISTS rembrane_workspace_isolation ON %I.%I',
            tenant_table.table_schema,
            tenant_table.table_name
        );
        EXECUTE format(
            'CREATE POLICY rembrane_workspace_isolation ON %I.%I '
            'USING (workspace_id = rembrane.current_workspace_id()) '
            'WITH CHECK (workspace_id = rembrane.current_workspace_id())',
            tenant_table.table_schema,
            tenant_table.table_name
        );
    END LOOP;
END
$$;

ALTER TABLE principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE principals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rembrane_workspace_members ON principals;
CREATE POLICY rembrane_workspace_members ON principals
FOR SELECT
USING (
    EXISTS (
        SELECT 1
        FROM memberships
        WHERE memberships.workspace_id = rembrane.current_workspace_id()
          AND memberships.principal_id = principals.id
    )
);

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rembrane_workspace_isolation ON workspaces;
CREATE POLICY rembrane_workspace_isolation ON workspaces
USING (id = rembrane.current_workspace_id())
WITH CHECK (id = rembrane.current_workspace_id());

ALTER TABLE memory_share_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_share_proposals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rembrane_workspace_isolation ON memory_share_proposals;
CREATE POLICY rembrane_workspace_isolation ON memory_share_proposals
USING (source_workspace_id = rembrane.current_workspace_id())
WITH CHECK (source_workspace_id = rembrane.current_workspace_id());

COMMIT;
