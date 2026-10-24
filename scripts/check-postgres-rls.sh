#!/bin/sh
set -eu

schema=migrations/postgres/0001_canonical_schema.sql
migration=migrations/postgres/0002_tenant_rls.sql
readme=migrations/postgres/README.md

for table in \
    principals \
    workspaces \
    memberships \
    workspace_events \
    memories \
    memory_evidence \
    activity_checkpoints \
    disclosure_receipts \
    disclosed_memories \
    projection_outbox \
    memory_share_proposals
do
    rg -q "^CREATE TABLE $table " "$schema" || {
        echo "PostgreSQL canonical table is missing: $table" >&2
        exit 1
    }
done

for invariant in \
    'workspace_events_require_contiguous_sequence' \
    'workspace_events_are_immutable' \
    'memory_share_proposals_validate_source' \
    'bytea NOT NULL' \
    'timestamptz NOT NULL'
do
    rg -F "$invariant" "$schema" >/dev/null || {
        echo "PostgreSQL canonical invariant is missing: $invariant" >&2
        exit 1
    }
done

for invariant in \
    "current_setting('rembrane.workspace_id', true)" \
    'ENABLE ROW LEVEL SECURITY' \
    'FORCE ROW LEVEL SECURITY' \
    'WITH CHECK (workspace_id = rembrane.current_workspace_id())' \
    'WITH CHECK (id = rembrane.current_workspace_id())' \
    'memberships.principal_id = principals.id' \
    'source_workspace_id = rembrane.current_workspace_id()'
do
    rg -F "$invariant" "$migration" >/dev/null || {
        echo "PostgreSQL RLS invariant is missing: $invariant" >&2
        exit 1
    }
done

for operational_invariant in \
    'SET LOCAL rembrane.workspace_id' \
    'must not own tenant tables' \
    'BYPASSRLS' \
    'security-definer'
do
    rg -F "$operational_invariant" "$readme" >/dev/null || {
        echo "PostgreSQL RLS operator invariant is missing: $operational_invariant" >&2
        exit 1
    }
done

echo "PostgreSQL RLS checks passed"
