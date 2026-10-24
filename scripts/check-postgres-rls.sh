#!/bin/sh
set -eu

schema=migrations/postgres/0001_canonical_schema.sql
administration=migrations/postgres/0002_workspace_administration.sql
travel=migrations/postgres/0003_travel_continuity.sql
migration=migrations/postgres/9999_tenant_rls.sql
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

for table in \
    workspace_invitations \
    member_scope_grants \
    workspace_key_rotations \
    workspace_key_rotation_receipts \
    workspace_key_rotation_recipients \
    administrative_audit_events \
    workspace_retention_policies \
    workspace_legal_holds
do
    rg -q "^CREATE TABLE $table " "$administration" || {
        echo "PostgreSQL administration table is missing: $table" >&2
        exit 1
    }
done

rg -F 'administrative_audit_events_are_append_only' "$administration" >/dev/null

for table in \
    checkpoint_disclosures \
    trips \
    booking_research \
    travel_disclosure_receipts \
    disclosed_booking_research
do
    rg -q "^CREATE TABLE $table " "$travel" || {
        echo "PostgreSQL travel table is missing: $table" >&2
        exit 1
    }
done

for invariant in \
    'source_references_included boolean NOT NULL DEFAULT false' \
    'sensitive_profile_included boolean NOT NULL DEFAULT false' \
    'octet_length(encryption_nonce) >= 12'
do
    rg -F "$invariant" "$travel" >/dev/null || {
        echo "PostgreSQL travel invariant is missing: $invariant" >&2
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
